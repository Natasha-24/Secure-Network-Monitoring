import os
import time
import threading
import pandas as pd
from datetime import datetime
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, wrpcap, get_if_list

from backend.detection.detector import detect_anomaly
from backend.detection.classifier import classify_threat
from backend.detection.incident_manager import create_incident

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BASELINE_PATH = os.path.join(BASE_DIR, "data", "normal", "normal_baseline.csv")
LIVE_FEATURE_PATH = os.path.join(BASE_DIR, "data", "live", "live_features.csv")
EVIDENCE_DIR = os.path.join(BASE_DIR, "data", "incidents", "pcap_evidence")

os.makedirs(os.path.dirname(LIVE_FEATURE_PATH), exist_ok=True)
os.makedirs(EVIDENCE_DIR, exist_ok=True)

class LiveMonitor:
    def __init__(self, interface=None, window_size=5):
        self.interface = interface
        self.window_size = window_size
        self.is_running = False
        self.thread = None
        self.activity_log = []
        self.latest_result = {
            "status": "STOPPED",
            "traffic_telemetry": {
                "total_packets": 0, "total_bytes": 0, "duration": 0,
                "packets_per_second": 0, "average_packet_size": 0,
                "tcp_packets": 0, "udp_packets": 0, "icmp_packets": 0,
                "other_packets": 0, "syn_packets": 0, "ack_packets": 0,
                "rst_packets": 0, "unique_source_ips": 0,
                "unique_destination_ips": 0, "unique_destination_ports": 0
            },
            "anomaly_score": 0,
            "severity": "LOW",
            "threat_type": "Normal Traffic",
            "confidence": "High",
            "reasons": [],
            "latest_incident": None
        }

    def log_event(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        entry = f"[{timestamp}] {message}"
        self.activity_log.insert(0, entry)
        if len(self.activity_log) > 20:
            self.activity_log.pop()

    def start(self, interface=None):
        if self.is_running:
            return
        if interface:
            self.interface = interface
        self.is_running = True
        self.log_event(f"Live monitoring started on interface: {self.interface or 'Default'}")
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()

    def stop(self):
        if not self.is_running:
            return
        self.is_running = False
        self.log_event("Live monitoring stopping...")

    def _run_loop(self):
        while self.is_running:
            captured_packets = []

            def packet_callback(pkt):
                captured_packets.append(pkt)

            # Live sniff over capture window
            sniff(iface=self.interface, timeout=self.window_size, prn=packet_callback, store=0)

            features = self._extract_live_features(captured_packets, self.window_size)
            
            # Write features for detector/classifier compatibility
            df = pd.DataFrame([features])
            df.to_csv(LIVE_FEATURE_PATH, index=False)

            # Run detection against baseline
            try:
                result = detect_anomaly(LIVE_FEATURE_PATH)
                
                # Custom dynamic classification for live stream
                classification = self._classify_live(features, result)
                
                score = result["anomaly_score"]
                severity = result["severity"]
                reasons = result["reasons"]
                threat_type = classification["threat_type"]
                confidence = classification["confidence"]

                # Handle incident creation and PCAP evidence export
                incident_data = None
                if severity in ["MEDIUM", "HIGH"]:
                    pcap_filename = f"incident_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
                    pcap_path = os.path.join(EVIDENCE_DIR, pcap_filename)
                    if captured_packets:
                        wrpcap(pcap_path, captured_packets)

                    incident_payload = {
                        "threat_type": threat_type,
                        "severity": severity,
                        "anomaly_score": score,
                        "confidence": confidence,
                        "reasons": reasons,
                        "evidence": pcap_path
                    }
                    incident_data = create_incident(incident_payload)
                    self.log_event(f"INCIDENT CREATED: {threat_type} ({severity})")

                elif score >= 20:
                    self.log_event(f"Elevated Activity: {threat_type}")
                else:
                    self.log_event("Normal traffic detected")

                # Update live telemetry payload
                self.latest_result = {
                    "status": "ACTIVE",
                    "traffic_telemetry": features,
                    "anomaly_score": score,
                    "severity": severity,
                    "threat_type": threat_type,
                    "confidence": confidence,
                    "reasons": reasons,
                    "latest_incident": incident_data,
                    "activity_log": self.activity_log
                }

            except Exception as e:
                self.log_event(f"Analysis error: {str(e)}")

    def _extract_live_features(self, packets, duration):
        total_packets = len(packets)
        total_bytes = sum(len(p) for p in packets)
        duration = max(duration, 1)

        tcp_packets = udp_packets = icmp_packets = other_packets = 0
        syn_packets = ack_packets = rst_packets = 0
        src_ips = set()
        dst_ips = set()
        dst_ports = set()

        for p in packets:
            if IP in p:
                src_ips.add(p[IP].src)
                dst_ips.add(p[IP].dst)
            elif IPv6 in p:
                src_ips.add(p[IPv6].src)
                dst_ips.add(p[IPv6].dst)

            if TCP in p:
                tcp_packets += 1
                flags = p[TCP].flags
                if flags & 0x02: syn_packets += 1
                if flags & 0x10: ack_packets += 1
                if flags & 0x04: rst_packets += 1
                dst_ports.add(p[TCP].dport)
            elif UDP in p:
                udp_packets += 1
                dst_ports.add(p[UDP].dport)
            elif ICMP in p:
                icmp_packets += 1
            else:
                other_packets += 1

        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "duration": round(duration, 2),
            "packets_per_second": round(total_packets / duration, 2),
            "average_packet_size": round(total_bytes / total_packets, 2) if total_packets > 0 else 0,
            "tcp_packets": tcp_packets,
            "udp_packets": udp_packets,
            "icmp_packets": icmp_packets,
            "other_packets": other_packets,
            "syn_packets": syn_packets,
            "ack_packets": ack_packets,
            "rst_packets": rst_packets,
            "unique_source_ips": len(src_ips),
            "unique_destination_ips": len(dst_ips),
            "unique_destination_ports": len(dst_ports)
        }

    def _classify_live(self, features, result):
        score = result["anomaly_score"]
        syn_pkts = features["syn_packets"]
        ports = features["unique_destination_ports"]
        pps = features["packets_per_second"]

        if score < 40:
            return {"threat_type": "Normal Traffic", "confidence": "High"}
        if ports >= 10 and syn_pkts >= 5:
            return {"threat_type": "Possible Port Scan", "confidence": "High"}
        if syn_pkts >= 15 and pps >= 20:
            return {"threat_type": "Possible SYN Flood / SYN-heavy Traffic", "confidence": "High"}
        if pps >= 30:
            return {"threat_type": "Abnormal Traffic Spike", "confidence": "Medium"}
        return {"threat_type": "General Network Anomaly", "confidence": "Medium"}

monitor_instance = LiveMonitor()
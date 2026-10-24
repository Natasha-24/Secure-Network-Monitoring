import os
import sys
import pandas as pd
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

NORMAL_PCAP = os.path.join(
    BASE_DIR,
    "data",
    "normal",
    "normal_kali_test.pcapng"
)

SUSPICIOUS_PCAP = os.path.join(
    BASE_DIR,
    "data",
    "suspicious",
    "suspicious_traffic.pcapng"
)


def extract_features(pcap_file, output_file):

    print("\nReading PCAP:")
    print(pcap_file)

    packets = rdpcap(pcap_file)

    if len(packets) == 0:
        print("No packets found.")
        return

    total_packets = len(packets)

    total_bytes = sum(
        len(packet)
        for packet in packets
    )

    # Capture duration
    timestamps = [
        float(packet.time)
        for packet in packets
        if hasattr(packet, "time")
    ]

    if timestamps:
        duration = max(timestamps) - min(timestamps)
    else:
        duration = 0

    if duration <= 0:
        duration = 1

    packets_per_second = total_packets / duration

    average_packet_size = total_bytes / total_packets

    tcp_packets = 0
    udp_packets = 0
    icmp_packets = 0
    other_packets = 0

    syn_packets = 0
    ack_packets = 0
    rst_packets = 0

    source_ips = set()
    destination_ips = set()
    destination_ports = set()

    for packet in packets:

        # IPv4
        if IP in packet:

            source_ips.add(packet[IP].src)
            destination_ips.add(packet[IP].dst)

        # IPv6
        elif IPv6 in packet:

            source_ips.add(packet[IPv6].src)
            destination_ips.add(packet[IPv6].dst)

        # TCP
        if TCP in packet:

            tcp_packets += 1

            flags = packet[TCP].flags

            if flags & 0x02:
                syn_packets += 1

            if flags & 0x10:
                ack_packets += 1

            if flags & 0x04:
                rst_packets += 1

            destination_ports.add(packet[TCP].dport)

        # UDP
        elif UDP in packet:

            udp_packets += 1

            destination_ports.add(packet[UDP].dport)

        # ICMP
        elif ICMP in packet:

            icmp_packets += 1

        else:

            other_packets += 1

    features = {

        "total_packets": total_packets,

        "total_bytes": total_bytes,

        "duration": round(duration, 2),

        "packets_per_second": round(
            packets_per_second,
            2
        ),

        "average_packet_size": round(
            average_packet_size,
            2
        ),

        "tcp_packets": tcp_packets,

        "udp_packets": udp_packets,

        "icmp_packets": icmp_packets,

        "other_packets": other_packets,

        "syn_packets": syn_packets,

        "ack_packets": ack_packets,

        "rst_packets": rst_packets,

        "unique_source_ips": len(source_ips),

        "unique_destination_ips": len(destination_ips),

        "unique_destination_ports": len(destination_ports)
    }

    df = pd.DataFrame([features])

    os.makedirs(
        os.path.dirname(output_file),
        exist_ok=True
    )

    df.to_csv(
        output_file,
        index=False
    )

    print("\n========== EXTRACTED FEATURES ==========")

    for key, value in features.items():

        print(
            f"{key:30}: {value}"
        )

    print("\nFeatures saved to:")

    print(output_file)


if __name__ == "__main__":

    # Default = normal traffic
    if len(sys.argv) == 1:

        pcap_file = NORMAL_PCAP

        output_file = os.path.join(
            BASE_DIR,
            "data",
            "normal",
            "normal_features.csv"
        )

    # Suspicious traffic
    elif sys.argv[1].lower() == "suspicious":

        pcap_file = SUSPICIOUS_PCAP

        output_file = os.path.join(
            BASE_DIR,
            "data",
            "suspicious",
            "suspicious_features.csv"
        )

    else:

        print(
            "Usage:"
        )

        print(
            "python backend\\analysis\\feature_extraction.py"
        )

        print(
            "python backend\\analysis\\feature_extraction.py suspicious"
        )

        sys.exit(1)

    if not os.path.exists(pcap_file):

        print("\nPCAP file not found:")
        print(pcap_file)

        sys.exit(1)

    extract_features(
        pcap_file,
        output_file
    )
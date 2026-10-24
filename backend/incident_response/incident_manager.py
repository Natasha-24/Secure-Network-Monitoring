import os
import sys
import json
from datetime import datetime

from backend.detection.classifier import classify_threat


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INCIDENT_DIR = os.path.join(BASE_DIR, "data", "incidents")
INCIDENT_FILE = os.path.join(INCIDENT_DIR, "incidents.json")

SUSPICIOUS_PCAP = os.path.join(
    BASE_DIR,
    "data",
    "suspicious",
    "suspicious_traffic.pcapng"
)


def create_incident(result):
    os.makedirs(INCIDENT_DIR, exist_ok=True)

    if os.path.exists(INCIDENT_FILE):
        with open(INCIDENT_FILE, "r") as file:
            incidents = json.load(file)
    else:
        incidents = []

    incident_id = "INC-" + datetime.now().strftime("%Y%m%d%H%M%S")

    incident = {
        "incident_id": incident_id,
        "timestamp": datetime.now().isoformat(),
        "threat_type": result["threat_type"],
        "severity": result["severity"],
        "anomaly_score": result["anomaly_score"],
        "confidence": result["confidence"],
        "detection_reasons": result["reasons"],
        "status": "OPEN",
        "evidence": SUSPICIOUS_PCAP
    }

    incidents.append(incident)

    with open(INCIDENT_FILE, "w") as file:
        json.dump(incidents, file, indent=4)

    return incident


def process_incident(traffic_type="normal"):

    print("\n========================================")
    print("          INCIDENT RESPONSE")
    print("========================================")

    result = classify_threat(traffic_type)

    print(f"Threat Type   : {result['threat_type']}")
    print(f"Severity      : {result['severity']}")
    print(f"Anomaly Score : {result['anomaly_score']:.2f}")

    if result["severity"] in ["MEDIUM", "HIGH"]:

        incident = create_incident(result)

        print("\nIncident Created!")
        print(f"Incident ID : {incident['incident_id']}")
        print(f"Status      : {incident['status']}")
        print(f"Evidence    : {incident['evidence']}")

    else:
        print("\nNo incident created.")
        print("Traffic classified as low-risk.")


if __name__ == "__main__":

    traffic_type = "normal"

    if len(sys.argv) > 1:
        traffic_type = sys.argv[1].lower()

    process_incident(traffic_type)
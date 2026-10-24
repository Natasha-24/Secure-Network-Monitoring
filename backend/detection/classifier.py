import os
import sys

from backend.detection.detector import detect_anomaly


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

NORMAL_FEATURE_FILE = os.path.join(
    BASE_DIR,
    "data",
    "normal",
    "normal_features.csv"
)

SUSPICIOUS_FEATURE_FILE = os.path.join(
    BASE_DIR,
    "data",
    "suspicious",
    "suspicious_features.csv"
)


def classify_threat(traffic_type="normal"):

    traffic_type = traffic_type.lower()

    if traffic_type == "suspicious":
        feature_file = SUSPICIOUS_FEATURE_FILE
    else:
        feature_file = NORMAL_FEATURE_FILE

    if not os.path.exists(feature_file):
        raise FileNotFoundError(
            f"Feature file not found:\n{feature_file}"
        )

    result = detect_anomaly(feature_file)

    score = result["anomaly_score"]
    severity = result["severity"]
    reasons = result["reasons"]

    # Calculate useful ratios
    syn_ratio = (
        result["current_features"]["syn_packets"]
        / max(result["baseline_features"]["syn_packets"], 1)
    )

    port_ratio = (
        result["current_features"]["unique_destination_ports"]
        / max(result["baseline_features"]["unique_destination_ports"], 1)
    )

    packet_rate_ratio = (
        result["current_features"]["packets_per_second"]
        / max(result["baseline_features"]["packets_per_second"], 1)
    )

    source_ip_ratio = (
        result["current_features"]["unique_source_ips"]
        / max(result["baseline_features"]["unique_source_ips"], 1)
    )

    # Threat classification
    if score < 40:
        threat_type = "Normal Traffic"
        confidence = "High"

    elif port_ratio >= 1.5 and syn_ratio >= 1.25:
        threat_type = "Possible Port Scan"
        confidence = "High"

    elif syn_ratio >= 1.75 and packet_rate_ratio >= 1.5:
        threat_type = "Possible SYN Flood / SYN-heavy Traffic"
        confidence = "High"

    elif packet_rate_ratio >= 1.5:
        threat_type = "Abnormal Traffic Spike"
        confidence = "Medium"

    elif source_ip_ratio >= 1.5:
        threat_type = "Possible Reconnaissance Activity"
        confidence = "Medium"

    else:
        threat_type = "General Network Anomaly"
        confidence = "Medium"

    return {
        "anomaly_score": score,
        "severity": severity,
        "threat_type": threat_type,
        "confidence": confidence,
        "reasons": reasons
    }


if __name__ == "__main__":

    traffic_type = "normal"

    if len(sys.argv) > 1:
        traffic_type = sys.argv[1].lower()

    result = classify_threat(traffic_type)

    print("\n========================================")
    print("          THREAT CLASSIFICATION")
    print("========================================")
    print(f"Anomaly Score : {result['anomaly_score']:.2f}")
    print(f"Severity      : {result['severity']}")
    print(f"Threat Type   : {result['threat_type']}")
    print(f"Confidence    : {result['confidence']}")

    print("\nDetection Reasons:")

    for reason in result["reasons"]:
        print(f"- {reason}")

    print("========================================")
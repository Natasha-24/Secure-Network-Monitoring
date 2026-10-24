import os
import sys
import pandas as pd


# ============================================================
# PATH CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

NORMAL_FEATURE_FILE = os.path.join(
    BASE_DIR,
    "data",
    "normal",
    "normal_features.csv"
)

BASELINE_FILE = os.path.join(
    BASE_DIR,
    "data",
    "normal",
    "normal_baseline.csv"
)

SUSPICIOUS_FEATURE_FILE = os.path.join(
    BASE_DIR,
    "data",
    "suspicious",
    "suspicious_features.csv"
)


# ============================================================
# FEATURE WEIGHTS
# ============================================================

FEATURE_WEIGHTS = {
    "packets_per_second": 0.20,
    "average_packet_size": 0.15,
    "syn_packets": 0.20,
    "rst_packets": 0.10,
    "unique_source_ips": 0.15,
    "unique_destination_ips": 0.10,
    "unique_destination_ports": 0.10
}


# ============================================================
# ANOMALY DETECTION
# ============================================================

def detect_anomaly(feature_file=None):

    # --------------------------------------------------------
    # Select feature file
    # --------------------------------------------------------

    if feature_file is None:
        feature_file = NORMAL_FEATURE_FILE

    # --------------------------------------------------------
    # Check files
    # --------------------------------------------------------

    if not os.path.exists(feature_file):
        raise FileNotFoundError(
            f"Feature file not found:\n{feature_file}"
        )

    if not os.path.exists(BASELINE_FILE):
        raise FileNotFoundError(
            f"Baseline file not found:\n{BASELINE_FILE}"
        )

    # --------------------------------------------------------
    # Read current traffic and baseline
    # --------------------------------------------------------

    current = pd.read_csv(feature_file).iloc[0]
    baseline = pd.read_csv(BASELINE_FILE).iloc[0]

    total_score = 0
    reasons = []

    print("\n========== ANOMALY DETECTION ==========\n")

    # --------------------------------------------------------
    # Analyze each feature
    # --------------------------------------------------------

    for feature, weight in FEATURE_WEIGHTS.items():

        current_value = current[feature]
        baseline_value = baseline[feature]

        # ----------------------------------------------------
        # Calculate percentage deviation
        # ----------------------------------------------------

        if baseline_value == 0:

            # Avoid division by zero
            deviation = 0

        else:

            deviation = (
                abs(current_value - baseline_value)
                / baseline_value
                * 100
            )

        # ----------------------------------------------------
        # Convert deviation into anomaly score
        # ----------------------------------------------------

        if deviation <= 10:

            feature_score = 0

        elif deviation <= 25:

            feature_score = 25

        elif deviation <= 50:

            feature_score = 60

        else:

            feature_score = 100

        # ----------------------------------------------------
        # Apply feature weight
        # ----------------------------------------------------

        weighted_score = feature_score * weight

        total_score += weighted_score

        # ----------------------------------------------------
        # Display results
        # ----------------------------------------------------

        print(feature)

        print(f"  Current  : {current_value:.2f}")
        print(f"  Baseline : {baseline_value:.2f}")
        print(f"  Deviation: {deviation:.2f}%")
        print(f"  Score    : {feature_score:.2f}")

        # ----------------------------------------------------
        # Generate explanation
        # ----------------------------------------------------

        if deviation > 25:

            direction = "increased"

            if current_value < baseline_value:
                direction = "decreased"

            reasons.append(
                f"{feature} {direction} by {deviation:.2f}%"
            )

        print()

    # ========================================================
    # DETERMINE SEVERITY
    # ========================================================

    if total_score >= 70:

        severity = "HIGH"

    elif total_score >= 40:

        severity = "MEDIUM"

    else:

        severity = "LOW"

    # ========================================================
    # DISPLAY OVERALL RESULT
    # ========================================================

    print("========================================")
    print(f"Overall anomaly score : {total_score:.2f}")
    print(f"Severity              : {severity}")
    print("========================================")

    # --------------------------------------------------------
    # Display detection reasons
    # --------------------------------------------------------

    if reasons:

        print("\nDetection reasons:")

        for reason in reasons:

            print(f"- {reason}")

    else:

        print("\nNo significant anomalies detected.")

    # ========================================================
    # RETURN RESULT
    # ========================================================
    #
    # IMPORTANT:
    # current_features and baseline_features are returned
    # because classifier.py uses them to calculate threat type.
    # ========================================================

    return {
        "anomaly_score": total_score,
        "severity": severity,
        "reasons": reasons,

        # Required by classifier.py
        "current_features": current.to_dict(),
        "baseline_features": baseline.to_dict()
    }


# ============================================================
# COMMAND LINE EXECUTION
# ============================================================

if __name__ == "__main__":

    # --------------------------------------------------------
    # No argument = normal traffic
    # --------------------------------------------------------

    if len(sys.argv) == 1:

        feature_file = NORMAL_FEATURE_FILE

    # --------------------------------------------------------
    # suspicious = suspicious traffic
    # --------------------------------------------------------

    elif sys.argv[1].lower() == "suspicious":

        feature_file = SUSPICIOUS_FEATURE_FILE

    # --------------------------------------------------------
    # Invalid argument
    # --------------------------------------------------------

    else:

        print("\nUsage:")

        print(
            "python backend\\detection\\detector.py"
        )

        print(
            "python backend\\detection\\detector.py suspicious"
        )

        sys.exit(1)

    # --------------------------------------------------------
    # Run detector
    # --------------------------------------------------------

    detect_anomaly(feature_file)
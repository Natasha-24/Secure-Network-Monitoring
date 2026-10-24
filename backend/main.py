from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import os
import json

from backend.detection.detector import detect_anomaly
from backend.detection.classifier import classify_threat


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)

FRONTEND_DIR = os.path.join(
    PROJECT_DIR,
    "frontend"
)

INCIDENT_FILE = os.path.join(
    BASE_DIR,
    "data",
    "incidents",
    "incidents.json"
)


# ============================================================
# FLASK APP
# ============================================================

app = Flask(
    __name__,
    static_folder=FRONTEND_DIR,
    static_url_path=""
)

CORS(app)


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/")
def home():
    return send_from_directory(
        FRONTEND_DIR,
        "index.html"
    )


# ============================================================
# SYSTEM STATUS
# ============================================================

@app.route("/api/status")
def status():

    return jsonify({
        "system_status": "ONLINE",
        "monitoring": "ACTIVE",
        "detection_engine": "READY",
        "incident_response": "READY"
    })


# ============================================================
# FEATURE FILE SELECTION
# ============================================================

def get_feature_file(traffic_type):

    if traffic_type == "suspicious":

        return os.path.join(
            BASE_DIR,
            "data",
            "suspicious",
            "suspicious_features.csv"
        )

    return os.path.join(
        BASE_DIR,
        "data",
        "normal",
        "normal_features.csv"
    )


# ============================================================
# ANALYZE TRAFFIC
# ============================================================

@app.route("/api/analyze", methods=["GET"])
def analyze():

    traffic_type = request.args.get(
        "type",
        "normal"
    ).lower()

    # ----------------------------------------
    # Validate traffic type
    # ----------------------------------------

    if traffic_type not in [
        "normal",
        "suspicious"
    ]:

        return jsonify({
            "error":
                "Invalid traffic type. "
                "Use normal or suspicious."
        }), 400


    try:

        # ----------------------------------------
        # Get feature file
        # ----------------------------------------

        feature_file = get_feature_file(
            traffic_type
        )


        # ----------------------------------------
        # Check feature file
        # ----------------------------------------

        if not os.path.exists(feature_file):

            return jsonify({
                "error":
                    f"Feature file not found: "
                    f"{feature_file}"
            }), 404


        # ----------------------------------------
        # Run anomaly detector
        # ----------------------------------------

        result = detect_anomaly(
            feature_file
        )


        # ----------------------------------------
        # Classify threat
        # ----------------------------------------

        classification = classify_threat(
            traffic_type
        )


        # ----------------------------------------
        # Return complete analysis
        # ----------------------------------------

        return jsonify({

            # Traffic information
            "traffic_type":
                traffic_type,

            # Detection result
            "anomaly_score":
                result["anomaly_score"],

            "severity":
                result["severity"],

            "reasons":
                result["reasons"],

            # Threat classification
            "threat_type":
                classification["threat_type"],

            "confidence":
                classification["confidence"],

            # IMPORTANT:
            # These two fields are required
            # by dashboard.js
            "current_features":
                result["current_features"],

            "baseline_features":
                result["baseline_features"]
        })


    except Exception as e:

        print(
            "ERROR during analysis:",
            str(e)
        )

        return jsonify({
            "error": str(e)
        }), 500


# ============================================================
# FEATURE DATA
# ============================================================

@app.route("/api/features")
def features():

    traffic_type = request.args.get(
        "type",
        "suspicious"
    ).lower()


    if traffic_type not in [
        "normal",
        "suspicious"
    ]:

        return jsonify({
            "error":
                "Invalid traffic type."
        }), 400


    try:

        result = detect_anomaly(
            get_feature_file(
                traffic_type
            )
        )


        return jsonify({

            "traffic_type":
                traffic_type,

            "current_features":
                result["current_features"],

            "baseline_features":
                result["baseline_features"]
        })


    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


# ============================================================
# INCIDENTS
# ============================================================

@app.route("/api/incidents")
def incidents():

    # ----------------------------------------
    # If incident file doesn't exist
    # ----------------------------------------

    if not os.path.exists(
        INCIDENT_FILE
    ):

        return jsonify([])


    try:

        with open(
            INCIDENT_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)


        return jsonify(data)


    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


# ============================================================
# FRONTEND FILES
# ============================================================

@app.route("/<path:path>")
def serve_frontend(path):

    requested_path = os.path.join(
        FRONTEND_DIR,
        path
    )


    # ----------------------------------------
    # Serve requested file if it exists
    # ----------------------------------------

    if os.path.isfile(
        requested_path
    ):

        return send_from_directory(
            FRONTEND_DIR,
            path
        )


    # ----------------------------------------
    # Otherwise return index.html
    # ----------------------------------------

    return send_from_directory(
        FRONTEND_DIR,
        "index.html"
    )


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    print(
        "\n========================================"
    )

    print(
        " SECURE NETWORK MONITORING PLATFORM"
    )

    print(
        "========================================"
    )

    print(
        "Starting Flask API..."
    )

    print(
        "Server: http://127.0.0.1:5000"
    )

    print(
        "========================================\n"
    )


    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
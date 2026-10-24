# Secure Network Monitoring and Incident Response Platform

A Python-based network security project that analyses captured network traffic, detects unusual activity, classifies possible threats, and records security incidents through a web-based dashboard.

## Overview

Network traffic contains useful information that can help identify suspicious activities such as port scanning and unusual connection patterns. However, manually analysing large packet captures can be time-consuming.

This project uses **Wireshark, Python, and Scapy** to analyse captured network traffic and compare it with a normal traffic baseline. When significant differences are found, the system calculates an anomaly score, identifies a possible threat, and records the incident for further investigation.

A Flask-based dashboard presents the traffic statistics, anomaly results, detection reasons, and incident history in one place.

## Objectives

- Capture and analyse network traffic using Wireshark.
- Extract important features from PCAP and PCAPNG files.
- Compare observed traffic with a normal traffic baseline.
- Detect unusual network patterns using a weighted anomaly-scoring method.
- Classify possible threats and assign severity levels.
- Record security incidents along with their related packet-capture evidence.
- Display analysis results through a web-based dashboard.

## Key Features

- **Packet Analysis:** Reads saved network captures and extracts useful packet information.
- **Feature Extraction:** Calculates packet rate, average packet size, protocol counts, SYN/RST counts, IP addresses, and destination ports.
- **Baseline Comparison:** Compares analysed traffic with reference values from normal traffic.
- **Anomaly Detection:** Calculates a weighted anomaly score based on deviations in selected network features.
- **Threat Classification:** Identifies possible port scans, SYN-heavy traffic, and abnormal traffic spikes using implemented rules.
- **Severity Assessment:** Assigns Low, Medium, or High severity based on the anomaly score.
- **Incident Management:** Records incident IDs, threat details, severity, status, and evidence paths.
- **Security Dashboard:** Displays traffic statistics, baseline comparisons, anomaly results, and incident history.
- 

## Methodology

1. **Traffic Capture:** Capture normal and suspicious traffic using Wireshark and save it in PCAP/PCAPNG format.
2. **Packet Processing:** Read the captured files using Python and Scapy.
3. **Feature Extraction:** Calculate packet counts, packet rate, packet size, SYN/RST counts, unique IP addresses, and destination ports.
4. **Baseline Creation:** Generate reference feature values from a normal traffic capture.
5. **Anomaly Detection:** Compare current feature values with the normal baseline and calculate a weighted anomaly score.
6. **Threat Classification:** Apply rule-based checks to identify possible suspicious traffic patterns.
7. **Incident Recording:** Store incident information and associate it with the relevant packet-capture evidence.
8. **Dashboard Display:** Present the analysis results through a Flask-based web interface.

## Technologies Used
                                  
Python - Backend processing and detection logic    
Wireshark - Network packet capture and inspection     
Scapy - PCAP/PCAPNG packet processing             
Pandas - Feature and baseline data processing      
NumPy - Numerical calculations                    
Flask - Backend API and dashboard integration     
HTML - Dashboard structure                       
CSS - Dashboard styling                         
JavaScript - Dashboard updates and charts              
Kali Linux - Controlled traffic generation for testing 
VirtualBox - Running the testing virtual machine       

## Project Structure

```text
Secure-Network-Monitoring/
├── backend/
│   ├── analysis/
│   │   ├── baseline.py
│   │   ├── feature_extraction.py
│   │   └── pcap_reader.py
│   ├── capture/
│   ├── detection/
│   │   ├── classifier.py
│   │   ├── detector.py
│   │   └── live_monitor.py
│   ├── incident_response/
│   │   └── incident_manager.py
│   ├── data/
│   │   ├── normal/
│   │   ├── suspicious/
│   │   └── incidents/
│   └── main.py
├── frontend/
│   ├── css/
│   │   └── style.css
│   ├── js/
│   │   └── dashboard.js
│   └── index.html
├── tests/
├── requirements.txt
├── .gitignore
└── README.md
```

## Requirements

- Windows 10/11 or another compatible operating system
- Python 3.x
- Git
- Wireshark and Npcap for packet capture on Windows
- Python packages listed in `requirements.txt`

Kali Linux and VirtualBox are optional for running controlled traffic-generation tests.

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/Natasha-24/Secure-Network-Monitoring.git
cd Secure-Network-Monitoring
```

### 2. Create a virtual environment

On Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Start the application

From the project root, run:

```powershell
python -m backend.main
```

Open the dashboard in your browser:

**[http://127.0.0.1:5000](http://127.0.0.1:5000)**

The application expects the required feature files and baseline data to be available in the configured project directories. If these files are not included in the repository, generate them from suitable traffic captures before running the analysis.

## Testing and Evaluation

The system can be tested using normal and suspicious traffic captures collected in an authorised, controlled environment.

During testing, compare the extracted feature values, anomaly score, severity, threat classification, and incident details. The results can help evaluate whether the implemented rules identify the expected traffic patterns.

## Current Limitations

- Analysis is based primarily on saved packet captures and extracted feature files; continuous live monitoring is not yet the main workflow.
- Detection relies on predefined feature weights and rule-based thresholds.
- Results depend on the quality and representativeness of the normal traffic baseline.
- Detection is limited to the traffic patterns covered by the implemented rules.
- IPv6 and more advanced attack patterns may require additional feature extraction and detection logic.

## Future Improvements

- Add continuous packet capture and real-time analysis.
- Improve baseline creation using multiple normal traffic captures.
- Evaluate detection using precision, recall, F1-score, and false-positive rate.
- Add support for IPv6 and additional suspicious traffic patterns.
- Improve incident investigation and reporting.
- Explore machine-learning-based anomaly detection.

## Disclaimer

This project is developed for academic and educational purposes. Packet capture and security testing should be performed only on systems and networks for which permission has been granted.

## Author

**Natasha Elizabeth P**

GitHub: [Natasha-24](https://github.com/Natasha-24)

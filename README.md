# 🛡️ NeuroSnare v3.0 – AI-Powered IDS/IPS with Attacker Profiling

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-24.0%2B-blue.svg)](https://www.docker.com/)
[![Scikit-learn](https://img.shields.io/badge/Scikit--learn-1.3%2B-orange.svg)](https://scikit-learn.org/)

> **NeuroSnare** is an advanced Intrusion Detection and Prevention System (IDPS) that leverages Machine Learning to detect network anomalies, then **silently redirects attackers** to a contained Docker honeypot for intelligence gathering and forensic analysis.

---

## 🎯 Key Features

| Feature | Description |
|---------|-------------|
| **🧠 AI-Powered Detection** | Isolation Forest algorithm for anomaly detection |
| **🔄 Multi-Honeypot** | SSH, Web, FTP, SMB honeypots in isolated containers |
| **🕵️ Attacker Profiling** | Canvas, WebGL, and Font fingerprinting |
| **📊 MITRE ATT&CK Mapping** | Automatic mapping of attacks to T-codes |
| **🌐 Threat Intelligence** | AbuseIPDB, VirusTotal, AlienVault OTX integration |
| **📈 Real-time Dashboard** | Live statistics, charts, and attacker profiles |
| **📄 PDF Reports** | Auto-generated forensic reports |
| **📝 Attack Replay** | Complete session timeline reconstruction |
| **🔗 IP Correlation** | Identify same attacker across multiple IPs |

---

## 🏗️ System Architecture
┌─────────────────────────────────────────────────────────────────┐
│ Internet │
└────────────────────────┬────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────────┐
│ NeuroSnare Gateway │
│ ┌──────────────────────────────────────────────────────────┐ │
│ │ Packet Sniffer (Scapy) │ │
│ └────────────────────┬─────────────────────────────────────┘ │
│ │ │
│ ┌────────────────────▼─────────────────────────────────────┐ │
│ │ AI Engine (Isolation Forest) │ │
│ │ Anomaly Detection in Real-time │ │
│ └────────────────────┬─────────────────────────────────────┘ │
│ │ │
│ ┌────────────────────▼─────────────────────────────────────┐ │
│ │ Tactical Responder (iptables DNAT) │ │
│ │ Redirects attackers to appropriate honeypot │ │
│ └────────────────────┬─────────────────────────────────────┘ │
└────────────────────────┼────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────────┐
│ Multi-Honeypot Environment │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│ │ SSH │ │ Web │ │ FTP │ │ SMB │ │
│ │ :22 │ │ :80/443 │ │ :21 │ │ :445 │ │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
│ │
│ ┌──────────────────────────────────────────────────────────┐ │
│ │ Activity Logger & Browser Fingerprinting │ │
│ └──────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘

text

---

## 🚀 Quick Start

### Prerequisites

```bash
# Required:
- Python 3.8+
- Docker & Docker Compose
- Linux with iptables support
- Root/Administrator privileges
Installation
bash
# 1. Clone the repository
git clone https://github.com/yourusername/NeuroSnare-v3.git
cd NeuroSnare-v3

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Start the honeypot containers
cd honeypot
docker-compose up -d --build
cd ..

# 4. Run NeuroSnare (requires root)
sudo python3 src/main.py

# 5. Open the Dashboard
# http://localhost:5000
Docker Compose (All-in-One)
bash
docker-compose up -d
📊 Dashboard Preview
Section	Description
Stats	Total attacks, redirected, unique IPs
Attacker Profiles	Risk scores, attack counts, fingerprints
IP Correlation	Linked IPs from same attacker
Attack Log	Real-time attack feed with MITRE IDs
Charts	Attack distribution visualization
🔬 How It Works
1. Packet Capture & Analysis
python
# Scapy captures and analyzes each packet
def packet_handler(packet):
    features = extract_features(packet)
    result = ai_engine.predict(features)
    if result['is_attack']:
        redirect_to_honeypot(packet[IP].src)
2. Attack Detection (Isolation Forest)
python
# AI model detects anomalies in real-time
model = IsolationForest(contamination=0.05)
prediction = model.predict(features)
# -1 = Malicious, 1 = Normal
3. Tactical Response (iptables DNAT)
bash
# Silent redirection to honeypot
iptables -t nat -A PREROUTING -s 192.168.1.100 -j DNAT --to-destination 192.168.1.102
4. Browser Fingerprinting
javascript
// JavaScript tracker collects:
- Canvas fingerprint
- WebGL fingerprint
- Installed fonts
- Timezone, Language
- Screen resolution
🛠️ Tech Stack
Component	Technology
Language	Python 3
Packet Capture	Scapy
Machine Learning	Scikit-learn (Isolation Forest)
Firewall	iptables (DNAT)
Honeypots	Docker
Web Framework	Flask
Database	SQLite
Frontend	HTML, CSS, JavaScript, Chart.js
Reporting	ReportLab (PDF)
📂 Project Structure
text
NeuroSnare-v3/
├── src/                    # Core source code
│   ├── sniffer.py          # Packet capture
│   ├── ai_engine.py        # ML detection
│   ├── responder.py        # iptables redirection
│   ├── dashboard.py        # Web interface
│   ├── attacker_profiler.py# Fingerprinting
│   ├── database.py         # SQLite storage
│   └── ...
├── honeypot/               # Multi-honeypot environment
│   ├── Dockerfile.ssh      # SSH honeypot
│   ├── Dockerfile.web      # Web honeypot
│   ├── Dockerfile.ftp      # FTP honeypot
│   └── Dockerfile.smb      # SMB honeypot
├── models/                 # Trained AI models
├── data/                   # Training data & MITRE mapping
├── logs/                   # System logs
├── reports/                # Generated PDF reports
└── templates/              # Dashboard HTML
⚠️ Disclaimer
IMPORTANT: This project is developed for educational purposes and internal network defense research only. Do not use on networks you do not own or have explicit permission to test. The authors are not responsible for any misuse or damage caused by this software.

📝 License
This project is licensed under the MIT License – see the LICENSE file for details.

📞 Contact
GitHub: yourusername

LinkedIn: yourprofile

Email: your.email@example.com

Built with ❤️ for Network Security Research

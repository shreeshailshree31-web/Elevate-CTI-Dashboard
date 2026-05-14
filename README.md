# 🛡️ Elevate CTI Gold | Enterprise Threat Dashboard

An advanced **Cyber Threat Intelligence (CTI)** dashboard designed for SOC analysts. This tool provides a "Single Pane of Glass" to analyze IP addresses and Domains, visualize global threat trends, and export forensic data for incident response.

## 🚀 Key Features
* **Dual-Source Intelligence:** Real-time data correlation from **AbuseIPDB** and **VirusTotal**.
* **Geospatial Mapping:** Interactive **Leaflet.js** map to visualize the physical location of threat actors.
* **Live Analytics:** Automated **Chart.js** dashboard showing the ratio of safe vs. malicious indicators.
* **Database Persistence:** Full integration with **MongoDB Atlas** for historical tracking.
* **Forensic Export:** One-click **CSV report generation** for audit logs and reporting.

## 🛠️ Technical Architecture
* **Backend:** Python 3.x, Flask
* **Database:** MongoDB Atlas (NoSQL)
* **Frontend:** HTML5, CSS3 (Glassmorphism UI), JavaScript
* **APIs:** VirusTotal API v3, AbuseIPDB API v2

## 🔧 Setup
1. Clone the repo and install dependencies: `pip install -r requirements.txt`
2. Create a `.env` file with your API keys.
3. Run `python app.py`.
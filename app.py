from flask import Flask, jsonify, request, render_template_string, Response
import os
from dotenv import load_dotenv
import requests
from pymongo import MongoClient
import datetime
import io
import csv

# 1. Load Environmental Variables
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
MONGO_URI = os.getenv('MONGO_URI')

app = Flask(__name__)

# 2. Database Connectivity
try:
    client = MongoClient(MONGO_URI)
    db = client['cti_database']
    history_collection = db['scan_history']
    print("✅ MongoDB Connection Verified")
except Exception as e:
    print(f"❌ Connection Error: {e}")

# 3. The Enterprise UI Template
# This is a standard Python string (no 'f' prefix) to avoid bracket errors
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Elevate CTI | Enterprise Gold</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root { --bg: #05070a; --glass: rgba(22, 27, 41, 0.8); --accent: #3b82f6; --text: #f8fafc; --border: rgba(255, 255, 255, 0.1); --danger: #ff4d4d; --safe: #00e676; }
        body { background: radial-gradient(circle at top, #1e293b 0%, #05070a 100%); color: var(--text); font-family: 'Inter', sans-serif; margin: 0; padding: 20px; min-height: 100vh; }
        .dashboard-wrapper { max-width: 1200px; margin: 0 auto; display: grid; grid-template-columns: 1fr 350px; gap: 20px; }
        .glass-card { background: var(--glass); backdrop-filter: blur(10px); border: 1px solid var(--border); border-radius: 16px; padding: 24px; margin-bottom: 20px; }
        .search-bar { display: flex; gap: 12px; margin-top: 15px; }
        input, select { background: rgba(0,0,0,0.4); border: 1px solid var(--border); color: white; padding: 12px; border-radius: 8px; outline: none; }
        button { background: var(--accent); color: white; border: none; padding: 0 25px; border-radius: 8px; cursor: pointer; font-weight: bold; }
        #map { height: 300px; border-radius: 12px; margin-top: 20px; border: 1px solid var(--border); z-index: 1; }
        .tag { padding: 6px 12px; border-radius: 20px; font-size: 0.7rem; font-weight: bold; }
        .critical { background: var(--danger); color: white; }
        .verified { background: var(--safe); color: black; }
    </style>
</head>
<body>
    <div class="dashboard-wrapper">
        <div style="grid-column: span 2; text-align: center; margin-bottom: 20px;">
            <h1 style="color:var(--accent); margin:0;">ELEVATE <span style="color:white">CTI GOLD</span></h1>
            <p style="color: #94a3b8; margin: 5px 0 0 0;">Intelligence-Driven Threat Defense</p>
        </div>

        <div class="main-content">
            <div class="glass-card">
                <form id="scan-form" class="search-bar">
                    <select id="scan-type"><option value="ip">IP Address</option><option value="domain">Domain</option></select>
                    <input type="text" id="target" style="flex:1" placeholder="Analyze Indicator..." required>
                    <button type="submit">SCAN</button>
                </form>
            </div>

            <div id="results" class="glass-card" style="display:none">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <h3 id="res-title">Threat Report</h3>
                    <span id="res-tag" class="tag">CLEAN</span>
                </div>
                <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:15px; margin-top:20px; text-align:center;">
                    <div><small style="color:#94a3b8">SCORE</small><h2 id="res-score" style="color:var(--accent)">0</h2></div>
                    <div><small style="color:#94a3b8">PROVIDER</small><h4 id="res-isp">-</h4></div>
                    <div><small style="color:#94a3b8">REGION</small><h4 id="res-loc">-</h4></div>
                </div>
                <div id="map"></div>
            </div>
        </div>

        <div class="sidebar">
            <div class="glass-card" style="text-align:center;">
                <h4 style="margin-bottom:15px">Live Threat Ratio</h4>
                <canvas id="statChart"></canvas>
                <p id="total-scans" style="font-size: 0.8rem; color: #94a3b8; margin-top: 15px;">Initializing Database...</p>
            </div>
            <div class="glass-card" style="text-align:center">
                <a href="/export" style="color:var(--safe); text-decoration:none; font-weight:bold;">
                    <i class="fas fa-file-csv"></i> DOWNLOAD AUDIT LOGS
                </a>
            </div>
        </div>
    </div>

    <script>
        let map = L.map('map').setView([20, 0], 2);
        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png').addTo(map);
        let marker, chart;

        // Auto-loads stats when page opens
        async function updateStats() {
            try {
                const r = await fetch('/get_stats');
                const d = await r.json();
                document.getElementById('total-scans').innerText = "Total Records: " + d.total;
                
                const ctx = document.getElementById('statChart').getContext('2d');
                if(chart) chart.destroy();
                chart = new Chart(ctx, {
                    type: 'doughnut',
                    data: { 
                        labels: ['Safe', 'Malicious'], 
                        datasets: [{ data: [d.safe, d.malicious], backgroundColor: ['#00e676', '#ff4d4d'], borderWidth: 0 }] 
                    },
                    options: { cutout: '70%', plugins: { legend: { position: 'bottom', labels: { color: 'white' } } } }
                });
            } catch (e) { console.log("Init failed"); }
        }

        window.onload = updateStats;

        document.getElementById('scan-form').onsubmit = async (e) => {
            e.preventDefault();
            const btn = e.target.querySelector('button');
            btn.innerText = "WAIT..."; btn.disabled = true;

            const fd = new FormData();
            fd.append('target', document.getElementById('target').value);
            fd.append('scan_type', document.getElementById('scan-type').value);

            const r = await fetch('/scan', { method: 'POST', body: fd });
            const data = await r.json();

            document.getElementById('results').style.display = 'block';
            document.getElementById('res-title').innerText = data.target;
            document.getElementById('res-score').innerText = data.score;
            document.getElementById('res-isp').innerText = data.field1;
            document.getElementById('res-loc').innerText = data.field2;

            const tag = document.getElementById('res-tag');
            if(data.score > 50 || (data.scan_type==='domain' && data.score > 0)) {
                tag.innerText = "MALICIOUS"; tag.className = "tag critical";
            } else {
                tag.innerText = "CLEAN"; tag.className = "tag verified";
            }

            if(data.lat && data.lon) {
                if(marker) map.removeLayer(marker);
                map.flyTo([data.lat, data.lon], 5);
                marker = L.marker([data.lat, data.lon]).addTo(map);
            }
            updateStats();
            btn.innerText = "SCAN"; btn.disabled = false;
        }
    </script>
</body>
</html>
"""

# 4. Backend Logic & API Routing
@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form.get('target')
    stype = request.form.get('scan_type')
    res = {"target": target, "score": 0, "field1": "N/A", "field2": "N/A", "lat": None, "lon": None, "scan_type": stype}

    try:
        if stype == 'ip':
            # AbuseIPDB API Call
            r = requests.get('https://api.abuseipdb.com/api/v2/check', 
                             headers={'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'},
                             params={'ipAddress': target, 'verbose': True})
            if r.status_code == 200:
                d = r.json()['data']
                res.update({
                    "score": d['abuseConfidenceScore'], 
                    "field1": d['isp'], 
                    "field2": d['countryCode'], 
                    "lat": d.get('latitude'), 
                    "lon": d.get('longitude')
                })
        else:
            # VirusTotal API Call
            r = requests.get(f"https://www.virustotal.com/api/v3/domains/{target}", 
                             headers={"x-apikey": VIRUSTOTAL_API_KEY})
            if r.status_code == 200:
                d = r.json()['data']['attributes']
                res.update({
                    "score": d['last_analysis_stats']['malicious'], 
                    "field1": d.get('registrar', 'Unknown Registrar')
                })

        # Save Entry to MongoDB History
        res['timestamp'] = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        history_collection.insert_one(res.copy())
    except Exception as e:
        print(f"Backend Error: {e}")

    return jsonify(res)

@app.route('/get_stats')
def get_stats():
    # Counts malicious vs total records for the live chart
    mal = history_collection.count_documents({
        "$or": [{"score": {"$gt": 50}}, {"scan_type": "domain", "score": {"$gt": 0}}]
    })
    tot = history_collection.count_documents({})
    return jsonify({"malicious": mal, "safe": max(0, tot - mal), "total": tot})

@app.route('/export')
def export():
    # Forensic Export logic
    data = list(history_collection.find({}, {'_id': 0}))
    if not data: return "Database empty."
    
    si = io.StringIO()
    # Fixed fieldnames to prevent the dict error
    cw = csv.DictWriter(si, fieldnames=["target", "score", "field1", "field2", "lat", "lon", "scan_type", "timestamp"], extrasaction='ignore')
    cw.writeheader()
    cw.writerows(data)
    return Response(si.getvalue(), mimetype="text/csv", headers={"Content-disposition": "attachment; filename=CTI_Forensic_Logs.csv"})

if __name__ == '__main__':
    # use_reloader=False stops the Windows socket error
    app.run(debug=True, port=5000, use_reloader=False)
# app.py

from flask import Flask, render_template, jsonify, request
from flask_sock import Sock
import threading
import time
import json

# Import the core logic functions and globals
from core.network_analysis import (
    load_ml_model, create_session_api, start_capture_api, stop_capture_api, 
    export_pcap_api, get_websocket_data
)
from core.phishing_detector import analyze_url
from core.web_scanner import scan_website


# Initialize Flask and configure paths
app = Flask(__name__, 
            template_folder='website/templates', 
            static_folder='website/static')
sock = Sock(app)


# --- 1. ROUTING FOR NAVIGATION ---

@app.route("/")
def home():
    return render_template("homepage.html") 

@app.route("/dashboard")
def dashboard():
    return render_template("index.html") 

@app.route("/network")
def network():
    return render_template("network_frontend.html")   # :contentReference[oaicite:1]{index=1}

@app.route("/phishing")
def phishing():
    return render_template("phishing.html")   # :contentReference[oaicite:2]{index=2}

@app.route("/vulnerability")
def vulnerability():
    return render_template("vulnerability.html")   # :contentReference[oaicite:3]{index=3}



# --- 2. ROUTING FOR NETWORK ANALYSIS API (Calling Core Functions) ---

@app.route("/api/sessions", methods=["POST"])
def route_create_session():
    return create_session_api()

@app.route("/api/sessions/<int:sid>/start", methods=["POST"])
def route_start_capture(sid):
    # Calls the imported function
    return start_capture_api(sid)

@app.route("/api/sessions/<int:sid>/stop", methods=["POST"])
def route_stop_capture(sid):
    # Calls the imported function
    return stop_capture_api(sid)

@app.route("/api/sessions/<int:sid>/export.pcap", methods=["GET"])
def route_export_pcap(sid):
    # Calls the imported function
    return export_pcap_api(sid)


# --- 3. ROUTING FOR SECURITY MODULES (Calling Placeholder Functions) ---

@app.route("/api/analyze/phishing", methods=["POST"])
def api_phishing_detector():
    """Endpoint to check a single URL for phishing."""
    url = request.json.get('url')
    if not url:
        return jsonify({"error": "URL parameter missing"}), 400
    
    result = analyze_url(url) # Calls the core logic
    return jsonify(result)

@app.route("/api/scan/web", methods=["POST"])
def api_web_scanner():
    """Endpoint to run a basic web vulnerability scan."""
    url = request.json.get('url')
    if not url:
        return jsonify({"error": "URL parameter missing"}), 400
    
    result = scan_website(url) # Calls the core logic
    return jsonify(result)


# --- 4. WEBSOCKET ROUTE ---

@sock.route("/ws")
def ws(ws):
    while True:
        try:
            new_flows, stats_data = get_websocket_data()

            # Send new flows immediately
            for flow in new_flows:
                ws.send(json.dumps({"type": "packet", "data": flow}))

            # Send stats if they were calculated
            if stats_data:
                ws.send(json.dumps({"type": "stats", "data": stats_data}))
            
            time.sleep(0.2)
        except Exception as e:
            print(f"WebSocket closed or error: {e}")
            break


# --- 5. APPLICATION STARTUP ---
if __name__ == "__main__":
    load_ml_model() # Load the model once on startup
    app.run(debug=True, host="0.0.0.0", port=5000)
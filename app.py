# app.py

from flask import Flask, render_template, jsonify, request
from flask_sock import Sock
import threading
import time
import json
import atexit
import importlib

# Import the core logic functions and globals
from core.api_routes import register_api_endpoints
from core import notifications
from core.network_analysis import get_websocket_data
from core.scheduler import scheduler


# Initialize Flask and configure paths
app = Flask(__name__, 
            template_folder='website/templates', 
            static_folder='website/static')
sock = Sock(app)

# Register API endpoints early
register_api_endpoints(app)


# --- 1. ROUTING FOR NAVIGATION ---

@app.route("/")
def home():
    return render_template("homepage.html") 

@app.route("/dashboard")
def dashboard():
    return render_template("index.html") 

@app.route("/network")
def network():
    return render_template("network_frontend.html")

@app.route("/phishing")
def phishing():
    return render_template("phishing.html")

@app.route("/vulnerability")
def vulnerability():
    return render_template("vulnerability.html")


# --- 2. ROUTING FOR SECURITY MODULES ---

# Routes moved to Blueprint in core/api_routes.py


# --- 4. WEBSOCKET ROUTE ---

@sock.route("/ws")
def ws(ws_connection):
    print("🚀 WebSocket connection established")
    
    while True:
        try:
            # 1. Fetch real-time packet data and stats
            new_flows, stats_data = get_websocket_data()

            for flow in new_flows:
                ws_connection.send(json.dumps({"type": "packet", "data": flow}))

            if stats_data:
                ws_connection.send(json.dumps({"type": "stats", "data": stats_data}))

            # 2. Fetch and send Phishing/Vulnerability notifications
            notes = notifications.pop_all()
            for note in notes:
                ws_connection.send(json.dumps({
                    "type": note['type'], 
                    "data": note['data']
                }))

            time.sleep(0.5)

        except Exception as e:
            # This try-except block is the correct way to detect a closed connection
            print(f"WebSocket disconnected: {e}")
            break


# --- 5. APPLICATION STARTUP ---
if __name__ == "__main__":
    # ======================================================================
    # 🆕 INITIALIZE PHISHING DETECTOR ML MODEL (LOAD ONCE AT STARTUP)
    # ======================================================================
    print("=" * 70)
    print("🚀 Initializing CyberSleuth Application")
    print("=" * 70)

    # --- NEW: Pre-load the Network ML model in the background ---
    import threading
    def preload_network_model():
        try:
            print("\n[Network Analysis] Pre-loading ML model in background...")
            from core.network_analysis import load_ml_model
            load_ml_model()
            print("✅ [Network Analysis] ML model loaded successfully and ready!")
        except Exception as e:
            print(f"⚠️ [Network Analysis] Warning: Could not load ML model: {e}")

    # Launch the thread so it doesn't block the server from starting
    threading.Thread(target=preload_network_model, daemon=True).start()
    # ------------------------------------------------------------

    print("\n" + "=" * 70)
    print("✅ Application ready - Starting Flask server")
    print("=" * 70 + "\n")

    # ML models are loaded lazily when starting capture to avoid heavy imports at startup
    app.run(debug=True, host="0.0.0.0", port=5000)


if scheduler:
    atexit.register(lambda: scheduler.shutdown())

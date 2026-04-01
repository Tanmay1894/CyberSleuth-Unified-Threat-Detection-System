# app.py

from flask import Flask, render_template, jsonify, request
from flask_sock import Sock
import threading
import time
import json
import atexit
import importlib

try:
    _apscheduler_bg = importlib.import_module('apscheduler.schedulers.background')
    BackgroundScheduler = getattr(_apscheduler_bg, 'BackgroundScheduler', None)
except Exception:
    BackgroundScheduler = None

# Import the core logic functions and globals
from core.api_routes import register_api_endpoints
from core import notifications


# Initialize Flask and configure paths
app = Flask(__name__, 
            template_folder='website/templates', 
            static_folder='website/static')
sock = Sock(app)

scheduler = BackgroundScheduler() if BackgroundScheduler else None
if scheduler:
    scheduler.start()

# Register API endpoints
register_api_endpoints(app)


def scheduled_vuln_scan():
    """Run vulnerability scans on suspicious phishing links."""
    try:
        from core.database import db
        from core.web_scanner import scan_website

        suspicious_links = db.get_suspicious_phishing_links(risk_threshold=70)
        for link in suspicious_links[:5]:
            try:
                vuln_result = scan_website(link['url'])
                scan_record = {
                    'url': link['url'],
                    'target_url': link['url'],
                    'phishing_url': link['url'],
                    'phishing_risk': link.get('risk_score', 0),
                    'vulnerabilities': vuln_result.get('findings', []),
                    'severity': vuln_result.get('overall_severity', 'Info'),
                    'source': 'scheduled-auto',
                    'status': 'completed',
                    **vuln_result
                }
                db.save_vulnerability_scan(scan_record)
            except Exception as inner_error:
                print(f"Scheduled auto-scan failed for {link.get('url')}: {inner_error}")
    except Exception as e:
        print(f"Scheduled vulnerability scan error: {e}")


@app.route('/api/vuln/schedule', methods=['POST'])
def add_vuln_schedule():
    schedule_data = request.json or {}

    if not scheduler:
        return jsonify({'error': 'APScheduler is not installed'}), 500

    try:
        scan_time = schedule_data.get('time', '09:00')
        hours, minutes = scan_time.split(':')
        job_id = f"vuln_scan_{schedule_data.get('id', int(time.time()))}"

        scheduler.add_job(
            scheduled_vuln_scan,
            'cron',
            hour=int(hours),
            minute=int(minutes),
            id=job_id,
            replace_existing=True
        )
        return jsonify({'status': 'scheduled', 'job_id': job_id}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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


# --- 2. ROUTING FOR NETWORK ANALYSIS API ---

@app.route("/api/sessions", methods=["POST"])
def route_create_session():
    # Lazy import to avoid heavy startup imports
    from core.network_analysis import create_session_api
    return create_session_api()

@app.route("/api/sessions/<int:sid>/start", methods=["POST"])
def route_start_capture(sid):
    # Ensure ML model is loaded before starting capture
    from core.network_analysis import load_ml_model, start_capture_api
    try:
        load_ml_model()
    except Exception:
        pass
    return start_capture_api(sid)

@app.route("/api/sessions/<int:sid>/stop", methods=["POST"])
def route_stop_capture(sid):
    from core.network_analysis import stop_capture_api
    return stop_capture_api(sid)

@app.route("/api/sessions/<int:sid>/export.pcap", methods=["GET"])
def route_export_pcap(sid):
    from core.network_analysis import export_pcap_api
    return export_pcap_api(sid)


# --- 3. ROUTING FOR SECURITY MODULES ---

@app.route("/api/analyze/phishing", methods=["POST"])
def api_phishing_detector():
    """Endpoint to check a single URL for phishing manually."""
    url = request.json.get('url')
    session_id = request.json.get('session_id')
    if not url:
        return jsonify({"error": "URL parameter missing"}), 400

    from core.phishing_detector import analyze_url
    result = analyze_url(url, source="Manual", session_id=session_id)
    return jsonify(result)

@app.route("/api/scan/web", methods=["POST"])
def api_web_scanner():
    """Endpoint to run a web vulnerability scan."""
    url = request.json.get('url')
    session_id = request.json.get('session_id')
    if not url:
        return jsonify({"error": "URL parameter missing"}), 400
    # Start an async scan and return pending status
    from core.web_scanner import start_vulnerability_scan
    result = start_vulnerability_scan(session_id, url)
    if isinstance(result, dict) and result.get('error'):
        return jsonify(result), 500
    return jsonify(result)


# --- 4. WEBSOCKET ROUTE ---

@sock.route("/ws")
def ws(ws):
    while True:
        try:
            # Lazy import websocket data helper
            from core.network_analysis import get_websocket_data
            new_flows, stats_data = get_websocket_data()

            # Send new flows immediately
            for flow in new_flows:
                ws.send(json.dumps({"type": "packet", "data": flow}))

            # Send stats if they were calculated
            if stats_data:
                ws.send(json.dumps({"type": "stats", "data": stats_data}))

            # Deliver any queued notifications (phishing / vulnerabilities)
            try:
                notes = notifications.pop_all()
                for note in notes:
                    if note['type'] == 'phishing':
                        ws.send(json.dumps({"type": "phishing", "data": note['data']}))
                    elif note['type'] == 'vulnerability':
                        ws.send(json.dumps({"type": "vulnerability", "data": note['data']}))
                    elif note['type'] == 'flow':
                        ws.send(json.dumps({"type": "packet", "data": note['data']}))
            except Exception:
                pass

            time.sleep(0.2)
        except Exception as e:
            print(f"WebSocket closed or error: {e}")
            break


# --- 5. APPLICATION STARTUP ---
if __name__ == "__main__":
    # ======================================================================
    # 🆕 INITIALIZE PHISHING DETECTOR ML MODEL (LOAD ONCE AT STARTUP)
    # ======================================================================
    print("=" * 70)
    print("🚀 Initializing CyberSleuth Application")
    print("=" * 70)

    # Temporarily disable heavy ML init to keep startup fast
    # try:
    #     from core.phishing_detector import initialize_ml_model
    #     print("\n[Phishing Detector] Loading ML model...")
    #     initialize_ml_model()
    #     print("✅ [Phishing Detector] ML model loaded successfully")
    # except Exception as e:
    #     print(f"⚠️  [Phishing Detector] Warning: Could not load ML model: {e}")
    #     print("    Phishing detection will use heuristics only")

    print("\n" + "=" * 70)
    print("✅ Application ready - Starting Flask server")
    print("=" * 70 + "\n")

    # ML models are loaded lazily when starting capture to avoid heavy imports at startup
    app.run(debug=True, host="0.0.0.0", port=5000)


if scheduler:
    atexit.register(lambda: scheduler.shutdown())

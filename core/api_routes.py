# core/api_routes.py

from flask import Blueprint, jsonify, request
from core.database import db
from core import network_analysis, phishing_detector, web_scanner

# Use a Blueprint instead of a global app
api_bp = Blueprint("api", __name__)

# --- Sessions API ---

@api_bp.route('/api/sessions', methods=['GET'])
def get_sessions():
    """Get all sessions."""
    try:
        sessions = db.get_sessions()
        return jsonify({'sessions': sessions}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/api/sessions/<int:session_id>', methods=['GET'])
def get_session(session_id):
    """Get a specific session."""
    try:
        session = db.get_session(session_id)
        if not session:
            return jsonify({'error': 'Session not found'}), 404
        return jsonify(session), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/api/sessions/<int:session_id>/status', methods=['GET'])
def get_session_status(session_id):
    """Check if session is actively scanning."""
    from core.network_analysis import is_session_active
    active = is_session_active(session_id)
    return jsonify({
        "sessionId": session_id,
        "isActive": active,
        "status": "active" if active else "stopped"
    }), 200

# --- Network Flows API ---

@api_bp.route('/api/flows', methods=['GET'])
def get_flows():
    """Get all flows with optional limit."""
    try:
        limit = request.args.get('limit', 100, type=int)
        flows = db.get_all_flows(limit=limit)
        return jsonify({'flows': flows}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/api/flows/<int:session_id>', methods=['GET'])
def get_flows_by_session(session_id):
    """Get flows for a specific session."""
    try:
        limit = request.args.get('limit', 1000, type=int)
        flows = db.get_flows_by_session(session_id, limit=limit)
        return jsonify({'flows': flows, 'count': len(flows), 'session_id': session_id}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- Phishing API ---

@api_bp.route('/api/phishing/history', methods=['GET'])
def get_phishing_history():
    """Get all phishing scan history."""
    try:
        limit = request.args.get('limit', 100, type=int)
        from core import phishing_detector  # lazy import
        results = db.get_recent_phishing_results(limit=limit)
        return jsonify({'results': results, 'scans': results, 'count': len(results)}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/api/phishing/session/<int:session_id>', methods=['GET'])
def get_phishing_by_session(session_id):
    """Get phishing scans for a specific session."""
    try:
        limit = request.args.get('limit', 100, type=int)
        from core import phishing_detector  # lazy import, in case it's needed later
        scans = db.get_phishing_scans_by_session(session_id, limit=limit)
        return jsonify({'scans': scans, 'session_id': session_id}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/api/phishing/monitor/start', methods=['POST'])
def start_phishing_monitor():
    """Start browser monitoring."""
    try:
        from core import phishing_detector  # lazy import
        result = phishing_detector.start_monitoring()
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/api/phishing/monitor/stop', methods=['POST'])
def stop_phishing_monitor():
    """Stop browser monitoring."""
    try:
        from core import phishing_detector  # lazy import
        result = phishing_detector.stop_monitoring()
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/api/phishing/monitor/status', methods=['GET'])
def get_phishing_monitor_status():
    """Get browser monitoring status."""
    try:
        from core import phishing_detector  # lazy import
        status = phishing_detector.get_monitor_status()
        return jsonify(status), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/api/phishing/browser-history', methods=['GET'])
def get_phishing_browser_history():
    """Get monitored browser history URLs."""
    try:
        limit = request.args.get('limit', 50, type=int)
        from core import phishing_detector  # lazy import
        urls = phishing_detector.get_monitored_urls()
        return jsonify({'urls': urls[:limit], 'total': len(urls)}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- Vulnerability API ---

@api_bp.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """Get all vulnerability scans."""
    try:
        limit = request.args.get('limit', 50, type=int)
        scans = db.get_vulnerability_scans(limit=limit)
        return jsonify({'scans': scans}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/api/vulnerabilities/history', methods=['GET'])
def get_vulnerability_history():
    """Get recent vulnerability scan history."""
    try:
        limit = request.args.get('limit', 20, type=int)
        scans = db.get_recent_vulnerability_scans(limit=limit)
        return jsonify({'scans': scans, 'count': len(scans)}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/api/vuln/history', methods=['GET'])
def get_vuln_history_alias():
    """Alias endpoint for vulnerability history."""
    try:
        limit = request.args.get('limit', 20, type=int)
        scans = db.get_recent_vulnerability_scans(limit=limit)
        return jsonify({'results': scans, 'count': len(scans)}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/api/phishing-to-vuln', methods=['POST'])
def auto_scan_suspicious_phishing():
    """Auto-scan high-risk phishing links for vulnerabilities."""
    try:
        from core.web_scanner import scan_website
        suspicious_links = db.get_suspicious_phishing_links(risk_threshold=70)

        results = []
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
                    'source': 'auto-phishing',
                    'status': 'completed',
                    **vuln_result
                }
                db.save_vulnerability_scan(scan_record)
                results.append(scan_record)
            except Exception as inner_error:
                print(f"Auto-scan failed for {link.get('url')}: {inner_error}")

        return jsonify({'auto_scans': len(results), 'results': results}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/api/vuln/auto-start', methods=['GET'])
def start_auto_vuln_scanning():
    """Return count of suspicious phishing links for auto-scanning."""
    try:
        suspicious_count = len(db.get_suspicious_phishing_links(risk_threshold=70))
        return jsonify({'suspicious_links': suspicious_count}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/api/sessions/latest', methods=['GET'])
def get_latest_session():
    """Get the latest session id."""
    try:
        latest_id = db.get_latest_session_id()
        return jsonify({'sessionId': latest_id}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/api/vulnerabilities/<int:scan_id>', methods=['GET'])
def get_vulnerability_scan(scan_id):
    """Get a specific vulnerability scan."""
    try:
        scan = db.get_vulnerability_scan(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        return jsonify(scan), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/api/vulnerabilities/session/<int:session_id>', methods=['GET'])
def get_vulnerabilities_by_session(session_id):
    """Get vulnerability scans for a specific session."""
    try:
        limit = request.args.get('limit', 50, type=int)
        scans = db.get_vulnerability_scans_by_session(session_id, limit=limit)
        return jsonify({'scans': scans, 'session_id': session_id}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/api/vulnerabilities/details/<int:scan_id>', methods=['GET'])
def get_vulnerability_details(scan_id):
    """Get detailed results for a vulnerability scan."""
    try:
        scan = db.get_vulnerability_scan(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        return jsonify(scan), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- Statistics API ---

@api_bp.route('/api/statistics', methods=['GET'])
def get_statistics():
    """Get system statistics."""
    try:
        stats = db.get_statistics()
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/api/threat-breakdown', methods=['GET'])
def get_threat_breakdown():
    """Get counts of different threat types for the pie chart."""
    try:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            # Get counts from different modules
            cursor.execute("SELECT COUNT(*) FROM network_flows WHERE is_anomalous = 1")
            net_anomalies = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM phishing_scans WHERE final_verdict = 'MALICIOUS'")
            phishing = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM vulnerability_scans WHERE status = 'completed'")
            vulns = cursor.fetchone()[0]
            
            return jsonify({
                'labels': ['Network Anomalies', 'Phishing Links', 'Web Vulnerabilities'],
                'data': [net_anomalies, phishing, vulns]
            }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/api/dashboard/alerts', methods=['GET'])
def get_dashboard_alerts():
    """Fetch the 10 most recent security alerts across all modules."""
    alerts = []
    try:
        with db.get_connection() as conn:
            cursor = conn.cursor()

            # 1. Get Anomalous Network Flows
            cursor.execute('''
                SELECT 'Network' as type, src_ip || ' -> ' || dst_ip as target, 
                       anomaly_score as severity_val, created_at as ts
                FROM network_flows WHERE is_anomalous = 1
                ORDER BY created_at DESC LIMIT 5
            ''')
            for row in cursor.fetchall():
                alerts.append({
                    'module': row['type'],
                    'message': f"Anomaly detected: {row['target']}",
                    'severity': 'high' if row['severity_val'] > 0.8 else 'medium',
                    'time': row['ts']
                })

            # 2. Get Malicious Phishing URLs
            cursor.execute('''
                SELECT 'Phishing' as type, url, final_verdict, timestamp as ts
                FROM phishing_scans WHERE final_verdict IN ('MALICIOUS', 'SUSPICIOUS')
                ORDER BY timestamp DESC LIMIT 5
            ''')
            for row in cursor.fetchall():
                alerts.append({
                    'module': row['type'],
                    'message': f"Threat: {row['url'][:30]}...",
                    'severity': 'critical' if row['final_verdict'] == 'MALICIOUS' else 'high',
                    'time': row['ts']
                })

            # 3. Get Critical Vulnerabilities
            cursor.execute('''
                SELECT 'Vulnerability' as type, target_url, timestamp as ts, results
                FROM vulnerability_scans WHERE status = 'completed'
                ORDER BY timestamp DESC LIMIT 5
            ''')
            for row in cursor.fetchall():
                import json
                res = json.loads(row['results']) if row['results'] else {}
                if res.get('overall_severity') in ['High', 'Critical']:
                    alerts.append({
                        'module': row['type'],
                        'message': f"Vulnerability on {row['target_url']}",
                        'severity': res.get('overall_severity').lower(),
                        'time': row['ts']
                    })

        # Sort combined alerts by time descending
        alerts.sort(key=lambda x: x['time'], reverse=True)
        return jsonify(alerts[:10]), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- Network Capture API ---

@api_bp.route('/api/sessions', methods=['POST'])
def create_network_session():
    return network_analysis.create_session_api()

@api_bp.route('/api/sessions/<int:session_id>/start', methods=['POST'])
def start_network_capture(session_id):
    from core.network_analysis import load_ml_model
    try:
        load_ml_model()
    except Exception:
        pass
    return network_analysis.start_capture_api(session_id)

@api_bp.route('/api/sessions/<int:session_id>/stop', methods=['POST'])
def stop_network_capture(session_id):
    return network_analysis.stop_capture_api(session_id)

@api_bp.route('/api/sessions/<int:session_id>/export.pcap', methods=['GET'])
def export_network_pcap(session_id):
    return network_analysis.export_pcap_api(session_id)

# --- Security Analysis API ---

@api_bp.route('/api/analyze/phishing', methods=['POST'])
def api_phishing_detector():
    """Endpoint to check a single URL for phishing manually."""
    data = request.get_json(force=True, silent=True) or {}
    url = data.get('url')
    session_id = data.get('session_id')
    if not url:
        return jsonify({"error": "URL parameter missing"}), 400

    result = phishing_detector.analyze_url(url, source="Manual", session_id=session_id)
    return jsonify(result)

@api_bp.route('/api/scan/web', methods=['POST'])
def api_web_scanner():
    """Endpoint to run a web vulnerability scan."""
    data = request.get_json(force=True, silent=True) or {}
    url = data.get('url')
    session_id = data.get('session_id')
    if not url:
        return jsonify({"error": "URL parameter missing"}), 400

    result = web_scanner.start_vulnerability_scan(session_id, url)
    if isinstance(result, dict) and result.get('error'):
        return jsonify(result), 500
    return jsonify(result)

@api_bp.route('/api/vuln/schedule', methods=['POST'])
def add_vuln_schedule():
    from apscheduler.schedulers.background import BackgroundScheduler
    import time

    schedule_data = request.json or {}

    try:
        scan_time = schedule_data.get('time', '09:00')
        hours, minutes = scan_time.split(':')
        job_id = f"vuln_scan_{schedule_data.get('id', int(time.time()))}"

        # For now, we'll need to handle scheduler differently since it's in app.py
        # This is a placeholder - the scheduler should be moved to a shared location
        return jsonify({'error': 'Scheduler not available in Blueprint'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def register_api_endpoints(app):
    """Attach all API routes to the Flask app."""
    app.register_blueprint(api_bp)

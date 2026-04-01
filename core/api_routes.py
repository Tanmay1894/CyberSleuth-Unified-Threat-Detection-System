# core/api_routes.py

from flask import jsonify, request
from core.database import db
from core import phishing_detector


def register_api_endpoints(app):
    """Register all REST API endpoints for historical data retrieval."""
    
    # --- Sessions API ---
    
    @app.route('/api/sessions', methods=['GET'])
    def get_sessions():
        """Get all sessions."""
        try:
            sessions = db.get_sessions()
            return jsonify({'sessions': sessions}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/sessions/<int:session_id>', methods=['GET'])
    def get_session(session_id):
        """Get a specific session."""
        try:
            session = db.get_session(session_id)
            if not session:
                return jsonify({'error': 'Session not found'}), 404
            return jsonify(session), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/sessions/<int:sid>/status', methods=['GET'])
    def get_session_status(sid):
        """Check if session is actively scanning."""
        from core.network_analysis import sniffing, currentdbsessionid

        is_active = False
        if currentdbsessionid == sid:
            is_active = sniffing

        return jsonify({
            'sessionId': sid,
            'isActive': is_active,
            'snifferStatus': 'active' if is_active else 'stopped'
        }), 200
    
    # --- Network Flows API ---
    
    @app.route('/api/flows', methods=['GET'])
    def get_flows():
        """Get all flows with optional limit."""
        try:
            limit = request.args.get('limit', 100, type=int)
            flows = db.get_all_flows(limit=limit)
            return jsonify({'flows': flows}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/flows/<int:session_id>', methods=['GET'])
    def get_flows_by_session(session_id):
        """Get flows for a specific session."""
        try:
            limit = request.args.get('limit', 1000, type=int)
            flows = db.get_flows_by_session(session_id, limit=limit)
            return jsonify({'flows': flows, 'count': len(flows), 'session_id': session_id}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    # --- Phishing API ---
    
    @app.route('/api/phishing/history', methods=['GET'])
    def get_phishing_history():
        """Get all phishing scan history."""
        try:
            limit = request.args.get('limit', 100, type=int)
            results = db.get_recent_phishing_results(limit=limit)
            return jsonify({'results': results, 'scans': results, 'count': len(results)}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/phishing/session/<int:session_id>', methods=['GET'])
    def get_phishing_by_session(session_id):
        """Get phishing scans for a specific session."""
        try:
            limit = request.args.get('limit', 100, type=int)
            scans = db.get_phishing_scans_by_session(session_id, limit=limit)
            return jsonify({'scans': scans, 'session_id': session_id}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/phishing/monitor/start', methods=['POST'])
    def start_phishing_monitor():
        """Start browser monitoring."""
        try:
            result = phishing_detector.start_monitoring()
            return jsonify(result), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/phishing/monitor/stop', methods=['POST'])
    def stop_phishing_monitor():
        """Stop browser monitoring."""
        try:
            result = phishing_detector.stop_monitoring()
            return jsonify(result), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/phishing/monitor/status', methods=['GET'])
    def get_phishing_monitor_status():
        """Get browser monitoring status."""
        try:
            status = phishing_detector.get_monitor_status()
            return jsonify(status), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/phishing/browser-history', methods=['GET'])
    def get_phishing_browser_history():
        """Get monitored browser history URLs."""
        try:
            limit = request.args.get('limit', 50, type=int)
            urls = phishing_detector.get_monitored_urls()
            return jsonify({
                'urls': urls[:limit],
                'total': len(urls)
            }), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    # --- Vulnerability API ---
    
    @app.route('/api/vulnerabilities', methods=['GET'])
    def get_vulnerabilities():
        """Get all vulnerability scans."""
        try:
            limit = request.args.get('limit', 50, type=int)
            scans = db.get_vulnerability_scans(limit=limit)
            return jsonify({'scans': scans}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/vulnerabilities/history', methods=['GET'])
    def get_vulnerability_history():
        """Get recent vulnerability scan history."""
        try:
            limit = request.args.get('limit', 20, type=int)
            scans = db.get_recent_vulnerability_scans(limit=limit)
            return jsonify({'scans': scans, 'count': len(scans)}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/vuln/history', methods=['GET'])
    def get_vuln_history_alias():
        """Alias endpoint for vulnerability history."""
        try:
            limit = request.args.get('limit', 20, type=int)
            scans = db.get_recent_vulnerability_scans(limit=limit)
            return jsonify({'results': scans, 'count': len(scans)}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/phishing-to-vuln', methods=['POST'])
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

    @app.route('/api/vuln/auto-start', methods=['GET'])
    def start_auto_vuln_scanning():
        """Return count of suspicious phishing links for auto-scanning."""
        try:
            suspicious_count = len(db.get_suspicious_phishing_links(risk_threshold=70))
            return jsonify({'suspicious_links': suspicious_count}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/sessions/latest', methods=['GET'])
    def get_latest_session():
        """Get the latest session id."""
        try:
            latest_id = db.get_latest_session_id()
            return jsonify({'sessionId': latest_id}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/vulnerabilities/<int:scan_id>', methods=['GET'])
    def get_vulnerability_scan(scan_id):
        """Get a specific vulnerability scan."""
        try:
            scan = db.get_vulnerability_scan(scan_id)
            if not scan:
                return jsonify({'error': 'Scan not found'}), 404
            return jsonify(scan), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/vulnerabilities/session/<int:session_id>', methods=['GET'])
    def get_vulnerabilities_by_session(session_id):
        """Get vulnerability scans for a specific session."""
        try:
            limit = request.args.get('limit', 50, type=int)
            scans = db.get_vulnerability_scans_by_session(session_id, limit=limit)
            return jsonify({'scans': scans, 'session_id': session_id}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/vulnerabilities/details/<int:scan_id>', methods=['GET'])
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
    
    @app.route('/api/statistics', methods=['GET'])
    def get_statistics():
        """Get system statistics."""
        try:
            stats = db.get_statistics()
            return jsonify(stats), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500

# core/database.py

import sqlite3
import json
import threading
from datetime import datetime
from contextlib import contextmanager


class DatabaseManager:
    """Thread-safe SQLite database manager for persistent storage of analysis data."""
    
    def __init__(self, db_path='cybersleuth.db'):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_database()
    
    @contextmanager
    def get_connection(self):
        """Context manager for thread-safe database connections."""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            except Exception as e:
                conn.rollback()
                raise e
            finally:
                conn.close()
    
    def _init_database(self):
        """Initialize database schema on first run."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    closed_at TIMESTAMP,
                    total_flows INTEGER DEFAULT 0,
                    total_packets INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'active'
                )
            ''')
            
            # Network flows table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_flows (
                    flow_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    packet_count INTEGER,
                    byte_count INTEGER,
                    duration REAL,
                    anomaly_score REAL,
                    is_anomalous INTEGER DEFAULT 0,
                    flow_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                )
            ''')
            
            # Phishing scans table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS phishing_scans (
                    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    url TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    gsb_status TEXT,
                    ml_verdict TEXT,
                    ml_confidence REAL,
                    final_verdict TEXT,
                    source TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                )
            ''')
            
            # Vulnerability scans table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerability_scans (
                    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    target_url TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    scan_type TEXT,
                    status TEXT DEFAULT 'pending',
                    results TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                )
            ''')
            
            # Vulnerability details table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerability_details (
                    detail_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    vulnerability_type TEXT,
                    severity TEXT,
                    description TEXT,
                    remediation TEXT,
                    FOREIGN KEY (scan_id) REFERENCES vulnerability_scans(scan_id)
                )
            ''')
            
            # Create indices for faster queries
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_flows_session ON network_flows(session_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_flows_created ON network_flows(created_at)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_phishing_session ON phishing_scans(session_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_phishing_timestamp ON phishing_scans(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_vuln_session ON vulnerability_scans(session_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_vuln_timestamp ON vulnerability_scans(timestamp)')
    
    def create_session(self):
        """Create a new analysis session."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO sessions (created_at, status) VALUES (?, ?)',
                          (datetime.now(), 'active'))
            conn.commit()
            return cursor.lastrowid
    
    def close_session(self, session_id):
        """Close a session and mark it as completed."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE sessions 
                SET closed_at = ?, status = 'completed'
                WHERE session_id = ?
            ''', (datetime.now(), session_id))
            conn.commit()
    
    def save_flow(self, session_id, flow_data):
        """Save a network flow to the database."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO network_flows 
                (session_id, src_ip, dst_ip, src_port, dst_port, protocol, packet_count, 
                 byte_count, duration, anomaly_score, is_anomalous, flow_data, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session_id,
                flow_data.get('src_ip'),
                flow_data.get('dst_ip'),
                flow_data.get('src_port'),
                flow_data.get('dst_port'),
                flow_data.get('protocol'),
                flow_data.get('packet_count', 0),
                flow_data.get('byte_count', 0),
                flow_data.get('duration', 0),
                flow_data.get('anomaly_score', 0),
                1 if flow_data.get('anomaly_score', 0) > 0.5 else 0,
                json.dumps(flow_data),
                datetime.now()
            ))
            conn.commit()
    
    def save_phishing_scan(self, session_id, scan_data):
        """Save a phishing scan result to the database."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO phishing_scans 
                (session_id, url, timestamp, gsb_status, ml_verdict, ml_confidence, 
                 final_verdict, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session_id,
                scan_data.get('url'),
                datetime.now(),
                scan_data.get('gsb_status'),
                scan_data.get('ml_verdict'),
                scan_data.get('ml_confidence', 0),
                scan_data.get('final_verdict'),
                scan_data.get('source', 'manual')
            ))
            conn.commit()
    
    def save_vulnerability_scan(self, session_id=None, scan_data=None):
        """Save a vulnerability scan report to the database.

        Supports both signatures:
        - save_vulnerability_scan(session_id, scan_data)
        - save_vulnerability_scan(scan_data)
        """
        if scan_data is None and isinstance(session_id, dict):
            scan_data = session_id
            session_id = scan_data.get('session_id')

        if scan_data is None:
            scan_data = {}

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO vulnerability_scans 
                (session_id, target_url, timestamp, scan_type, status, results)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                session_id,
                scan_data.get('target_url') or scan_data.get('url'),
                datetime.now(),
                scan_data.get('scan_type', 'full'),
                scan_data.get('status', 'completed'),
                json.dumps(scan_data)
            ))
            conn.commit()
            return cursor.lastrowid
    
    def get_sessions(self, limit=50):
        """Retrieve all sessions."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM sessions ORDER BY created_at DESC LIMIT ?', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_session(self, session_id):
        """Retrieve a specific session."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM sessions WHERE session_id = ?', (session_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_flows_by_session(self, session_id, limit=1000):
        """Get all flows for a specific session."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT flow_id, session_id, created_at, src_ip, dst_ip,
                       protocol, byte_count, flow_data, anomaly_score, packet_count, duration
                FROM network_flows
                WHERE session_id = ?
                ORDER BY created_at DESC
                LIMIT ?
            ''', (session_id, limit))

            rows = cursor.fetchall()
            flows = []

            for row in rows:
                row_dict = dict(row)
                parsed_flow_data = {}
                if row_dict.get('flow_data'):
                    try:
                        parsed_flow_data = json.loads(row_dict['flow_data'])
                    except Exception:
                        parsed_flow_data = {}

                row_dict['id'] = row_dict.get('flow_id')
                row_dict['timestamp'] = row_dict.get('created_at')
                row_dict['source_ip'] = row_dict.get('src_ip')
                row_dict['destination_ip'] = row_dict.get('dst_ip')
                row_dict['size'] = row_dict.get('byte_count')
                row_dict['info'] = parsed_flow_data.get('info', '')
                row_dict['flowdata'] = parsed_flow_data if parsed_flow_data else row_dict
                flows.append(row_dict)

            return flows
    
    def get_all_flows(self, limit=100):
        """Retrieve all flows globally."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM network_flows 
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (limit,))
            rows = cursor.fetchall()
            results = []
            for row in rows:
                row_dict = dict(row)
                if row_dict.get('flow_data'):
                    try:
                        row_dict['flow_data'] = json.loads(row_dict['flow_data'])
                    except Exception:
                        pass
                results.append(row_dict)
            return results
    
    def get_phishing_scans(self, limit=100):
        """Retrieve all phishing scans."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM phishing_scans 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_phishing_scans_by_session(self, session_id, limit=100):
        """Retrieve phishing scans for a specific session."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM phishing_scans 
                WHERE session_id = ? 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (session_id, limit))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_vulnerability_scans(self, limit=100):
        """Retrieve all vulnerability scans."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM vulnerability_scans 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            rows = cursor.fetchall()
            results = []
            for row in rows:
                row_dict = dict(row)
                if row_dict['results']:
                    row_dict['results'] = json.loads(row_dict['results'])
                results.append(row_dict)
            return results

    def get_recent_phishing_results(self, limit=100):
        """Get recent phishing results - monitoring AND manual."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            try:
                cursor.execute('''
                    SELECT id, url, timestamp, result, risk_score, source, features
                    FROM phishing_results
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (limit,))

                results = []
                for row in cursor.fetchall():
                    result = dict(row)
                    if result.get('features'):
                        try:
                            result['features'] = json.loads(result['features'])
                        except Exception:
                            pass
                    results.append(result)
                return results
            except sqlite3.OperationalError:
                cursor.execute('''
                    SELECT scan_id as id, url, timestamp, final_verdict as result,
                           ml_confidence as risk_score, source, NULL as features
                    FROM phishing_scans
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (limit,))

                results = []
                for row in cursor.fetchall():
                    result = dict(row)
                    try:
                        confidence = float(result.get('risk_score') or 0)
                        result['risk_score'] = max(0, min(100, round(confidence * 100)))
                    except Exception:
                        result['risk_score'] = 0
                    results.append(result)
                return results

    def get_recent_vulnerability_scans(self, limit=20):
        """Get recent vulnerability scans."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM vulnerability_scans
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            rows = cursor.fetchall()
            results = []
            for row in rows:
                row_dict = dict(row)
                if row_dict.get('results'):
                    try:
                        row_dict['results'] = json.loads(row_dict['results'])
                    except Exception:
                        pass
                results.append(row_dict)
            return results

    def get_suspicious_phishing_links(self, risk_threshold=70):
        """Get phishing links with high risk score for vulnerability scanning."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            try:
                cursor.execute('''
                    SELECT url, risk_score
                    FROM phishing_results
                    WHERE risk_score > ? AND result IN ('phishing', 'warning')
                    ORDER BY risk_score DESC
                    LIMIT 10
                ''', (risk_threshold,))
                return [dict(row) for row in cursor.fetchall()]
            except sqlite3.OperationalError:
                cursor.execute('''
                    SELECT url,
                           CAST(COALESCE(ml_confidence, 0) * 100 AS INTEGER) AS risk_score
                    FROM phishing_scans
                    WHERE (CAST(COALESCE(ml_confidence, 0) * 100 AS INTEGER)) > ?
                      AND LOWER(COALESCE(final_verdict, '')) IN ('malicious', 'suspicious')
                    ORDER BY risk_score DESC
                    LIMIT 10
                ''', (risk_threshold,))
                return [dict(row) for row in cursor.fetchall()]

    def get_latest_session_id(self):
        """Get latest session id."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT session_id
                FROM sessions
                ORDER BY created_at DESC
                LIMIT 1
            ''')
            row = cursor.fetchone()
            return row['session_id'] if row else None
    
    def get_vulnerability_scans_by_session(self, session_id, limit=100):
        """Retrieve vulnerability scans for a specific session."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM vulnerability_scans 
                WHERE session_id = ? 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (session_id, limit))
            rows = cursor.fetchall()
            results = []
            for row in rows:
                row_dict = dict(row)
                if row_dict['results']:
                    row_dict['results'] = json.loads(row_dict['results'])
                results.append(row_dict)
            return results
    
    def get_vulnerability_scan(self, scan_id):
        """Retrieve a specific vulnerability scan."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM vulnerability_scans WHERE scan_id = ?', (scan_id,))
            row = cursor.fetchone()
            if row:
                row_dict = dict(row)
                if row_dict['results']:
                    row_dict['results'] = json.loads(row_dict['results'])
                return row_dict
            return None

    def update_vulnerability_scan(self, scan_id, status=None, results=None):
        """Update status and results for a vulnerability scan."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if results is not None:
                cursor.execute('''
                    UPDATE vulnerability_scans
                    SET status = ?, results = ?, timestamp = ?
                    WHERE scan_id = ?
                ''', (status or 'completed', json.dumps(results), datetime.now(), scan_id))
            else:
                cursor.execute('''
                    UPDATE vulnerability_scans
                    SET status = ?, timestamp = ?
                    WHERE scan_id = ?
                ''', (status or 'completed', datetime.now(), scan_id))
            conn.commit()
    
    def get_statistics(self):
        """Get real-time system statistics from the database."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Count total packets captured across all sessions
            cursor.execute('SELECT SUM(packet_count) as count FROM network_flows')
            total_packets = cursor.fetchone()['count'] or 0
            
            # Count high-risk network anomalies (Score > 0.7)
            cursor.execute('SELECT COUNT(*) as count FROM network_flows WHERE anomaly_score > 0.7')
            alerts = cursor.fetchone()['count'] or 0
            
            # Count unique phishing URLs detected as MALICIOUS or SUSPICIOUS
            cursor.execute("SELECT COUNT(*) as count FROM phishing_scans WHERE final_verdict IN ('MALICIOUS', 'SUSPICIOUS')")
            phishing = cursor.fetchone()['count'] or 0
            
            # Count completed vulnerability scans with findings
            cursor.execute("SELECT COUNT(*) as count FROM vulnerability_scans WHERE status = 'completed'")
            vulns = cursor.fetchone()['count'] or 0
            
            return {
                'sessions': total_packets, # Total Packets
                'flows': alerts,           # Active Alerts
                'phishing_scans': phishing, # Suspicious URLs
                'vulnerability_scans': vulns # Vulnerable Sites
            }


# Global database instance
db = DatabaseManager()

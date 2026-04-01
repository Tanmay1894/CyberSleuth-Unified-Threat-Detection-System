import warnings
warnings.filterwarnings("ignore", message="sklearn.utils.parallel.delayed")

import re
import requests
import json
import sqlite3
import joblib
import pandas as pd
import numpy as np
import socket
import ssl
import whois
import os
import shutil
import time
import threading
from urllib.parse import urlparse
from datetime import datetime, timedelta
from threading import Lock
from bs4 import BeautifulSoup
import pytz

from core.database import db
from core import notifications

# ==========================================
# CONFIGURATION & API CONSTANTS
# ==========================================
GSB_API_KEY = ""  
GSB_ENDPOINT = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
MODEL_PATH = "models/phishing_model.pkl"

# Chrome Monitor Config
CHROME_USER_DATA = os.path.expanduser(r"~\AppData\Local\Google\Chrome\User Data")
TEMP_DB = "history_tmp.db"
POLL_INTERVAL = 2  # seconds
TIMEZONE = pytz.timezone("Asia/Kolkata")

# Global state for background monitoring
monitor_state = {
    "is_active": False,
    "baselines": {},
    "session_start_time": None,
    "seen_urls": set(),
    "monitored_urls": []  # Store all monitored URLs with results
}

MONITOR_LOCK = Lock()

# ==========================================
# DATABASE & LOGGING
# ==========================================
# Using central DB (core.database.db) and notification queues in core.notifications

# ==========================================
# PHISHING DETECTION LOGIC
# ==========================================
def analyze_url(url, source="Manual", session_id=None):
    """Analyze a URL for phishing threats."""
    
    # Normalize URL
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # GSB Check
    gsb_result = check_gsb(url)
    
    # ML Check
    ml_result = ml_phishing_check(url)
    
    # Combine verdicts
    if gsb_result.get('status') == "MALICIOUS":
        final_verdict = "MALICIOUS"
        confidence = 1.0
    elif gsb_result.get('status') == "SAFE" and ml_result.get('verdict') == "Safe":
        final_verdict = "SAFE"
        confidence = 1.0
    elif gsb_result.get('status') == "SAFE" and ml_result.get('verdict') == "Phishing":
        final_verdict = "SUSPICIOUS"
        confidence = ml_result.get('confidence', 0.5)
    else:
        final_verdict = "UNKNOWN"
        confidence = ml_result.get('confidence', 0.5)

    # Persist scan and push notification
    try:
        scan_record = {
            'url': url,
            'gsb_status': gsb_result.get('status'),
            'ml_verdict': ml_result.get('verdict'),
            'ml_confidence': ml_result.get('confidence'),
            'final_verdict': final_verdict,
            'source': source,
            'timestamp': datetime.now().isoformat()
        }
        db.save_phishing_scan(session_id, scan_record)
        notifications.push_phishing(scan_record)
    except Exception as e:
        print(f"Error saving phishing scan: {e}")

    return {
        "url": url,
        "gsb_status": gsb_result.get('status'),
        "ml_verdict": ml_result.get('verdict'),
        "ml_confidence": ml_result.get('confidence'),
        "final_verdict": final_verdict,
        "confidence": confidence,
        "timestamp": datetime.now().isoformat(),
        "session_id": session_id
    }

def check_gsb(url):
    """Check URL against Google Safe Browsing API."""
    try:
        payload = {
            "client": {
                "clientId": "cybersleuth",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        print(f"[GSB] Checking URL: {url}")
        print(f"[GSB] Endpoint: {GSB_ENDPOINT}")
        response = requests.post(GSB_ENDPOINT, json=payload, timeout=5)
        print(f"[GSB] Response status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"[GSB] Response data: {data}")
            if "matches" in data and len(data["matches"]) > 0:
                return {"status": "MALICIOUS", "details": data["matches"]}
            else:
                return {"status": "SAFE", "details": "Not found in GSB database"}
        else:
            print(f"[GSB] API error: {response.status_code} - {response.text}")
            return {"status": "UNKNOWN", "details": f"GSB API check failed: {response.status_code}"}
    except Exception as e:
        print(f"[GSB] Exception: {str(e)}")
        return {"status": "UNKNOWN", "details": str(e)}

def ml_phishing_check(url):
    """Check URL using ML model."""
    try:
        if not os.path.exists(MODEL_PATH):
            return {"verdict": "Unknown", "confidence": 0.5}
        
        model = joblib.load(MODEL_PATH)
        
        # Extract features from URL
        features = extract_phishing_features(url)
        
        # Predict
        prediction = model.predict([features])[0]
        confidence = model.predict_proba([features])[0].max()
        
        verdict = "Phishing" if prediction == 1 else "Safe"
        
        return {"verdict": verdict, "confidence": confidence}
    except Exception as e:
        print(f"ML check error: {e}")
        return {"verdict": "Unknown", "confidence": 0.5}

def extract_phishing_features(url):
    """Extract 30 features from URL for ML model."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        
        features = [
            # URL-based features
            len(url),
            url.count('@'),
            url.count('//'),
            url.count('-'),
            url.count('_'),
            url.count('?'),
            url.count('='),
            1 if 'https' in url else 0,
            len(domain.split('.')),
            1 if domain.startswith('www') else 0,
            # Domain features
            len(domain),
            domain.count('-'),
            domain.count('_'),
            # Additional features (placeholder)
            1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1
        ]
        
        return features[:30]  # Ensure exactly 30 features
    except:
        return [1] * 30

def start_browser_monitoring():
    """Start background browser monitoring thread."""
    def monitor_loop():
        profiles = get_chrome_profiles()
        
        # Establish baseline (ignore all previous history)
        baselines = {}
        for name, path in profiles:
            baselines[name] = get_latest_chrome_timestamp(path)
        
        print("Monitoring Chrome URLs from now on (all profiles)...\n")
        
        while monitor_state["is_active"]:
            try:
                for name, path in profiles:
                    new_rows = get_new_chrome_entries(path, baselines[name])
                    
                    for url, visit_time in new_rows:
                        baselines[name] = max(baselines[name], visit_time)
                        ts = chrome_time_to_datetime(visit_time)
                        
                        # Analyze URL immediately
                        if url not in monitor_state["seen_urls"]:
                            monitor_state["seen_urls"].add(url)
                            result = analyze_url(url, source="BrowserMonitor")
                            
                            with MONITOR_LOCK:
                                monitor_state["monitored_urls"].insert(0, {
                                    "url": url,
                                    "timestamp": ts.isoformat() if ts else datetime.now().isoformat(),
                                    "profile": name,
                                    "result": result
                                })
                                # Keep only last 100 URLs
                                if len(monitor_state["monitored_urls"]) > 100:
                                    monitor_state["monitored_urls"] = monitor_state["monitored_urls"][:100]
                            
                            print(f"[{name}] {ts} → {url} - {result['final_verdict']}")
                
                time.sleep(POLL_INTERVAL)
                
            except Exception as e:
                print(f"Monitor error: {e}")
                time.sleep(5)
    
    thread = threading.Thread(target=monitor_loop, daemon=True)
    thread.start()

def chrome_time_to_datetime(chrome_time):
    """Convert Chrome time to datetime."""
    if chrome_time == 0:
        return None
    epoch = datetime(1601, 1, 1)
    return TIMEZONE.localize(epoch + timedelta(microseconds=chrome_time))

def get_chrome_profiles():
    """Get all Chrome profiles and their history paths."""
    profiles = []
    try:
        for name in os.listdir(CHROME_USER_DATA):
            if name == "Default" or name.startswith("Profile"):
                history_path = os.path.join(CHROME_USER_DATA, name, "History")
                if os.path.exists(history_path):
                    profiles.append((name, history_path))
    except Exception as e:
        print(f"Error getting Chrome profiles: {e}")
    return profiles

def copy_chrome_db(src):
    """Copy Chrome history database to temp location."""
    try:
        shutil.copy2(src, TEMP_DB)
    except Exception as e:
        print(f"Error copying Chrome DB: {e}")

def get_latest_chrome_timestamp(history_path):
    """Get the latest timestamp from Chrome history."""
    try:
        copy_chrome_db(history_path)
        conn = sqlite3.connect(TEMP_DB)
        cur = conn.cursor()
        
        cur.execute("""
            SELECT MAX(last_visit_time) FROM urls
        """)
        
        result = cur.fetchone()[0]
        conn.close()
        os.remove(TEMP_DB)
        return result or 0
    except Exception as e:
        print(f"Error getting latest Chrome timestamp: {e}")
        if os.path.exists(TEMP_DB):
            try:
                os.remove(TEMP_DB)
            except:
                pass
        return 0

def get_new_chrome_entries(history_path, since_time):
    """Get new URL entries from Chrome history since a certain time."""
    try:
        copy_chrome_db(history_path)
        conn = sqlite3.connect(TEMP_DB)
        cur = conn.cursor()
        
        cur.execute("""
            SELECT url, last_visit_time
            FROM urls
            WHERE last_visit_time > ?
            ORDER BY last_visit_time ASC
        """, (since_time,))
        
        rows = cur.fetchall()
        conn.close()
        os.remove(TEMP_DB)
        return rows
    except Exception as e:
        print(f"Error getting new Chrome entries: {e}")
        if os.path.exists(TEMP_DB):
            try:
                os.remove(TEMP_DB)
            except:
                pass
        return []

def toggle_monitor(enable):
    """Toggle browser monitoring."""
    with MONITOR_LOCK:
        monitor_state["is_active"] = enable
        if enable:
            monitor_state["session_start_time"] = datetime.now().isoformat()
            monitor_state["seen_urls"] = set()
            monitor_state["monitored_urls"] = []
            start_browser_monitoring()
        else:
            monitor_state["seen_urls"] = set()

def get_monitored_urls():
    """Get all monitored URLs from the current session."""
    with MONITOR_LOCK:
        return monitor_state["monitored_urls"].copy()

def get_monitor_status():
    """Get the current monitoring status."""
    with MONITOR_LOCK:
        return {
            "is_active": monitor_state["is_active"],
            "session_start_time": monitor_state["session_start_time"],
            "url_count": len(monitor_state["monitored_urls"])
        }
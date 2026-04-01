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
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta
from threading import Lock
from bs4 import BeautifulSoup
import pytz
import math
from collections import Counter

from core.database import db
from core import notifications

# ==========================================
# CONFIGURATION & API CONSTANTS
# ==========================================
# Load API key from environment variable with fallback
GSB_API_KEY = os.environ.get("GSB_API_KEY", "")
GSB_ENDPOINT = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
MODEL_PATH = "models/phishing_model.pkl"

# Chrome Monitor Config
CHROME_USER_DATA = os.path.expanduser(r"~\AppData\Local\Google\Chrome\User Data")
TEMP_DB = "history_tmp.db"
POLL_INTERVAL = 2  # seconds
TIMEZONE = pytz.timezone("Asia/Kolkata")

# Global state for background monitoring (DO NOT MODIFY)
monitor_state = {
    "is_active": False,
    "baselines": {},
    "session_start_time": None,
    "seen_urls": set(),
    "monitored_urls": []  # Store all monitored URLs with results
}

MONITOR_LOCK = Lock()

# ==========================================
# GLOBAL ML MODEL (LOADED ONCE AT STARTUP)
# ==========================================
ML_MODEL = None
MODEL_LOCK = Lock()

# GSB API Cache and Rate Limiting
GSB_CACHE = {}
GSB_CACHE_LOCK = Lock()
GSB_CACHE_TTL = 3600  # 1 hour cache
GSB_LAST_CALL = 0
GSB_MIN_INTERVAL = 0.1  # 100ms between calls

# ==========================================
# RISK SCORE THRESHOLDS
# ==========================================
RISK_THRESHOLD_SAFE = 30
RISK_THRESHOLD_SUSPICIOUS = 60
RISK_THRESHOLD_MALICIOUS = 60

# ==========================================
# SUSPICIOUS KEYWORDS
# ==========================================
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update', 
    'confirm', 'banking', 'paypal', 'ebay', 'password', 'credit',
    'suspend', 'locked', 'urgent', 'unusual', 'activity', 'verify',
    'validation', 'authenticate', 'wallet', 'crypto'
]

# ==========================================
# MODEL INITIALIZATION
# ==========================================
def initialize_ml_model():
    """Load ML model once at application startup."""
    global ML_MODEL
    try:
        if os.path.exists(MODEL_PATH):
            with MODEL_LOCK:
                ML_MODEL = joblib.load(MODEL_PATH)
                print(f"[ML] Model loaded successfully from {MODEL_PATH}")
        else:
            print(f"[ML] Warning: Model file not found at {MODEL_PATH}")
    except Exception as e:
        print(f"[ML] Error loading model: {e}")

# ==========================================
# ADVANCED FEATURE EXTRACTION
# ==========================================
def extract_phishing_features(url):
    """
    Extract 30 features from URL for UCI phishing model.

    Feature mapping (must match training data order):
    [0] URL length
    [1] Number of dots in URL
    [2] Presence of @ symbol (1 if present, 0 otherwise)
    [3] Number of double slashes (//)
    [4] Number of hyphens in URL
    [5] Number of underscores in URL
    [6] Number of question marks
    [7] Number of equals signs
    [8] HTTPS presence (1 if https, 0 otherwise)
    [9] Subdomain depth (number of dots in domain)
    [10] Has www prefix (1 if yes, 0 otherwise)
    [11] Domain length
    [12] Hyphens in domain
    [13] Underscores in domain
    [14] URL entropy (randomness measure)
    [15] Has IP address instead of domain (1 if yes, 0 otherwise)
    [16] Number of query parameters
    [17] Suspicious keyword count
    [18] Domain age in days (0 if unavailable)
    [19] SSL certificate valid (1 if valid, 0 otherwise, -1 if unavailable)
    [20] Has login form (1 if detected, 0 otherwise, -1 if unavailable)
    [21] Has external forms (1 if detected, 0 otherwise, -1 if unavailable)
    [22] Number of iframes (0 if unavailable)
    [23] Number of external scripts (0 if unavailable)
    [24] Excessive redirects (1 if detected, 0 otherwise)
    [25] Port number present (1 if non-standard port, 0 otherwise)
    [26] Shortened URL (1 if detected, 0 otherwise)
    [27] Path depth (number of slashes in path)
    [28] Has fragment (#) (1 if present, 0 otherwise)
    [29] Digit ratio in domain (percentage of digits)
    """

    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query

        # Feature 0: URL length
        url_length = len(url)

        # Feature 1: Number of dots
        dot_count = url.count('.')

        # Feature 2: @ symbol presence
        at_symbol = 1 if '@' in url else 0

        # Feature 3: Double slashes
        double_slash = url.count('//')

        # Feature 4: Hyphens
        hyphen_count = url.count('-')

        # Feature 5: Underscores
        underscore_count = url.count('_')

        # Feature 6: Question marks
        question_count = url.count('?')

        # Feature 7: Equals signs
        equals_count = url.count('=')

        # Feature 8: HTTPS presence
        has_https = 1 if parsed.scheme == 'https' else 0

        # Feature 9: Subdomain depth
        subdomain_depth = len(domain.split('.')) - 1 if domain else 0

        # Feature 10: WWW prefix
        has_www = 1 if domain.startswith('www.') else 0

        # Feature 11: Domain length
        domain_length = len(domain)

        # Feature 12: Hyphens in domain
        domain_hyphens = domain.count('-')

        # Feature 13: Underscores in domain
        domain_underscores = domain.count('_')

        # Feature 14: URL entropy
        url_entropy = calculate_entropy(url)

        # Feature 15: IP address instead of domain
        has_ip = 1 if is_ip_address(domain) else 0

        # Feature 16: Number of query parameters
        query_params = len(parse_qs(query)) if query else 0

        # Feature 17: Suspicious keyword count
        suspicious_count = sum(1 for keyword in SUSPICIOUS_KEYWORDS if keyword in url.lower())

        # Feature 18: Domain age (expensive, use caching)
        domain_age_days = get_domain_age(domain)

        # Feature 19: SSL certificate validity
        ssl_valid = check_ssl_certificate(domain)

        # Feature 20-23: Content-based features (lightweight check)
        content_features = extract_content_features(url)
        has_login_form = content_features.get('has_login_form', -1)
        has_external_forms = content_features.get('has_external_forms', -1)
        iframe_count = content_features.get('iframe_count', 0)
        external_script_count = content_features.get('external_script_count', 0)

        # Feature 24: Excessive redirects
        excessive_redirects = check_redirects(url)

        # Feature 25: Non-standard port
        port = parsed.port
        non_standard_port = 1 if port and port not in [80, 443] else 0

        # Feature 26: Shortened URL
        is_shortened = 1 if is_url_shortener(domain) else 0

        # Feature 27: Path depth
        path_depth = path.count('/') if path else 0

        # Feature 28: Has fragment
        has_fragment = 1 if parsed.fragment else 0

        # Feature 29: Digit ratio in domain
        digit_ratio = calculate_digit_ratio(domain)

        # Assemble feature vector (exactly 30 features)
        features = [
            url_length,           # 0
            dot_count,            # 1
            at_symbol,            # 2
            double_slash,         # 3
            hyphen_count,         # 4
            underscore_count,     # 5
            question_count,       # 6
            equals_count,         # 7
            has_https,            # 8
            subdomain_depth,      # 9
            has_www,              # 10
            domain_length,        # 11
            domain_hyphens,       # 12
            domain_underscores,   # 13
            url_entropy,          # 14
            has_ip,               # 15
            query_params,         # 16
            suspicious_count,     # 17
            domain_age_days,      # 18
            ssl_valid,            # 19
            has_login_form,       # 20
            has_external_forms,   # 21
            iframe_count,         # 22
            external_script_count,# 23
            excessive_redirects,  # 24
            non_standard_port,    # 25
            is_shortened,         # 26
            path_depth,           # 27
            has_fragment,         # 28
            digit_ratio           # 29
        ]

        return features

    except Exception as e:
        print(f"[Feature Extraction] Error: {e}")
        # Return safe default features
        return [0] * 30

# ==========================================
# FEATURE EXTRACTION UTILITIES
# ==========================================
def calculate_entropy(text):
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0

    try:
        counter = Counter(text)
        length = len(text)
        entropy = 0.0

        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return round(entropy, 4)
    except:
        return 0.0

def is_ip_address(domain):
    """Check if domain is an IP address."""
    try:
        socket.inet_aton(domain)
        return True
    except:
        return False

def get_domain_age(domain):
    """
    Get domain age in days using WHOIS.
    Returns 0 if unavailable or error.
    """
    try:
        # Remove www prefix
        domain = domain.replace('www.', '')

        # Query WHOIS with timeout
        w = whois.whois(domain)

        if w.creation_date:
            creation_date = w.creation_date
            # Handle list of dates
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            # Calculate age
            age = (datetime.now() - creation_date).days
            return max(0, age)  # Ensure non-negative

        return 0
    except:
        return 0  # Safe fallback

def check_ssl_certificate(domain):
    """
    Check SSL certificate validity.
    Returns: 1 (valid), 0 (invalid/self-signed/expired), -1 (unavailable)
    """
    try:
        # Remove www prefix
        domain = domain.replace('www.', '')

        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                # Check expiration
                not_after = cert.get('notAfter')
                if not_after:
                    expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    if expiry_date < datetime.now():
                        return 0  # Expired

                return 1  # Valid
    except ssl.SSLError:
        return 0  # SSL error (self-signed, etc.)
    except:
        return -1  # Unavailable

def extract_content_features(url):
    """
    Extract content-based features from webpage.
    Returns dict with has_login_form, has_external_forms, iframe_count, external_script_count.
    """
    features = {
        'has_login_form': -1,
        'has_external_forms': -1,
        'iframe_count': 0,
        'external_script_count': 0
    }

    try:
        # Fetch with timeout and size limit
        response = requests.get(url, timeout=5, stream=True)

        # Read limited content (first 500KB)
        content_size = 0
        content_chunks = []
        for chunk in response.iter_content(chunk_size=8192):
            content_chunks.append(chunk)
            content_size += len(chunk)
            if content_size > 500000:  # 500KB limit
                break

        content = b''.join(content_chunks)

        # Parse HTML
        soup = BeautifulSoup(content, 'html.parser')
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Check for login forms
        forms = soup.find_all('form')
        has_login_form = 0
        has_external_forms = 0

        for form in forms:
            # Check for password fields
            password_fields = form.find_all('input', {'type': 'password'})
            if password_fields:
                has_login_form = 1

            # Check for external form actions
            action = form.get('action', '')
            if action and action.startswith('http'):
                action_domain = urlparse(action).netloc
                if action_domain and action_domain != domain:
                    has_external_forms = 1

        features['has_login_form'] = has_login_form
        features['has_external_forms'] = has_external_forms

        # Count iframes
        iframes = soup.find_all('iframe')
        features['iframe_count'] = len(iframes)

        # Count external scripts
        scripts = soup.find_all('script', {'src': True})
        external_scripts = 0
        for script in scripts:
            src = script.get('src', '')
            if src.startswith('http'):
                script_domain = urlparse(src).netloc
                if script_domain and script_domain != domain:
                    external_scripts += 1

        features['external_script_count'] = external_scripts

    except:
        pass  # Return default values

    return features

def check_redirects(url):
    """Check for excessive redirects. Returns 1 if excessive, 0 otherwise."""
    try:
        response = requests.head(url, allow_redirects=True, timeout=3)
        redirect_count = len(response.history)
        return 1 if redirect_count > 3 else 0
    except:
        return 0

def is_url_shortener(domain):
    """Check if domain is a known URL shortener."""
    shorteners = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 
        'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'short.link'
    ]
    return domain.lower() in shorteners

def calculate_digit_ratio(domain):
    """Calculate ratio of digits in domain."""
    if not domain:
        return 0.0
    digit_count = sum(c.isdigit() for c in domain)
    return round(digit_count / len(domain), 4)


def is_suspicious_url(features):
    """Static heuristics - instant zero-cost detection."""
    warnings_count = 0

    if features.get('is_ip'):
        warnings_count += 2

    if len(features.get('subdomains', [])) > 3:
        warnings_count += 1

    suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq']
    if features.get('tld') in suspicious_tlds:
        warnings_count += 1

    if features.get('domain_age_days', 0) < 30:
        warnings_count += 1

    return warnings_count >= 2


def make_final_decision(gsb_result, ml_score, ml_confidence, url_features):
    """
    HYBRID DECISION ENGINE - ML FIRST, GSB SECOND
    """
    ml_risk = ml_score * 100

    if is_suspicious_url(url_features):
        return "phishing", 95, "suspicious_features"

    if ml_risk > 75 and ml_confidence > 0.8:
        return "phishing", ml_risk, "ml_detection"
    elif ml_risk > 50:
        if gsb_result == "phishing":
            return "phishing", 90, "gsb_confirmed"
        return "warning", ml_risk, "ml_suspicious"
    else:
        if gsb_result == "phishing":
            return "phishing", 85, "gsb_only"
        return "safe", ml_risk, "all_clear"

# ==========================================
# ML PHISHING CHECK (REFACTORED)
# ==========================================
def ml_phishing_check(url):
    """Check URL using trained ML model with real feature extraction."""
    try:
        global ML_MODEL

        # Initialize model if not loaded
        if ML_MODEL is None:
            initialize_ml_model()

        if ML_MODEL is None:
            return {"verdict": "Unknown", "confidence": 0.5}

        # Extract real features (30 features matching training data)
        features = extract_phishing_features(url)

        # Thread-safe prediction
        with MODEL_LOCK:
            # Reshape for single prediction
            features_array = np.array(features).reshape(1, -1)

            prediction = ML_MODEL.predict(features_array)[0]
            probabilities = ML_MODEL.predict_proba(features_array)[0]
            confidence = probabilities.max()

        verdict = "Phishing" if prediction == 1 else "Safe"

        return {
            "verdict": verdict, 
            "confidence": float(confidence),
            "features": features  # Include for debugging
        }

    except Exception as e:
        print(f"[ML] Error during prediction: {e}")
        return {"verdict": "Unknown", "confidence": 0.5}

# ==========================================
# GOOGLE SAFE BROWSING (WITH CACHING & THROTTLING)
# ==========================================
def check_gsb(url):
    """Check URL against Google Safe Browsing API with caching and rate limiting."""
    global GSB_LAST_CALL

    # Check cache first
    with GSB_CACHE_LOCK:
        if url in GSB_CACHE:
            cache_entry = GSB_CACHE[url]
            if time.time() - cache_entry['timestamp'] < GSB_CACHE_TTL:
                return cache_entry['result']

    # Rate limiting
    current_time = time.time()
    time_since_last = current_time - GSB_LAST_CALL
    if time_since_last < GSB_MIN_INTERVAL:
        time.sleep(GSB_MIN_INTERVAL - time_since_last)

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

        response = requests.post(GSB_ENDPOINT, json=payload, timeout=5)
        GSB_LAST_CALL = time.time()

        if response.status_code == 200:
            data = response.json()

            if "matches" in data and len(data["matches"]) > 0:
                result = {"status": "MALICIOUS", "details": data["matches"]}
            else:
                result = {"status": "SAFE", "details": "Not found in GSB database"}

            # Cache result
            with GSB_CACHE_LOCK:
                GSB_CACHE[url] = {'result': result, 'timestamp': time.time()}

            return result
        else:
            return {"status": "UNKNOWN", "details": f"GSB API error: {response.status_code}"}

    except Exception as e:
        return {"status": "UNKNOWN", "details": str(e)}

# ==========================================
# WEIGHTED SCORING SYSTEM
# ==========================================
def calculate_risk_score(url, gsb_result, ml_result, features):
    """
    Calculate risk score (0-100) and generate reasons.

    Returns: (risk_score, reasons_list)
    """
    risk_score = 0
    reasons = []

    # GSB is authoritative - if malicious, override
    if gsb_result.get('status') == 'MALICIOUS':
        return 100, ["Flagged as malicious by Google Safe Browsing"]

    # ML prediction weight (30 points max)
    if ml_result.get('verdict') == 'Phishing':
        ml_confidence = ml_result.get('confidence', 0.5)
        ml_score = ml_confidence * 30
        risk_score += ml_score
        reasons.append(f"ML model detected phishing pattern (confidence: {ml_confidence:.2f})")

    # Feature-based scoring
    parsed = urlparse(url)
    domain = parsed.netloc

    # URL length (5 points)
    if len(url) > 75:
        risk_score += 5
        reasons.append("Unusually long URL")

    # Entropy (5 points)
    if features[14] > 4.5:  # High entropy
        risk_score += 5
        reasons.append("High URL entropy (random-looking)")

    # IP address instead of domain (10 points)
    if features[15] == 1:
        risk_score += 10
        reasons.append("Uses IP address instead of domain name")

    # Suspicious keywords (10 points)
    if features[17] > 0:
        risk_score += min(10, features[17] * 3)
        reasons.append(f"Contains {features[17]} suspicious keyword(s)")

    # Domain age (10 points)
    if 0 < features[18] < 30:  # Newly registered (< 30 days)
        risk_score += 10
        reasons.append("Newly registered domain (less than 30 days old)")
    elif 30 <= features[18] < 180:  # Young domain (< 6 months)
        risk_score += 5
        reasons.append("Young domain (less than 6 months old)")

    # SSL issues (10 points)
    if features[19] == 0:  # Invalid SSL
        risk_score += 10
        reasons.append("Invalid, expired, or self-signed SSL certificate")
    elif features[19] == -1 and parsed.scheme == 'https':  # SSL unavailable
        risk_score += 5
        reasons.append("SSL certificate unavailable")

    # HTTP instead of HTTPS (5 points)
    if features[8] == 0:
        risk_score += 5
        reasons.append("Not using HTTPS")

    # Login forms (5 points)
    if features[20] == 1:
        risk_score += 5
        reasons.append("Contains login/password form")

    # External forms (10 points)
    if features[21] == 1:
        risk_score += 10
        reasons.append("Form submits to external domain")

    # Excessive iframes (5 points)
    if features[22] > 3:
        risk_score += 5
        reasons.append(f"Contains {features[22]} iframes")

    # URL shortener (5 points)
    if features[26] == 1:
        risk_score += 5
        reasons.append("Uses URL shortening service")

    # @ symbol (5 points)
    if features[2] == 1:
        risk_score += 5
        reasons.append("Contains @ symbol in URL")

    # Excessive subdomains (5 points)
    if features[9] > 3:
        risk_score += 5
        reasons.append(f"Excessive subdomain depth ({features[9]} levels)")

    # Non-standard port (3 points)
    if features[25] == 1:
        risk_score += 3
        reasons.append("Uses non-standard port number")

    # Cap at 100
    risk_score = min(100, risk_score)

    # If no reasons, it's safe
    if not reasons:
        reasons.append("No suspicious indicators detected")

    return int(risk_score), reasons

# ==========================================
# ENHANCED ANALYZE URL
# ==========================================
def analyze_url(url, source="Manual", session_id=None):
    """Analyze a URL for phishing threats with enhanced detection."""

    # Normalize URL
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    # GSB Check
    gsb_result = check_gsb(url)

    # ML Check
    ml_result = ml_phishing_check(url)

    features = ml_result.get('features', extract_phishing_features(url))
    parsed = urlparse(url)
    domain = (parsed.netloc or '').split(':')[0]
    domain_without_www = domain.replace('www.', '')
    subdomains = domain_without_www.split('.')[:-2] if len(domain_without_www.split('.')) > 2 else []
    tld = domain_without_www.split('.')[-1].lower() if '.' in domain_without_www else ''
    domain_age_days = int(features[18]) if len(features) > 18 else 0
    is_ip = bool(features[15]) if len(features) > 15 else is_ip_address(domain_without_www)

    url_feature_context = {
        'is_ip': is_ip,
        'subdomains': subdomains,
        'tld': tld,
        'domain_age_days': domain_age_days
    }

    gsb_label = "phishing" if gsb_result.get('status') == 'MALICIOUS' else "safe"
    ml_confidence = float(ml_result.get('confidence', 0.5) or 0.5)
    ml_score = ml_confidence if str(ml_result.get('verdict', '')).lower() == 'phishing' else ml_confidence * 0.5

    decision, risk_score, detection_method = make_final_decision(
        gsb_label,
        ml_score,
        ml_confidence,
        url_feature_context
    )

    if decision == 'phishing':
        final_verdict = "MALICIOUS"
        confidence = max(ml_confidence, min(1.0, float(risk_score) / 100.0))
    elif decision == 'warning':
        final_verdict = "SUSPICIOUS"
        confidence = min(1.0, float(risk_score) / 100.0)
    else:
        final_verdict = "SAFE"
        confidence = 1.0 - min(1.0, float(risk_score) / 100.0)

    reasons = [
        f"Detection method: {detection_method}",
        f"GSB status: {gsb_result.get('status', 'UNKNOWN')}",
        f"ML verdict: {ml_result.get('verdict', 'Unknown')} ({ml_confidence:.2f})"
    ]

    # Persist scan and push notification
    try:
        scan_record = {
            'url': url,
            'gsb_status': gsb_result.get('status'),
            'ml_verdict': ml_result.get('verdict'),
            'ml_confidence': ml_result.get('confidence'),
            'final_verdict': final_verdict,
            'risk_score': risk_score,
            'detection_method': detection_method,
            'reasons': reasons,
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
        "detection_method": detection_method,
        "result": decision,
        "confidence": confidence,
        "risk_score": int(risk_score),
        "reasons": reasons,
        "timestamp": datetime.now().isoformat(),
        "session_id": session_id
    }

# ==========================================
# CHROME MONITORING (UNCHANGED)
# ==========================================
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

                            print(f"[{name}] {ts} → {url} - {result['final_verdict']} (Score: {result['risk_score']})")

                time.sleep(POLL_INTERVAL)

            except Exception as e:
                print(f"Monitor error: {e}")
                time.sleep(5)

    thread = threading.Thread(target=monitor_loop, daemon=True)
    thread.start()
    return thread

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
        return 0

def get_new_chrome_entries(history_path, baseline_time):
    """Get new Chrome history entries after baseline time."""
    try:
        copy_chrome_db(history_path)
        conn = sqlite3.connect(TEMP_DB)
        cur = conn.cursor()

        cur.execute("""
            SELECT url, last_visit_time 
            FROM urls 
            WHERE last_visit_time > ?
            ORDER BY last_visit_time ASC
        """, (baseline_time,))

        rows = cur.fetchall()
        conn.close()

        try:
            os.remove(TEMP_DB)
        except:
            pass

        return rows
    except Exception as e:
        print(f"Error getting new Chrome entries: {e}")
        return []


def _is_monitor_thread_alive():
    """Check whether the background browser monitor thread is active."""
    thread = monitor_state.get("thread")
    return bool(thread and thread.is_alive())


def toggle_monitor(enable):
    """Enable or disable continuous browser monitoring."""
    with MONITOR_LOCK:
        if enable:
            # Avoid spinning duplicate monitor threads.
            if monitor_state.get("is_active") and _is_monitor_thread_alive():
                return

            monitor_state["is_active"] = True
            monitor_state["session_start_time"] = datetime.now().isoformat()
            monitor_state["seen_urls"] = set()
            monitor_state["monitored_urls"] = []

            thread = start_browser_monitoring()
            # Keep a reference to latest thread for status checks.
            monitor_state["thread"] = thread
            return

        monitor_state["is_active"] = False
        monitor_state["session_start_time"] = None
        monitor_state["thread"] = None


def start_monitoring():
    """Start Chrome history monitoring and return status payload."""
    toggle_monitor(True)
    status = get_monitor_status()
    return {
        "status": "success",
        "message": "Browser monitoring started",
        "monitor_status": status
    }


def stop_monitoring():
    """Stop Chrome history monitoring and return status payload."""
    toggle_monitor(False)
    status = get_monitor_status()
    return {
        "status": "success",
        "message": "Browser monitoring stopped",
        "monitor_status": status
    }


def get_monitored_urls():
    """Return monitored browser URLs with analysis results."""
    with MONITOR_LOCK:
        return list(monitor_state.get("monitored_urls", []))


def get_monitor_status():
    """Return current monitor status for API/UI polling."""
    with MONITOR_LOCK:
        urls = monitor_state.get("monitored_urls", [])
        return {
            "is_active": bool(monitor_state.get("is_active", False) and _is_monitor_thread_alive()),
            "session_start_time": monitor_state.get("session_start_time"),
            "url_count": len(urls)
        }

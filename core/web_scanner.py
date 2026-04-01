# core/web_scanner.py

import socket
import ssl
import re
import threading
from collections import deque
from datetime import datetime
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

from core import notifications
from core.database import db


DEFAULT_TIMEOUT = 5
MAX_PAGES = 6
MAX_CRAWL_DEPTH = 1
MAX_TOTAL_REQUESTS = 18

SAFE_HEADERS = {
    'User-Agent': 'CyberSleuthScanner/1.0 (+safe passive-active security testing)',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
}

COMMON_ENDPOINTS = [
    'admin',
    'login',
    'dashboard',
    'backup',
    '.git',
    '.env',
    'api',
    'test',
    'staging',
    'phpinfo.php',
]

SQL_ERROR_PATTERNS = [
    r"sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"odbc sql server driver",
    r"postgresql.*error",
    r"sqlite.*error",
    r"you have an error in your sql syntax",
]

SQLI_PROBE_VALUE = "' OR '1'='1"
XSS_PROBE_MARKER = "CYBERSLEUTH_XSS_PROBE"

def scan_website(url):
    """Comprehensive web vulnerability scanner."""
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = urlparse(url)
    hostname = parsed.netloc.split(':')[0]
    port = 443 if parsed.scheme == 'https' else 80
    
    findings = []
    
    # 1. Port Scan
    port_findings = scan_porta(hostname, [80, 443, 22, 21, 25, 3306, 5432])
    findings.extend(port_findings)
    
    # 2. SSL Certificate Analysis
    if parsed.scheme == 'https':
        ssl_findings = check_ssl_certificate(hostname, port)
        findings.extend(ssl_findings)
    
    # 3. HTTP Headers Analysis
    header_findings = analyze_headers(url)
    findings.extend(header_findings)
    
    # 4. Service Detection
    service_findings = detect_services(hostname)
    findings.extend(service_findings)

    # 5. Controlled crawl + DOM extraction
    discovered_pages, dom_findings = crawl_and_extract(url)
    findings.extend(dom_findings)

    # 6. Safe active testing modules (non-destructive)
    active_findings = []
    active_findings.extend(test_sql_injection(discovered_pages))
    active_findings.extend(test_reflected_xss(discovered_pages))
    active_findings.extend(basic_directory_bruteforce(url))
    findings.extend(active_findings)

    findings = deduplicate_findings(findings)
    
    # Determine severity
    severity_map = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
    max_severity = min([severity_map.get(f.get('severity', 'Info'), 4) for f in findings] + [4])
    severity_levels = {0: 'Critical', 1: 'High', 2: 'Medium', 3: 'Low', 4: 'Info'}
    overall_severity = severity_levels[max_severity]
    
    return {
        "url": url,
        "timestamp": datetime.now().isoformat(),
        "overall_severity": overall_severity,
        "findings_count": len(findings),
        "findings": findings,
        "has_vulnerabilities": len(findings) > 0
    }


def start_vulnerability_scan(session_id, url):
    """Start a vulnerability scan asynchronously; returns scan_id and pending status."""
    try:
        # create DB entry with pending status
        scan_data = {
            'target_url': url,
            'scan_type': 'full',
            'status': 'pending',
            'results': None
        }
        scan_id = db.save_vulnerability_scan(session_id, scan_data)

        def run_scan():
            try:
                results = scan_website(url)
                results_record = {
                    'scan_id': scan_id,
                    'target_url': url,
                    'status': 'completed',
                    'timestamp': datetime.now().isoformat(),
                    **results
                }
                db.update_vulnerability_scan(scan_id, status='completed', results=results_record)
                notifications.push_vulnerability(results_record)
            except Exception as e:
                db.update_vulnerability_scan(scan_id, status='failed', results={'error': str(e)})
                notifications.push_vulnerability({'scan_id': scan_id, 'status': 'failed', 'error': str(e)})

        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()
        return {'scan_id': scan_id, 'status': 'pending', 'session_id': session_id}
    except Exception as e:
        return {'error': str(e)}

def scan_porta(hostname, ports):
    """Scan common ports for service availability."""
    findings = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((hostname, port))
            if result == 0:
                findings.append({
                    "type": "Open Port",
                    "severity": "Medium",
                    "port": port,
                    "service": get_service_name(port),
                    "description": f"Port {port} is open",
                    "solution": "Close non-essential ports at firewall/security-group level and restrict access by source IP."
                })
            sock.close()
        except:
            pass
    return findings

def check_ssl_certificate(hostname, port):
    """Check SSL certificate security."""
    findings = []
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Check expiry
                if cert:
                    findings.append({
                        "type": "SSL Certificate",
                        "severity": "Low",
                        "description": "SSL certificate found",
                        "issuer": cert.get('issuer', 'Unknown'),
                        "solution": "Keep TLS certificate valid and renewed automatically; enforce modern TLS settings."
                    })
    except:
        findings.append({
            "type": "SSL Certificate",
            "severity": "High",
            "description": "SSL certificate validation failed",
            "solution": "Install a valid CA-signed certificate and fix chain or hostname mismatches."
        })
    return findings

def analyze_headers(url):
    """Analyze HTTP security headers."""
    findings = []
    try:
        response = requests.head(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True, headers=SAFE_HEADERS)
        headers = response.headers
        
        security_headers = [
            'Strict-Transport-Security',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Content-Security-Policy',
            'X-XSS-Protection'
        ]
        
        for header in security_headers:
            if header not in headers:
                findings.append({
                    "type": "Missing Security Header",
                    "severity": "Medium",
                    "header": header,
                    "description": f"Missing {header} header",
                    "solution": f"Configure web server/app to include the {header} header with secure values."
                })
        
        # Check server disclosure
        if 'Server' in headers:
            findings.append({
                "type": "Server Information Disclosure",
                "severity": "Low",
                "server": headers['Server'],
                "description": "Server version is disclosed",
                "solution": "Suppress verbose Server/X-Powered-By headers in production to reduce fingerprinting risk."
            })
    except:
        pass
    return findings

def detect_services(hostname):
    """Detect common services and technologies."""
    findings = []
    try:
        # Check for common services
        services = [
            (22, "SSH"),
            (80, "HTTP"),
            (443, "HTTPS"),
            (3306, "MySQL"),
            (5432, "PostgreSQL")
        ]
        
        for port, service in services:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                if sock.connect_ex((hostname, port)) == 0:
                    findings.append({
                        "type": "Service Detection",
                        "severity": "Info",
                        "service": service,
                        "port": port,
                        "description": f"{service} service detected on port {port}",
                        "solution": "Confirm service exposure is intended and restrict management services to trusted networks."
                    })
                sock.close()
            except:
                pass
    except:
        pass
    return findings


def _safe_get(session, target_url):
    return session.get(target_url, timeout=DEFAULT_TIMEOUT, headers=SAFE_HEADERS, allow_redirects=True)


def _normalize_base_url(target_url):
    parsed = urlparse(target_url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or '/', '', '', ''))


def _is_internal_link(base_netloc, candidate_url):
    parsed = urlparse(candidate_url)
    return (not parsed.netloc) or (parsed.netloc == base_netloc)


def crawl_and_extract(start_url):
    """Crawl a limited number of internal pages and extract forms, scripts, and links."""
    findings = []
    pages = []
    visited = set()

    queue = deque([(_normalize_base_url(start_url), 0)])
    root_netloc = urlparse(start_url).netloc
    request_count = 0

    with requests.Session() as session:
        while queue and len(visited) < MAX_PAGES and request_count < MAX_TOTAL_REQUESTS:
            current_url, depth = queue.popleft()
            if current_url in visited:
                continue

            visited.add(current_url)
            try:
                response = _safe_get(session, current_url)
                request_count += 1
            except requests.RequestException:
                continue

            content_type = (response.headers.get('Content-Type') or '').lower()
            if 'text/html' not in content_type:
                continue

            page_data, page_findings, links = extract_dom_security_data(current_url, response.text)
            pages.append(page_data)
            findings.extend(page_findings)

            if depth < MAX_CRAWL_DEPTH:
                for link in links:
                    absolute = urljoin(current_url, link)
                    normalized = _normalize_base_url(absolute)
                    if _is_internal_link(root_netloc, normalized) and normalized not in visited:
                        queue.append((normalized, depth + 1))

    return pages, findings


def extract_dom_security_data(page_url, html):
    """Extract forms, inputs, scripts and internal links from page DOM."""
    soup = BeautifulSoup(html, 'html.parser')

    forms = []
    links = []
    scripts = soup.find_all('script')
    script_src_count = sum(1 for script in scripts if script.get('src'))
    inline_script_count = len(scripts) - script_src_count

    for form in soup.find_all('form'):
        action = form.get('action') or page_url
        method = (form.get('method') or 'GET').upper()
        inputs = []
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            inputs.append({
                'name': input_tag.get('name') or '',
                'type': input_tag.get('type') or input_tag.name
            })
        forms.append({'action': urljoin(page_url, action), 'method': method, 'inputs': inputs})

    for anchor in soup.find_all('a', href=True):
        href = anchor.get('href')
        if href and not href.startswith(('javascript:', 'mailto:', '#')):
            links.append(href)

    findings = []

    if inline_script_count > 0 and len(scripts) > 4:
        findings.append({
            'type': 'DOM Surface Exposure',
            'severity': 'Low',
            'description': f'Page {page_url} contains {inline_script_count} inline scripts across {len(scripts)} script tags.',
            'affected_component': page_url,
            'solution': 'Move inline scripts to external files and enforce a strict Content-Security-Policy with nonces/hashes.'
        })

    for form in forms:
        if form['method'] == 'GET' and any(inp.get('type') == 'password' for inp in form['inputs']):
            findings.append({
                'type': 'Insecure Form Method',
                'severity': 'Medium',
                'description': f"Form submitting to {form['action']} uses GET with sensitive fields.",
                'affected_component': form['action'],
                'solution': 'Use POST for sensitive forms and ensure TLS is enforced for the full form submission path.'
            })

    page_data = {
        'url': page_url,
        'forms': forms,
        'links': links,
        'scripts': {
            'total': len(scripts),
            'external': script_src_count,
            'inline': inline_script_count,
        }
    }
    return page_data, findings, links


def test_sql_injection(discovered_pages):
    """Safe SQLi checks using harmless probes and error-pattern detection."""
    findings = []
    regexes = [re.compile(pattern, re.IGNORECASE) for pattern in SQL_ERROR_PATTERNS]

    with requests.Session() as session:
        requests_used = 0
        for page in discovered_pages:
            if requests_used >= MAX_TOTAL_REQUESTS:
                break

            # Query parameter probing
            parsed = urlparse(page['url'])
            params = parse_qs(parsed.query)
            if params:
                injected_params = {k: SQLI_PROBE_VALUE for k in params.keys()}
                probe_query = urlencode(injected_params, doseq=True)
                probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, probe_query, parsed.fragment))
                try:
                    response = _safe_get(session, probe_url)
                    requests_used += 1
                    body = response.text[:5000]
                    if any(rx.search(body) for rx in regexes):
                        findings.append({
                            'type': 'Potential SQL Injection',
                            'severity': 'High',
                            'description': f'SQL error pattern observed after safe query probe on {page["url"]}.',
                            'affected_component': page['url'],
                            'solution': 'Use parameterized queries, strict input validation, and centralized database error handling.'
                        })
                except requests.RequestException:
                    continue

            # GET form probing (safe, read-only)
            for form in page.get('forms', []):
                if requests_used >= MAX_TOTAL_REQUESTS:
                    break
                if form.get('method') != 'GET':
                    continue

                input_names = [inp.get('name') for inp in form.get('inputs', []) if inp.get('name')]
                if not input_names:
                    continue

                probe_params = {name: SQLI_PROBE_VALUE for name in input_names[:3]}
                action = form.get('action') or page['url']
                join_char = '&' if ('?' in action) else '?'
                probe_url = f"{action}{join_char}{urlencode(probe_params)}"

                try:
                    response = _safe_get(session, probe_url)
                    requests_used += 1
                    body = response.text[:5000]
                    if any(rx.search(body) for rx in regexes):
                        findings.append({
                            'type': 'Potential SQL Injection',
                            'severity': 'High',
                            'description': f'SQL error pattern observed after safe form probe on {action}.',
                            'affected_component': action,
                            'solution': 'Validate and normalize user input server-side and use parameterized SQL queries for all database access.'
                        })
                except requests.RequestException:
                    continue

    return findings


def test_reflected_xss(discovered_pages):
    """Safe reflected XSS checks using unique marker reflection detection."""
    findings = []

    with requests.Session() as session:
        requests_used = 0
        for page in discovered_pages:
            if requests_used >= MAX_TOTAL_REQUESTS:
                break

            parsed = urlparse(page['url'])
            params = parse_qs(parsed.query)
            if params:
                probe_params = {k: XSS_PROBE_MARKER for k in params.keys()}
                probe_query = urlencode(probe_params, doseq=True)
                probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, probe_query, parsed.fragment))
                try:
                    response = _safe_get(session, probe_url)
                    requests_used += 1
                    if XSS_PROBE_MARKER in response.text:
                        findings.append({
                            'type': 'Potential Reflected XSS',
                            'severity': 'Medium',
                            'description': f'Unsanitized reflection marker detected in response for {page["url"]}.',
                            'affected_component': page['url'],
                            'solution': 'Apply output encoding per context (HTML/attribute/JS), validate inputs, and enforce CSP.'
                        })
                except requests.RequestException:
                    continue

            for form in page.get('forms', []):
                if requests_used >= MAX_TOTAL_REQUESTS:
                    break
                if form.get('method') != 'GET':
                    continue
                input_names = [inp.get('name') for inp in form.get('inputs', []) if inp.get('name')]
                if not input_names:
                    continue

                probe_params = {name: XSS_PROBE_MARKER for name in input_names[:3]}
                action = form.get('action') or page['url']
                join_char = '&' if ('?' in action) else '?'
                probe_url = f"{action}{join_char}{urlencode(probe_params)}"

                try:
                    response = _safe_get(session, probe_url)
                    requests_used += 1
                    if XSS_PROBE_MARKER in response.text:
                        findings.append({
                            'type': 'Potential Reflected XSS',
                            'severity': 'Medium',
                            'description': f'Input reflection marker detected for form endpoint {action}.',
                            'affected_component': action,
                            'solution': 'Escape reflected user input in templates and add contextual encoding libraries at render points.'
                        })
                except requests.RequestException:
                    continue

    return findings


def basic_directory_bruteforce(base_url):
    """Safe endpoint discovery using a minimal common path list."""
    findings = []
    root = _normalize_base_url(base_url).rstrip('/')

    with requests.Session() as session:
        checked = 0
        for endpoint in COMMON_ENDPOINTS:
            if checked >= 8:
                break
            checked += 1
            probe_url = f"{root}/{endpoint}"
            try:
                response = _safe_get(session, probe_url)
            except requests.RequestException:
                continue

            if response.status_code in (200, 401, 403):
                severity = 'Medium' if endpoint in ('.git', '.env', 'backup', 'staging', 'phpinfo.php') else 'Low'
                findings.append({
                    'type': 'Exposed Endpoint',
                    'severity': severity,
                    'description': f'Potentially sensitive endpoint exposed: {probe_url} (HTTP {response.status_code}).',
                    'affected_component': probe_url,
                    'solution': 'Restrict access to sensitive paths, remove unused files, and return 404 for private resources.'
                })

    return findings


def deduplicate_findings(findings):
    """Remove duplicate findings while preserving order."""
    cleaned = []
    seen = set()

    for finding in findings:
        normalized = {
            'type': finding.get('type', 'Finding'),
            'severity': finding.get('severity', 'Info'),
            'description': finding.get('description', ''),
            'solution': finding.get('solution') or 'Review this finding and apply security hardening best practices.',
        }
        for key in ('port', 'service', 'header', 'server', 'issuer', 'affected_component'):
            if key in finding:
                normalized[key] = finding.get(key)

        key = (
            normalized.get('type'),
            normalized.get('severity'),
            normalized.get('description'),
            normalized.get('affected_component'),
            normalized.get('port'),
        )
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(normalized)

    return cleaned

def get_service_name(port):
    """Map port to service name."""
    services = {
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        465: "SMTPS",
        587: "SMTP",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        5432: "PostgreSQL",
        5984: "CouchDB",
        6379: "Redis",
        27017: "MongoDB"
    }
    return services.get(port, f"Service-{port}")
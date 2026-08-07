import importlib
import time

try:
    _apscheduler_bg = importlib.import_module('apscheduler.schedulers.background')
    BackgroundScheduler = getattr(_apscheduler_bg, 'BackgroundScheduler', None)
except Exception:
    BackgroundScheduler = None

scheduler = BackgroundScheduler() if BackgroundScheduler else None
if scheduler:
    scheduler.start()

def scheduled_target_scan(target_url):
    """Run a scheduled vulnerability scan on a specific user-defined URL."""
    try:
        from core.web_scanner import start_vulnerability_scan
        print(f"[*] Executing scheduled vulnerability scan for: {target_url}")
        # Use session_id 0 to represent a system-scheduled background task
        start_vulnerability_scan(0, target_url)
    except Exception as e:
        print(f"Scheduled target scan error for {target_url}: {e}")

def scheduled_vuln_scan():
    """Run vulnerability scans on suspicious phishing links (Global Auto-Scan)."""
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
                db.save_vulnerability_scan(session_id=0, scan_data=scan_record)
            except Exception as inner_error:
                print(f"Scheduled auto-scan failed for {link.get('url')}: {inner_error}")
    except Exception as e:
        print(f"Scheduled vulnerability scan error: {e}")


def remove_scheduled_scan(job_id):
    """Remove a scheduled vulnerability scan."""
    if scheduler:
        try:
            scheduler.remove_job(job_id)
            print(f"[*] Successfully removed scheduled job: {job_id}")
            return True
        except Exception as e:
            print(f"[!] Failed to remove job {job_id} (It may have already executed/expired): {e}")
    return False
import os
import sqlite3
import shutil
import time
from datetime import datetime, timedelta
import pytz

# ===== CONFIG =====
POLL_INTERVAL = 2  # seconds
TIMEZONE = pytz.timezone("Asia/Kolkata")

CHROME_USER_DATA = os.path.expanduser(
    r"~\AppData\Local\Google\Chrome\User Data"
)

TEMP_DB = "history_tmp.db"
# ==================

def chrome_time_to_datetime(chrome_time):
    if chrome_time == 0:
        return None
    epoch = datetime(1601, 1, 1)
    return TIMEZONE.localize(epoch + timedelta(microseconds=chrome_time))

def get_profiles():
    profiles = []
    for name in os.listdir(CHROME_USER_DATA):
        if name == "Default" or name.startswith("Profile"):
            history_path = os.path.join(CHROME_USER_DATA, name, "History")
            if os.path.exists(history_path):
                profiles.append((name, history_path))
    return profiles

def copy_db(src):
    shutil.copy2(src, TEMP_DB)

def get_latest_timestamp(history_path):
    copy_db(history_path)
    conn = sqlite3.connect(TEMP_DB)
    cur = conn.cursor()

    cur.execute("""
        SELECT MAX(last_visit_time) FROM urls
    """)

    result = cur.fetchone()[0]
    conn.close()
    os.remove(TEMP_DB)
    return result or 0

def get_new_entries(history_path, since_time):
    copy_db(history_path)
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

def monitor_all_profiles():
    profiles = get_profiles()

    # Establish baseline (ignore all previous history)
    baselines = {}
    for name, path in profiles:
        baselines[name] = get_latest_timestamp(path)

    print("Monitoring Chrome URLs from now on (all profiles)...\n")

    while True:
        try:
            for name, path in profiles:
                new_rows = get_new_entries(path, baselines[name])

                for url, visit_time in new_rows:
                    baselines[name] = max(baselines[name], visit_time)
                    ts = chrome_time_to_datetime(visit_time)
                    print(f"[{name}] {ts} → {url}")

            time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:
            print("\nStopped.")
            break

        except Exception as e:
            print("Error:", e)
            time.sleep(5)

if __name__ == "__main__":
    monitor_all_profiles()

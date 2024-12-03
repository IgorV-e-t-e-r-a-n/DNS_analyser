#Parse DNS logs or query public DNS logs.
#Compare domain queries against known bad lists (e.g., OpenPhish).
#Store flagged queries in a SQLite database.
#Generate a report of suspicious domains.
#Optionally support real-time monitoring.


import sqlite3
import requests 
import time 
from threading import Thread


#===== Setup =====
#Database initialization
def init_database():
    conn = sqlite3.connect('dns_monitor.db') #free dns db
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS flagged_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            flagged_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    conn.commit()
    conn.close()
    
    
# Fetch known bad domains from OpenPhish
def fetch_known_bad_domains():
    try:
        response = requests.get("https://openphish.com/feed.txt", timeout=10)
        if response.status_code == 200: #UDP code for succesful result 
            return set(response.text.splitlines())
    except requests.RequestException as e:
        print(f"Error fetching bad domains: {e}")
    return set()

# ===== Log Parsing =====
#Mock DNS log data
def mock_dns_logs():
    return [
        "google.com",
        "malicious-site.com",
        "safe-site.org",
        "phishing-login.com",
        "banksecure.com"
    ] #the most popular websites
    
#Parse logs and flag suspicious domains
def monitor_dns_logs(bad_domains):
    conn = sqlite3.connect('dns_monitor.db')
    cursor = conn.cursor()
    
    dns_logs = mock_dns_logs()  #replace with actual log parsing
    print(f"Checking DNS logs...")
    for domain in dns_logs:
        if domain in bad_domains:
            print(f"Flagged suspicious domain: {domain}")
            cursor.execute("INSERT INTO flagged_domains (domain) VALUES (?)", (domain,))
            conn.commit()

    conn.close()


#===== Reporting =====
#Generate a report from flagged domains
def generate_report():
    conn = sqlite3.connect('dns_monitor.db')
    cursor = conn.cursor()

    cursor.execute("SELECT domain, flagged_time FROM flagged_domains;")
    flagged = cursor.fetchall()

    print("\nSuspicious Domains Report:")
    print("-" * 30)
    for domain, timestamp in flagged:
        print(f"Domain: {domain} | Flagged Time: {timestamp}")
    conn.close()

# ===== Real-Time Monitoring (Optional) =====
def real_time_monitor(bad_domains, interval=10):
    while True:
        monitor_dns_logs(bad_domains)
        time.sleep(interval)

# ===== Main Program =====
if __name__ == "__main__":
    print("Initializing DNS Monitoring Tool...")
    init_database()

    print("Fetching known bad domains...")
    bad_domains = fetch_known_bad_domains()
    print(f"Loaded {len(bad_domains)} bad domains.")

    # Real-time monitoring using threading
    monitor_thread = Thread(target=real_time_monitor, args=(bad_domains,))
    monitor_thread.daemon = True
    monitor_thread.start()

    # Run manual checks and report generation
    while True:
        print("\nOptions:\n1. Check DNS Logs\n2. Generate Report\n3. Exit")
        choice = input("Enter your choice: ").strip()
        if choice == "1":
            monitor_dns_logs(bad_domains)
        elif choice == "2":
            generate_report()
        elif choice == "3":
            print("Exiting DNS Monitoring Tool.")
            break
        else:
            print("Invalid choice. Please try again.")
import sqlite3
import requests
from scapy.all import sniff, DNS, IP
from threading import Thread

# Function to fetch DNS logs from a public URL (e.g., OpenPhish)
def fetch_dns_log_from_url(url):
    try:
        print(f"Fetching DNS logs from {url}...")
        response = requests.get(url)
        if response.status_code == 200:
            return response.text.splitlines()  # Return lines of DNS logs
        else:
            print(f"Failed to fetch DNS log from {url}, Status code: {response.status_code}")
            return []
    except Exception as e:
        print(f"Error fetching DNS log from {url}: {e}")
        return []

# Function to fetch DNS logs from multiple URLs concurrently (using threads)
def fetch_dns_logs_concurrently(urls):
    logs = []
    def fetch_and_append(url):
        logs.extend(fetch_dns_log_from_url(url))
    
    threads = []
    for url in urls:
        thread = Thread(target=fetch_and_append, args=(url,))
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()
        
    return logs

# Коллекция логов DNS-сервера
def dns_packet_callback(packet):
    if packet.haslayer(DNS) and packet.haslayer(IP):
        dns_query = packet[DNS].qd.qname.decode()  # Получаем домен из запроса
        print(f"DNS Query: {dns_query}")
        check_and_store_flagged_domain(dns_query)

# Функция для проверки доменов и сохранения в базе данных
def check_and_store_flagged_domain(domain):
    # Пример списка подозрительных доменов (можно взять из открытых источников)
    suspicious_keywords = ["login", "secure", "bank"]
    
    # Фильтрация доменов по ключевым словам
    if any(kw in domain for kw in suspicious_keywords):
        print(f"Flagged Domain: {domain}")
        store_flagged_domain(domain)

# Сохранение подозрительных доменов в базе данных
def store_flagged_domain(domain):
    conn = sqlite3.connect('flagged_domains.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS flagged_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            flagged_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('INSERT INTO flagged_domains (domain) VALUES (?)', (domain,))
    conn.commit()
    conn.close()

# Функция для автоматического мониторинга DNS-запросов с конкретных URL
def monitor_dns_from_urls(urls):
    print("Starting to fetch DNS logs from URLs...")
    logs = fetch_dns_logs_concurrently(urls)
    
    # Process the fetched logs (just as an example, assume these logs have domains)
    for log in logs:
        print(f"Processing log: {log}")
        check_and_store_flagged_domain(log)

# Сниффинг DNS-запросов в реальном времени (порт 53)
def start_dns_sniffer():
    print("Starting DNS sniffing...")
    sniff(filter="udp port 53", prn=dns_packet_callback, store=0)

# Основная функция
def main():
    # URLs для получения логов (например, OpenPhish)
    dns_log_urls = [
        "https://openphish.com/feed.txt"  # Real OpenPhish feed URL
    ]
    
    # Запустим мониторинг DNS-запросов с этих URL
    monitor_dns_from_urls(dns_log_urls)
    
    # Запустим сниффер для мониторинга реальных DNS-запросов
    start_dns_sniffer()

if __name__ == "__main__":
    main()

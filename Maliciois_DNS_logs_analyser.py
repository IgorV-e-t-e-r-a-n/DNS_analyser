#Parse DNS logs or query public DNS logs.
#Compare domain queries against known bad lists (e.g., OpenPhish).
#Store flagged queries in a SQLite database.
#Generate a report of suspicious domains.
#Optionally support real-time monitoring.


import sqlite3
import requests 
import time 
from threading import Thread


import requests
import sqlite3
from scapy.all import sniff, DNS, IP

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

# Сниффинг DNS-запросов (порт 53)
def start_dns_sniffer():
    print("Starting DNS sniffing...")
    sniff(filter="udp port 53", prn=dns_packet_callback, store=0)

# Основная функция
def main():
    # Пример, как можно начать сбор логов
    start_dns_sniffer()

if __name__ == "__main__":
    main()

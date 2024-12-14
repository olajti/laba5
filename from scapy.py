from scapy.all import *
import time

# Змінна для збереження інформації про джерела
ip_counter = {}

# Функція для обробки пакетів
def packet_callback(packet):
    global ip_counter
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        if ip_src in ip_counter:
            ip_counter[ip_src] += 1
        else:
            ip_counter[ip_src] = 1

        # Якщо кількість пакетів з одного джерела перевищує ліміт, сповіщаємо
        if ip_counter[ip_src] > 100:
            print(f"Підозріле сканування портів від {ip_src}")
            # Можна додати сповіщення, наприклад через email або SMS
            # Для цього треба інтегрувати з іншими бібліотеками для сповіщень

# Налаштовуємо перехоплення пакету на заданому інтерфейсі
def start_sniffing(interface="eth0"):
    print(f"Запуск перехоплення на інтерфейсі {interface}...")
    sniff(iface=interface, prn=packet_callback, store=0)

# Запуск програми
if __name__ == "__main__":
    start_sniffing("eth0")  # Замініть на ваш інтерфейс


#частина 2
import subprocess

# Функція для налаштування брандмауера
def configure_firewall():
    try:
        # Приклад заборони вхідного трафіку з певної IP-адреси
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", "192.168.1.100", "-j", "DROP"], check=True)
        
        # Приклад обмеження доступу до певного порту (наприклад, порт 80)
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "80", "-j", "DROP"], check=True)
        
        # Приклад дозволу доступу тільки з довірених IP-адрес
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", "192.168.1.1", "-j", "ACCEPT"], check=True)

        print("Брандмауер налаштовано успішно!")
    except subprocess.CalledProcessError as e:
        print(f"Помилка налаштування брандмауера: {e}")

# Викликаємо функцію налаштування
configure_firewall()


#сканування
import nmap

# Функція для сканування діапазону IP-адрес і портів
def scan_network(target="192.168.1.0/24", ports="80,443,22"):
    nm = nmap.PortScanner()
    print(f"Сканування діапазону {target} на порти {ports}...")
    nm.scan(hosts=target, arguments=f"-p {ports}")

    # Вивести інформацію про відкриті порти
    for host in nm.all_hosts():
        print(f"Хост: {host}")
        for proto in nm[host].all_protocols():
            print(f"Протокол: {proto}")
            lport = nm[host][proto].keys()
            for port in lport:
                print(f"  Порт: {port} відкритий, сервіси: {nm[host][proto][port]['name']}, версія: {nm[host][proto][port]['version']}")

# Викликаємо функцію для сканування
scan_network("192.168.1.0/24", "22,80,443")

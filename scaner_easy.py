#!/usr/bin/env python
import scapy.all as scapy
import argparse
import socket 

def get_arguments():
    # Tworzenie parsera argumentów
    parser = argparse.ArgumentParser()
    # Dodawanie argumentu -t/--target
    parser.add_argument("-t", "--target", dest="target", help="Specify target IP or IP range")
    # Parsowanie argumentów
    options = parser.parse_args()

    # Jeśli nie podano adresu IP, pytaj użytkownika o jego podanie
    if not options.target:
        options.target = input("Podaj adres IP sieci np.(192.168.0.0/24): ")

    # Zwracanie przypisanych wartości
    return options

def scan(ip):
    # Tworzenie pakietu ARP z adresem IP docelowym
    arp_packet = scapy.ARP(pdst=ip)
    # Tworzenie pakietu Ether z adresem MAC rozgłoszeniowym
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # Łączenie pakietów ARP i Ether
    arp_broadcast_packet = broadcast_packet/arp_packet
    # Wysyłanie pakietu ARP rozgłoszeniowego i oczekiwanie na odpowiedzi
    answered_list = scapy.srp(arp_broadcast_packet, timeout=3, verbose=False)[0]
    # Lista klientów
    client_list = []

    # Iterowanie przez odpowiedzi
    for element in answered_list:
        # Tworzenie słownika z adresem IP i MAC klienta
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        # Dodawanie słownika do listy klientów
        client_list.append(client_dict)

    # Zwracanie listy klientów
    return client_list

def print_result(scan_list):
    # Drukowanie nagłówka tabeli
    print("IP\t\t\tMAC\n----------------------------------------")
    # Iterowanie przez listę klientów i drukowanie adresów IP i MAC
    for client in scan_list:
        print(client["ip"] + "\t\t" + client["mac"])

# Pobieranie argumentów
options = get_arguments()
# Wykonanie skanowania
result_list = scan(options.target)
# Drukowanie wyników skanowania
print_result(result_list)

print ("Skanowanie portów")
#skanowanie portów za pomocą socket
def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            return True
        else:
            return False
    except Exception:
        return False
    
def scan_network(network):
    ip_prefix = network.split('.')[0:3]
    for i in range(1, 255):
        ip = '.'.join(ip_prefix + [str(i)])
        for port in range(1, 8080):  # Skanujemy porty od 1 do 8080
            if scan_port(ip, port):
                print(f"IP: {ip}, Port: {port} - OPEN")

network = options.target  # Pobranie adresów do skanowania z wcześniej wpisanego adresu
scan_network(network)
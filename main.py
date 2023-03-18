import socket
import scapy.all as scapy
import ipaddress
from classes import bcolors

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def main_menu():

    print(f'''{bcolors.HEADER}
     _   _      _                      _      ____                                  
    | \ | | ___| |___      _____  _ __| | __ / ___|  ___ __ _ _ __  _ __   ___ _ __ 
    |  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ / \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
    | |\  |  __/ |_ \ V  V / (_) | |  |   <   ___) | (_| (_| | | | | | | |  __/ |   
    |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\ |____/ \___\__,_|_| |_|_| |_|\___|_|{bcolors.ENDC}
    ''')


    print(f'''{bcolors.OKBLUE}
    1. Scan network/host
    2. Scan ports{bcolors.ENDC}{bcolors.FAIL}
    3. Exit{bcolors.ENDC}
    ''')

def clear_terminal():
    print('\033c')

def select_network_ip():
    ip = input('Enter the IP of a host or a network to scan: ')
    return ip

def detect_ip_type(ip):
    if '/' in ip:
        return 'network'
    else:
        return 'host'

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)
    except socket.herror:
        return 'Unknown'

def scan_ip(ip):
    request = scapy.ARP()
    request.pdst = ip
    broadcast = scapy.Ether()
    broadcast.dst = 'ff:ff:ff:ff:ff:ff'
    request_broadcast = broadcast / request
    answered_list = scapy.srp(request_broadcast, timeout=1, verbose=False)[0]
    return answered_list

def scan_ip_menu():
    ip = select_network_ip()
    ip_type = detect_ip_type(ip)
    if ip_type == 'network':
        print('Scanning network')
        answered_list = scan_ip(ip)
        print(f'{bcolors.OKGREEN}Hosts up:')
        for element in answered_list:
            print(element[1].psrc, ' - ', get_hostname(element[1].psrc)[0], ' - ', element[1].hwsrc)
        print(f'{bcolors.ENDC}')
    elif ip_type == 'host':
        print('Scanning host')
        answered_list = scan_ip(ip)
        if len(answered_list) != 0:
            print(f'{bcolors.OKGREEN}Host {ip} is up{bcolors.ENDC}')
        else:
            print(f'{bcolors.FAIL}Host {ip} is down{bcolors.ENDC}')
    else:
        print(f'{bcolors.FAIL}Invalid IP or network{bcolors.ENDC}')
        
def scan_ports_menu():
    print('Scanning ports')
    for i in range(1, 1024):
        if s.connect_ex((' ', i)) == 0:
            print('Port open: ' + str(i))

def main():
    while True:
        clear_terminal()
        main_menu()
        choice = input('Enter your choice: ')
        if choice == '1':
            scan_ip_menu()
        elif choice == '2':
            scan_ports_menu()
        elif choice == '3':
            break
        else:
            print('Invalid choice')
        input('Press enter to continue')

if __name__ == '__main__':
    main()
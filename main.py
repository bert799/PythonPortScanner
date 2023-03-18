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

def select_network_ip():
    ip = input('Enter the IP of a host or a network to scan: ')
    return ip

# detect if input is a ip with a mask or a single ip
def detect_ip_type(ip):
    if '/' in ip:
        return 'network'
    else:
        return 'host'

def scan_network():
    ip = select_network_ip()
    ip_type = detect_ip_type(ip)
    request = scapy.ARP()
    if ip_type == 'network':
        print('Scanning network')
        request = scapy.ARP()
        request.pdst = ip
        broadcast = scapy.Ether()
        broadcast.dst = 'ff:ff:ff:ff:ff:ff'
        request_broadcast = broadcast / request
        answered_list = scapy.srp(request_broadcast, timeout=1, verbose=False)[0]
        print(f'{bcolors.OKGREEN}Hosts up:{bcolors.ENDC}')
        for element in answered_list:
            print(element[1].psrc)
        print(f'{bcolors.FAIL}Hosts down:{bcolors.ENDC}')
    elif ip_type == 'host':
        print('Scanning host')
        if s.connect_ex((ip, 80)) == 0:
            print(f'{bcolors.OKGREEN}Host up: {ip}{bcolors.ENDC}')
        else:
            print(f'{bcolors.FAIL}Host down: {ip}{bcolors.ENDC}')
    else:
        print(f'{bcolors.FAIL}Invalid IP or network{bcolors.ENDC}')
        
def scan_ports():
    print('Scanning ports')
    for i in range(1, 1024):
        if s.connect_ex((' ', i)) == 0:
            print('Port open: ' + str(i))

def main():
    while True:
        main_menu()
        choice = input('Enter your choice: ')
        if choice == '1':
            scan_network()
        elif choice == '2':
            scan_ports()
        elif choice == '3':
            break
        else:
            print('Invalid choice')

if __name__ == '__main__':
    main()
import socket
import scapy.all as scapy
from classes import bcolors

well_known_ports = {
    20: 'FTP (File Transfer Protocol)',
    21: 'FTP (File Transfer Protocol)',
    22: 'SSH (Secure Shell)',
    23: 'Telnet',
    25: 'SMTP (Simple Mail Transfer Protocol)',
    53: 'DNS (Domain Name System)',
    80: 'HTTP (Hypertext Transfer Protocol)',
    110: 'POP3 (Post Office Protocol version 3)',
    119: 'NNTP (Network News Transfer Protocol)',
    123: 'NTP (Network Time Protocol)',
    143: 'IMAP (Internet Message Access Protocol)',
    161: 'SNMP (Simple Network Management Protocol)',
    194: 'IRC (Internet Relay Chat)',
    443: 'HTTPS (HTTP Secure)',
    445: 'SMB (Server Message Block)',
    465: 'SMTPS (Simple Mail Transfer Protocol Secure)',
    514: 'Syslog',
    587: 'SMTP (Mail Submission)',
    631: 'IPP (Internet Printing Protocol)',
    873: 'rsync',
    993: 'IMAPS (Internet Message Access Protocol Secure)',
    995: 'POP3S (Post Office Protocol version 3 Secure)',
    1080: 'SOCKS (SOCKetS)',
    1194: 'OpenVPN',
    1433: 'Microsoft SQL Server',
    1434: 'Microsoft SQL Server',
    1521: 'Oracle',
    1723: 'PPTP (Point-to-Point Tunneling Protocol)',
    3306: 'MySQL',
    3389: 'RDP (Remote Desktop Protocol)',
    5432: 'PostgreSQL',
    5900: 'VNC (Virtual Network Computing)',
    5901: 'VNC (Virtual Network Computing)',
    5902: 'VNC (Virtual Network Computing)',
    5903: 'VNC (Virtual Network Computing)',
    6379: 'Redis',
    8080: 'HTTP Alternate (http_alt)',
    8443: 'HTTPS Alternate (https_alt)',
    9000: 'Jenkins',
    9090: 'HTTP Alternate (http_alt)',
    9091: 'HTTP Alternate (http_alt)'
}

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
            print(element[1].psrc,' - ', element[1].hwsrc)
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
    ip = input('Enter the IP of a host to scan: ')
    port_range = input('(Optinal) Enter the port range to scan (ex: 1-100): ')
    if port_range == '':
        port_range = [1, 65535]
    elif '-' in port_range:
        port_range = port_range.split('-')
        port_range = range(int(port_range[0]), int(port_range[1]))
    else:
        port_range = [int(port_range)]
    scan_ports(ip, port_range)

def scan_ports(ip, port_range):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    print(f'{bcolors.OKBLUE}Scanning ports for {ip}{bcolors.ENDC}')
    print('Port number --- Service name --- Well-known service name')
    open_ports = 0
    closed_ports = 0
    for port in port_range:
        try:
            s.connect((ip, port))
            print(f"{bcolors.OKGREEN}{port}{bcolors.ENDC}                   {socket.getservbyport(port, 'tcp')}        {well_known_ports.get(port, 'Unknown')}")
            open_ports += 1
            s.close()
        except:
            closed_ports += 1
            pass
    print(f'{bcolors.OKBLUE}Open ports: {open_ports}{bcolors.ENDC} {bcolors.FAIL}Closed ports: {closed_ports}{bcolors.ENDC}')

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
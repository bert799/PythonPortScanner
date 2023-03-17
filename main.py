import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def main_menu():
    print('''1. Scan network/host
            2. Scan ports
            3. Exit''')


def scan_network():
    print('Scanning network')
    for i in range(1, 255):
        ip = '192.168.1.' + str(i)
        if s.connect_ex((ip, 80)) == 0:
            print('Host up: ' + ip)
        else:
            print('Host down: ' + ip)

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
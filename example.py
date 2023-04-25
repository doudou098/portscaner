import socket
import sys
import nmap
import subprocess

class PortScanner:
    def __init__(self):
        self.target_ip = ''
        self.target_ports = []
        self.open_ports = []
        self.services = {}
        self.scanner = nmap.PortScanner()

    def network_discovery(self):
        ip = input("Enter IP address to scan (e.g. 192.168.1.0): ")
        subnet = input("Enter the subnet you want to scan (e.g. 24): ")
        network_address = ip.split('.')[0] + '.' + ip.split('.')[1] + '.' + ip.split('.')[2]
        ip_list = []
        for i in range(1, 256):
            ip = network_address + '.' + str(i)
            ip_list.append(ip)
        self.scanner.scan(hosts=' '.join(ip_list), arguments='-n -sP')
        hosts_list = [(x, self.scanner[x]['status']['state']) for x in self.scanner.all_hosts()]
        print("Active devices:")
        for host, status in hosts_list:
            if status == 'up':
                print(host)
                ip_list.append(ip)
        return ip_list

    def top_ports(self):
        """Scans the top 10 most common ports for open ports.

        Returns:
            A list of tuples, where each tuple contains the port number, the service name, and the version.
        """

        ports = [
            (20, "FTP"),
            (21, "FTP"),
            (22, "SSH"),
            (139, "SMB"),
            (137, "SMB"),
            (445, "SMB"),
            (53, "DNS"),
            (80, "HTTP"),
            (443, "HTTPS"),
            (8080, "HTTP"),
            (8443, "HTTPS"),
            (23, "Telnet"),
            (25, "SMTP"),
            (69, "TFTP")
        ]

        open_ports = []
        for port, service in ports:
            try:
                scanner = nmap.PortScanner()
                scanner.scan(hosts='localhost', arguments='-n -p ' + str(port))
                if scanner[socket.gethostbyname('localhost')]['status']['state'] == 'up':
                    open_ports.append((port, service))
            except nmap.PortScannerError:
                pass

        return open_ports


    def menu(self):
        print("Welcome to the Port Scanner!")
        while True:
            print("Please select an option:")
            print("1. Network Discovery")
            print("2. Scan top ports")
            print("3. Exit")
            choice = input()
            if choice == '1':
                ip_list = self.network_discovery()
                print("Scanning the following IP addresses:")
                for ip in ip_list:
                    print(ip)
                self.scanner.scan(hosts=' '.join(ip_list), arguments='-n -sP')
                hosts_list = [(x, self.scanner[x]['status']['state']) for x in self.scanner.all_hosts()]
                print("Active devices:")
                for host, status in hosts_list:
                    if status == 'up':
                        print(host)
            elif choice == '2':
                open_ports = self.top_ports()
                while True:
                    print("Please select a port number:")
                    for port, service in open_ports:
                        print("  {} ({})".format(port, service))

                    port_number = input("Enter a port number: ")
                    if port_number == "":
                        break

                    try:
                        version = nmap.PortScanner().scan(hosts='localhost', arguments='-n -p ' + port_number)[socket.gethostbyname('localhost')]['tcp'][port_number]['state']['version']
                        print("The version of the service running on port {} is {}".format(port_number, version))
                    except nmap.PortScannerError:
                        print("The port {} is not open.".format(port_number))

            elif choice == '3':
                sys.exit()
            else:
                print("Invalid choice. Please try again.")

if __name__ == '__main__':
    scanner = PortScanner()
    scanner.menu()

print("3. Targeted Scan")
print("4. Detailed Scan")
choice = ()
if choice == 1:
    pass
elif choice == '3':
    self.targeted_scan()
elif choice == '4':
    self.detailed_scan()
    def targeted_scan(self):
        self.target_ip = input("Enter target IP address to scan: ")
        while True:
            port_str = input("Enter port number(s) to scan (separated by commas): ")
            if not port_str:
                break
            ports = []
            for port in port_str.split(","):
                if not port.isdigit() or not (1 <= int(port) <= 65535):
                    print("Invalid input. Please enter a number between 1 and 65535 or press Enter to finish.")
                    break
                ports.append(int(port))
            else:
                self.target_ports = ports
                break
        
        self.open_ports = []
        self.services = {}
        for port in self.target_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            try:
                sock.connect((self.target_ip, port))
                self.open_ports.append(port)
                try:
                    service = socket.getservbyport(port)
                except:
                    service = 'unknown'
                self.services[port] = service
            except:
                pass
            finally:
                sock.close()
        if len(self.open_ports) > 0:
            print("Port\tOpen/closed\tService\tVersion")
            for port in self.open_ports:
                print("{}\t{}\t{}\t{}".format(port, 'open', self.services.get(port, 'unknown'), ''))
        else:
            print("No open ports found on {}.".format(self.target_ip))



    def detailed_scan(self):
        self.target_ip = input("Enter the IP address you want to scan: ")
        self.target_port = int(input("Enter the port number you want to scan: "))
        result = self.scanner.scan(self.target_ip, arguments='-sV -p{}'.format(self.target_port))
        try:
            state = result['scan'][self.target_ip]['tcp'][self.target_port]['state']
            name = result['scan'][self.target_ip]['tcp'][self.target_port]['name']
            product = result['scan'][self.target_ip]['tcp'][self.target_port]['product']
            version = result['scan'][self.target_ip]['tcp'][self.target_port]['version']
            print("Port {} is {}".format(self.target_port, state))
            print("Service: {} - {} - {}".format(name, product, version))
        except:
            state = 'unknown'
            name = 'unknown'
            product = 'unknown'
            version = 'unknown'
            print("Port {} is {}, Service: {} {}, Version: {}".format(self.target_port, state, name, product, version))
        choice = input("Do you want to save the results to a file? (y/n): ")
        if choice.lower() == 'y':
            filename = input("Enter the filename to save the results to: ")
            with open(filename, 'w') as f:
                f.write("Port: {}\n".format(self.target_port))
                f.write("State: {}\n".format(state))
                f.write("Name: {}\n".format(name))
                f.write("Product: {}\n".format(product))
                f.write("Version: {}\n".format(version))
                print("Results saved to file: {}".format(filename))
        else:
            print("Results not saved.")


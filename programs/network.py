import os
import subprocess
import socket
import netifaces
import scapy.all as scapy
from scapy.layers import http, dns
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
import threading
import time
import datetime
import json
from collections import defaultdict
import netaddr
from threading import Thread, Lock
import signal
import sys

class NetworkAnalyzer:
    def __init__(self):
        self.running = False
        self.captured_data = defaultdict(list)
        self.lock = Lock()
        self.devices = defaultdict(dict)
        self.packet_count = 0
        self.start_time = None

    def get_network_interfaces(self):
        interfaces = []
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                ip_info = addrs[netifaces.AF_INET][0]
                interfaces.append({
                    'name': iface,
                    'ip': ip_info['addr'],
                    'netmask': ip_info['netmask']
                })
        return interfaces

    def get_network_range(self, interface):
        try:
            ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
            netmask = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['netmask']
            network = netaddr.IPNetwork(f"{ip}/{netmask}")
            return str(network.cidr)
        except:
            return "192.168.1.0/24"

    def comprehensive_arp_scan(self, interface):
        network_range = self.get_network_range(interface)
        print(f"Scanning network: {network_range}")
        
        request = scapy.ARP(pdst=network_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / request
        
        answered = scapy.srp(packet, timeout=2, iface=interface, verbose=False)[0]
        
        devices = []
        for element in answered:
            device = {
                'ip': element[1].psrc,
                'mac': element[1].hwsrc,
                'vendor': self.get_mac_vendor(element[1].hwsrc),
                'hostname': self.reverse_dns_lookup(element[1].psrc)
            }
            devices.append(device)
            self.devices[element[1].psrc] = device
        
        return devices

    def get_mac_vendor(self, mac_address):
        try:
            mac = mac_address[:8].upper().replace(':', '')
            oui_files = ['/usr/share/ieee-data/oui.txt', '/usr/share/hwdata/oui.txt']
            for oui_file in oui_files:
                if os.path.exists(oui_file):
                    with open(oui_file, 'r') as f:
                        for line in f:
                            if mac in line:
                                return line.split('\t')[-1].strip()
        except:
            pass
        return "Unknown"

    def reverse_dns_lookup(self, ip):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"

    def start_comprehensive_sniffing(self, interface, duration=300):
        self.running = True
        self.start_time = datetime.datetime.now()
        self.packet_count = 0
        
        print(f"Starting comprehensive network analysis on interface {interface}")
        print("Capturing all network traffic...")
        print("Press Ctrl+C to stop\n")
        
        threads = [
            Thread(target=self.sniff_http, args=(interface,)),
            Thread(target=self.sniff_dns, args=(interface,)),
            Thread(target=self.sniff_tcp, args=(interface,)),
            Thread(target=self.sniff_udp, args=(interface,)),
            Thread(target=self.sniff_icmp, args=(interface,)),
            Thread(target=self.monitor_bandwidth, args=(interface,))
        ]
        
        for thread in threads:
            thread.daemon = True
            thread.start()
        
        try:
            while self.running and (datetime.datetime.now() - self.start_time).seconds < duration:
                time.sleep(1)
                self.display_stats()
        except KeyboardInterrupt:
            print("\nStopping network analysis...")
        finally:
            self.running = False
            self.generate_comprehensive_report()

    def sniff_http(self, interface):
        def process_http(packet):
            if packet.haslayer(http.HTTPRequest):
                with self.lock:
                    self.packet_count += 1
                    url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
                    src_ip = packet[IP].src
                    
                    http_data = {
                        'timestamp': datetime.datetime.now().isoformat(),
                        'src_ip': src_ip,
                        'method': packet[http.HTTPRequest].Method.decode(),
                        'url': url,
                        'user_agent': '',
                        'cookies': ''
                    }
                    
                    if packet.haslayer(scapy.Raw):
                        load = packet[scapy.Raw].load.decode(errors='ignore')
                        http_data['payload'] = load
                        
                        if 'User-Agent' in load:
                            http_data['user_agent'] = load.split('User-Agent: ')[1].split('\r\n')[0]
                        if 'Cookie' in load:
                            http_data['cookies'] = load.split('Cookie: ')[1].split('\r\n')[0]
                        
                        for credential_key in ["username", "password", "login", "pass", "user", "email"]:
                            if credential_key in load.lower():
                                http_data['credentials'] = load
                                break
                    
                    self.captured_data['http'].append(http_data)
                    self.update_device_activity(src_ip, 'http', http_data)
        
        scapy.sniff(iface=interface, filter="tcp port 80 or tcp port 8080 or tcp port 443", prn=process_http, store=False, stop_filter=lambda x: not self.running)

    def sniff_dns(self, interface):
        def process_dns(packet):
            if packet.haslayer(dns.DNSQR):
                with self.lock:
                    self.packet_count += 1
                    dns_data = {
                        'timestamp': datetime.datetime.now().isoformat(),
                        'src_ip': packet[IP].src,
                        'query': packet[dns.DNSQR].qname.decode(),
                        'type': 'query'
                    }
                    self.captured_data['dns'].append(dns_data)
                    self.update_device_activity(packet[IP].src, 'dns', dns_data)
            
            if packet.haslayer(dns.DNSRR):
                with self.lock:
                    self.packet_count += 1
                    dns_data = {
                        'timestamp': datetime.datetime.now().isoformat(),
                        'src_ip': packet[IP].src,
                        'response': packet[dns.DNSRR].rdata,
                        'type': 'response'
                    }
                    self.captured_data['dns'].append(dns_data)
                    self.update_device_activity(packet[IP].src, 'dns', dns_data)
        
        scapy.sniff(iface=interface, filter="udp port 53", prn=process_dns, store=False, stop_filter=lambda x: not self.running)

    def sniff_tcp(self, interface):
        def process_tcp(packet):
            if packet.haslayer(TCP):
                with self.lock:
                    self.packet_count += 1
                    tcp_data = {
                        'timestamp': datetime.datetime.now().isoformat(),
                        'src_ip': packet[IP].src,
                        'dst_ip': packet[IP].dst,
                        'src_port': packet[TCP].sport,
                        'dst_port': packet[TCP].dport,
                        'flags': packet[TCP].flags
                    }
                    self.captured_data['tcp'].append(tcp_data)
                    self.update_device_activity(packet[IP].src, 'tcp', tcp_data)
        
        scapy.sniff(iface=interface, filter="tcp", prn=process_tcp, store=False, stop_filter=lambda x: not self.running)

    def sniff_udp(self, interface):
        def process_udp(packet):
            if packet.haslayer(UDP):
                with self.lock:
                    self.packet_count += 1
                    udp_data = {
                        'timestamp': datetime.datetime.now().isoformat(),
                        'src_ip': packet[IP].src,
                        'dst_ip': packet[IP].dst,
                        'src_port': packet[UDP].sport,
                        'dst_port': packet[UDP].dport
                    }
                    self.captured_data['udp'].append(udp_data)
                    self.update_device_activity(packet[IP].src, 'udp', udp_data)
        
        scapy.sniff(iface=interface, filter="udp", prn=process_udp, store=False, stop_filter=lambda x: not self.running)

    def sniff_icmp(self, interface):
        def process_icmp(packet):
            if packet.haslayer(ICMP):
                with self.lock:
                    self.packet_count += 1
                    icmp_data = {
                        'timestamp': datetime.datetime.now().isoformat(),
                        'src_ip': packet[IP].src,
                        'dst_ip': packet[IP].dst,
                        'type': packet[ICMP].type,
                        'code': packet[ICMP].code
                    }
                    self.captured_data['icmp'].append(icmp_data)
                    self.update_device_activity(packet[IP].src, 'icmp', icmp_data)
        
        scapy.sniff(iface=interface, filter="icmp", prn=process_icmp, store=False, stop_filter=lambda x: not self.running)

    def monitor_bandwidth(self, interface):
        prev_stats = defaultdict(int)
        
        while self.running:
            time.sleep(2)
            with self.lock:
                current_stats = defaultdict(int)
                for protocol in ['tcp', 'udp', 'icmp', 'http', 'dns']:
                    for packet in self.captured_data[protocol]:
                        if packet['timestamp'] > (datetime.datetime.now() - datetime.timedelta(seconds=2)).isoformat():
                            current_stats[packet['src_ip']] += 1
                
                for ip, count in current_stats.items():
                    if ip in self.devices:
                        self.devices[ip]['bandwidth'] = count - prev_stats.get(ip, 0)
                
                prev_stats = current_stats

    def update_device_activity(self, ip, protocol, data):
        if ip not in self.devices:
            self.devices[ip] = {
                'ip': ip,
                'mac': 'Unknown',
                'vendor': 'Unknown',
                'hostname': 'Unknown',
                'activity': defaultdict(list),
                'bandwidth': 0
            }
        
        if protocol not in self.devices[ip]['activity']:
            self.devices[ip]['activity'][protocol] = []
        
        self.devices[ip]['activity'][protocol].append(data)
        
        if len(self.devices[ip]['activity'][protocol]) > 1000:
            self.devices[ip]['activity'][protocol] = self.devices[ip]['activity'][protocol][-1000:]

    def display_stats(self):
        with self.lock:
            print(f"\rPackets captured: {self.packet_count} | Devices found: {len(self.devices)} | Running: {(datetime.datetime.now() - self.start_time).seconds}s", end='', flush=True)

    def generate_comprehensive_report(self):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"network_analysis_report_{timestamp}.json"
        
        report = {
            'start_time': self.start_time.isoformat(),
            'end_time': datetime.datetime.now().isoformat(),
            'duration': (datetime.datetime.now() - self.start_time).seconds,
            'total_packets': self.packet_count,
            'devices': dict(self.devices),
            'captured_data': dict(self.captured_data)
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"\nReport saved to: {filename}")
        self.print_summary()

    def print_summary(self):
        print("\n" + "="*80)
        print("NETWORK ANALYSIS SUMMARY")
        print("="*80)
        
        print(f"\nTotal packets captured: {self.packet_count}")
        print(f"Analysis duration: {(datetime.datetime.now() - self.start_time).seconds} seconds")
        print(f"Devices detected: {len(self.devices)}")
        
        print("\nDEVICES FOUND:")
        print("-"*40)
        for ip, device in self.devices.items():
            print(f"IP: {ip}")
            print(f"MAC: {device.get('mac', 'Unknown')}")
            print(f"Vendor: {device.get('vendor', 'Unknown')}")
            print(f"Hostname: {device.get('hostname', 'Unknown')}")
            print(f"Bandwidth: {device.get('bandwidth', 0)} packets/sec")
            print(f"Protocols: {list(device.get('activity', {}).keys())}")
            print("-"*20)
        
        print("\nPROTOCOL STATISTICS:")
        print("-"*40)
        for protocol, packets in self.captured_data.items():
            print(f"{protocol.upper()}: {len(packets)} packets")

def network_analyzer_main():
    signal.signal(signal.SIGINT, lambda sig, frame: sys.exit(0))
    
    analyzer = NetworkAnalyzer()
    
    interfaces = analyzer.get_network_interfaces()
    if not interfaces:
        print("No network interfaces found")
        return
    
    print("Available network interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i+1}. {iface['name']} ({iface['ip']})")
    
    try:
        choice = int(input("\nSelect interface (number): ")) - 1
        selected_iface = interfaces[choice]['name']
    except:
        print("Invalid selection")
        return
    
    print(f"\n1. ARP Scan")
    print("2. Comprehensive Network Analysis")
    print("3. Both")
    
    try:
        mode = int(input("\nSelect mode: "))
    except:
        print("Invalid selection")
        return
    
    if mode in [1, 3]:
        devices = analyzer.comprehensive_arp_scan(selected_iface)
        print(f"\nFound {len(devices)} devices:")
        for device in devices:
            print(f"IP: {device['ip']} | MAC: {device['mac']} | Vendor: {device['vendor']} | Hostname: {device['hostname']}")
    
    if mode in [2, 3]:
        duration = int(input("Analysis duration (seconds, default 300): ") or "300")
        analyzer.start_comprehensive_sniffing(selected_iface, duration)

def packet_sniffing():
    def process_packet(packet):
        if packet.haslayer(http.HTTPRequest):
            url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
            print(f"HTTP Request: {url}")
            if packet.haslayer(scapy.Raw):
                load = packet[scapy.Raw].load
                for word in ["username", "password", "user", "pass"]:
                    if word in str(load):
                        print(f"Possible credentials: {load}")
                        break
    print("Starting packet sniffing...")
    scapy.sniff(iface="eth0", store=False, prn=process_packet)

def arp_scan():
    def scan(ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        
        clients = []
        for element in answered:
            client = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            clients.append(client)
        return clients

    target_ip = "192.168.1.1/24"
    print(f"Scanning network {target_ip}")
    clients = scan(target_ip)
    print("IP Address\t\tMAC Address")
    for client in clients:
        print(f"{client['ip']}\t\t{client['mac']}")

def trace_route(target):
    print(f"Tracing route to {target}")
    result = subprocess.run(["traceroute", target], capture_output=True, text=True)
    print(result.stdout)

def network_info():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print(f"Hostname: {hostname}")
    print(f"Local IP: {local_ip}")
    
    interfaces = netifaces.interfaces()
    for iface in interfaces:
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            ip_info = addrs[netifaces.AF_INET][0]
            print(f"Interface {iface}: {ip_info['addr']}/{ip_info['netmask']}")
    
    gateways = netifaces.gateways()
    if 'default' in gateways:
        for family, (gateway, interface, *_) in gateways['default'].items():
            print(f"Default Gateway: {gateway} via {interface}")

def reset_network():
    confirm = input("Reset network configuration? (y/N): ")
    if confirm.lower() != 'y':
        return
    
    commands = [
        "sudo systemctl restart networking",
        "sudo systemctl restart network-manager",
        "sudo dhclient -r",
        "sudo dhclient",
        "sudo systemctl restart systemd-networkd"
    ]
    
    for cmd in commands:
        try:
            subprocess.run(cmd, shell=True, check=True)
        except:
            pass
    
    print("Network configuration reset")
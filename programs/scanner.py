import socket
import subprocess
import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from netaddr import IPNetwork, IPAddress
import struct
import os
from datetime import datetime

def network_scan(target):
    print(f"Starting comprehensive scan of {target}")
    start_time = time.time()
    
    try:
        if '/' in target:
            network = IPNetwork(target)
            print(f"Scanning network: {network}")
            hosts = list(network)
        else:
            try:
                ipaddress.ip_address(target)
                hosts = [target]
            except:
                resolved_ip = socket.gethostbyname(target)
                print(f"Resolved {target} to {resolved_ip}")
                hosts = [resolved_ip]
    except Exception as e:
        print(f"Target validation failed: {e}")
        return
    
    scan_results = {}
    
    for host in hosts:
        host_str = str(host)
        if host_str.endswith('.0') or host_str.endswith('.255'):
            continue
            
        print(f"Scanning host: {host_str}")
        host_results = {}
        
        host_results['ports'] = tcp_port_scan(host_str)
        host_results['udp_ports'] = udp_port_scan(host_str)
        host_results['os_info'] = os_detection(host_str)
        host_results['services'] = service_detection(host_str, host_results['ports'])
        host_results['hostname'] = reverse_dns_lookup(host_str)
        
        if host_results['ports']:
            host_results['vulnerabilities'] = vulnerability_scan(host_str, host_results['ports'])
        
        scan_results[host_str] = host_results
    
    end_time = time.time()
    print(f"Scan completed in {end_time - start_time:.2f} seconds")
    
    generate_scan_report(scan_results, target)
    
    return scan_results

def tcp_port_scan(target, ports=None):
    if ports is None:
        ports = list(range(1, 1001)) + [1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017]
    
    open_ports = []
    
    def check_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                    return port
        except:
            pass
        return None
    
    with ThreadPoolExecutor(max_workers=500) as executor:
        futures = [executor.submit(check_port, port) for port in ports]
        for future in as_completed(futures):
            future.result()
    
    return sorted(open_ports)

def udp_port_scan(target, ports=None):
    if ports is None:
        ports = [53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 445, 514, 520, 631, 1434, 1900, 4500, 49152]
    
    open_ports = []
    
    def check_udp_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2)
                sock.sendto(b'\x00' * 64, (target, port))
                try:
                    data, addr = sock.recvfrom(1024)
                    open_ports.append(port)
                    return port
                except socket.timeout:
                    pass
        except:
            pass
        return None
    
    with ThreadPoolExecutor(max_workers=200) as executor:
        futures = [executor.submit(check_udp_port, port) for port in ports]
        for future in as_completed(futures):
            future.result()
    
    return sorted(open_ports)

def os_detection(target):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            sock.settimeout(2)
            packet = b'\x08\x00\x00\x00\x00\x00\x00\x00'
            sock.sendto(packet, (target, 0))
            
            response, addr = sock.recvfrom(1024)
            ttl = response[8]
            
            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                return "Windows"
            else:
                return "Unknown"
    except:
        pass
    
    try:
        result = subprocess.run(['nmap', '-O', '--osscan-limit', target], 
                              capture_output=True, text=True, timeout=30)
        if 'OS details' in result.stdout:
            for line in result.stdout.split('\n'):
                if 'OS details' in line:
                    return line.split(':', 1)[1].strip()
    except:
        pass
    
    return "Unknown"

def service_detection(target, ports):
    services = {}
    
    if not ports:
        return services
    
    def detect_service(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect((target, port))
                
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    
                    if 'HTTP' in banner:
                        services[port] = 'HTTP Service'
                        if 'Server:' in banner:
                            for line in banner.split('\n'):
                                if line.startswith('Server:'):
                                    services[port] = line.strip()
                    else:
                        services[port] = 'Unknown TCP Service'
                        
                except:
                    services[port] = 'Filtered/No Response'
                    
        except:
            services[port] = 'Connection Failed'
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(detect_service, ports)
    
    common_ports = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 135: 'MSRPC', 139: 'NetBIOS',
        143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS',
        995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
        27017: 'MongoDB'
    }
    
    for port in ports:
        if port in common_ports and port not in services:
            services[port] = common_ports[port]
    
    return services

def reverse_dns_lookup(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except:
        return "No reverse DNS"

def vulnerability_scan(target, ports):
    vulnerabilities = []
    
    if 21 in ports:
        vulnerabilities.append('FTP Anonymous login possible')
    
    if 23 in ports:
        vulnerabilities.append('Telnet service - unencrypted communication')
    
    if 135 in ports or 139 in ports or 445 in ports:
        vulnerabilities.append('SMB vulnerabilities possible')
    
    if 3389 in ports:
        vulnerabilities.append('RDP exposed - brute force risk')
    
    if 1433 in ports:
        vulnerabilities.append('MSSQL exposed - authentication attacks possible')
    
    if 5900 in ports:
        vulnerabilities.append('VNC exposed - unencrypted screen sharing')
    
    try:
        result = subprocess.run(['nmap', '--script', 'vuln', target], 
                              capture_output=True, text=True, timeout=120)
        for line in result.stdout.split('\n'):
            if 'VULNERABLE:' in line:
                vulnerabilities.append(line.split('VULNERABLE:')[1].strip())
    except:
        pass
    
    return vulnerabilities

def generate_scan_report(results, target):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{target.replace('/', '_')}_{timestamp}.txt"
    
    with open(filename, 'w') as f:
        f.write(f"Network Scan Report\n")
        f.write(f"Target: {target}\n")
        f.write(f"Scan Date: {datetime.now()}\n")
        f.write("=" * 80 + "\n\n")
        
        for host, data in results.items():
            f.write(f"Host: {host}\n")
            f.write(f"Hostname: {data.get('hostname', 'Unknown')}\n")
            f.write(f"OS Detection: {data.get('os_info', 'Unknown')}\n")
            
            f.write("\nOpen TCP Ports:\n")
            for port in data.get('ports', []):
                service = data.get('services', {}).get(port, 'Unknown')
                f.write(f"  Port {port}: {service}\n")
            
            f.write("\nOpen UDP Ports:\n")
            for port in data.get('udp_ports', []):
                f.write(f"  Port {port}: UDP Open\n")
            
            f.write("\nPotential Vulnerabilities:\n")
            for vuln in data.get('vulnerabilities', []):
                f.write(f"  - {vuln}\n")
            
            f.write("\n" + "=" * 80 + "\n\n")
    
    print(f"Scan report saved to: {filename}")

def syn_scan(target, ports=None):
    if ports is None:
        ports = range(1, 1001)
    
    open_ports = []
    
    def syn_scan_port(port):
        try:
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            packet = create_syn_packet(target, port)
            raw_socket.sendto(packet, (target, 0))
            
            response = raw_socket.recvfrom(1024)[0]
            if response[33] == 0x12:
                open_ports.append(port)
                
            raw_socket.close()
        except:
            pass
    
    with ThreadPoolExecutor(max_workers=300) as executor:
        executor.map(syn_scan_port, ports)
    
    return sorted(open_ports)

def create_syn_packet(dst_ip, dst_port):
    src_ip = socket.gethostbyname(socket.gethostname())
    src_port = 54321
    
    ip_header = struct.pack('!BBHHHBBH4s4s',
        69, 0, 40, 54321, 0, 64, 6, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    
    tcp_header = struct.pack('!HHLLBBHHH',
        src_port, dst_port, 0, 0, 5 << 4, 2, 1024, 0, 0)
    
    pseudo_header = struct.pack('!4s4sBBH',
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        0, 6, len(tcp_header))
    
    checksum = calculate_checksum(pseudo_header + tcp_header)
    
    tcp_header = struct.pack('!HHLLBBH',
        src_port, dst_port, 0, 0, 5 << 4, 2, 1024) + struct.pack('H', checksum) + b'\x00\x00'
    
    return ip_header + tcp_header

def calculate_checksum(data):
    if len(data) % 2:
        data += b'\x00'
    
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i+1]
        total += word
        total = (total & 0xffff) + (total >> 16)
    
    return ~total & 0xffff

def network_discovery(network):
    active_hosts = []
    
    def ping_host(ip):
        try:
            subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)], 
                         capture_output=True, check=True)
            active_hosts.append(str(ip))
            return str(ip)
        except:
            return None
    
    hosts = list(IPNetwork(network))
    
    with ThreadPoolExecutor(max_workers=255) as executor:
        futures = [executor.submit(ping_host, host) for host in hosts]
        for future in as_completed(futures):
            future.result()
    
    return active_hosts

def comprehensive_scan(target):
    print(f"Initiating comprehensive scan on {target}")
    
    if '/' in target:
        active_hosts = network_discovery(target)
        print(f"Discovered {len(active_hosts)} active hosts")
        
        all_results = {}
        for host in active_hosts:
            print(f"Scanning host: {host}")
            all_results[host] = network_scan(host)
        
        return all_results
    else:
        return network_scan(target)
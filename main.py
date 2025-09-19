#!/usr/bin/env python3
import os
import sys
import argparse
from programs import install, network, web, wordpress, crypto, forensic, exploit, scanner, fuzzer, reverse, audit, report

def main():
    parser = argparse.ArgumentParser(description="Advanced Security Toolkit", formatter_class=argparse.RawDescriptionHelpFormatter)
    
    parser.add_argument('-v', '--version', action='version', version='Advanced Security Toolkit v3.0')
    
    install_group = parser.add_argument_group('Installation')
    install_group.add_argument('--install', metavar='TOOL', help='Install security tool')
    install_group.add_argument('--list-tools', action='store_true', help='List available tools')
    
    web_group = parser.add_argument_group('Web Analysis')
    web_group.add_argument('--crawl', metavar='URL', help='Crawl website links')
    web_group.add_argument('--dirscan', metavar='URL', help='Directory brute force')
    web_group.add_argument('--wpscan', metavar='URL', help='WordPress vulnerability scan')
    web_group.add_argument('--subdomains', metavar='DOMAIN', help='Find subdomains')
    web_group.add_argument('--headers', metavar='URL', help='Analyze HTTP headers')
    
    network_group = parser.add_argument_group('Network')
    network_group.add_argument('--net-scan', metavar='IP', help='Network port scan')
    network_group.add_argument('--packet-sniff', action='store_true', help='Packet sniffing')
    network_group.add_argument('--arp-scan', action='store_true', help='ARP network scan')
    network_group.add_argument('--traceroute', metavar='HOST', help='Network route tracing')
    network_group.add_argument('--net-info', action='store_true', help='Network information')
    network_group.add_argument('--reset-net', action='store_true', help='Reset network configuration')
    
    crypto_group = parser.add_argument_group('Cryptography')
    crypto_group.add_argument('--encrypt-file', metavar='FILE', help='Encrypt file')
    crypto_group.add_argument('--decrypt-file', metavar='FILE', help='Decrypt file')
    crypto_group.add_argument('--hash', metavar='TEXT', help='Generate hashes')
    crypto_group.add_argument('--brute-hash', metavar='HASH', help='Brute force hash')
    
    forensic_group = parser.add_argument_group('Forensics')
    forensic_group.add_argument('--mem-dump', action='store_true', help='Memory acquisition')
    forensic_group.add_argument('--disk-image', metavar='DEVICE', help='Create disk image')
    forensic_group.add_argument('--file-recover', metavar='PATH', help='Recover deleted files')
    forensic_group.add_argument('--meta-extract', metavar='FILE', help='Extract metadata')
    
    exploit_group = parser.add_argument_group('Exploitation')
    exploit_group.add_argument('--exploit-search', metavar='QUERY', help='Search exploits')
    exploit_group.add_argument('--shell-gen', metavar='TYPE', help='Generate reverse shell')
    exploit_group.add_argument('--payload-gen', metavar='TYPE', help='Generate payload')
    
    audit_group = parser.add_argument_group('Audit')
    audit_group.add_argument('--sys-audit', action='store_true', help='System security audit')
    audit_group.add_argument('--pass-audit', action='store_true', help='Password policy audit')
    audit_group.add_argument('--log-analysis', metavar='LOG_FILE', help='Analyze log files')
    
    args = parser.parse_args()
    
    try:
        if args.install:
            install.install_tool(args.install)
        elif args.list_tools:
            install.list_tools()
        elif args.crawl:
            web.crawl_website(args.crawl)
        elif args.dirscan:
            web.directory_scan(args.dirscan)
        elif args.wpscan:
            wordpress.wp_scan(args.wpscan)
        elif args.subdomains:
            web.find_subdomains(args.subdomains)
        elif args.headers:
            web.analyze_headers(args.headers)
        elif args.net_scan:
            scanner.network_scan(args.net_scan)
        elif args.packet_sniff:
            network.packet_sniffing()
        elif args.arp_scan:
            network.arp_scan()
        elif args.traceroute:
            network.trace_route(args.traceroute)
        elif args.net_info:
            network.network_info()
        elif args.reset_net:
            network.reset_network()
        elif args.encrypt_file:
            crypto.encrypt_file(args.encrypt_file)
        elif args.decrypt_file:
            crypto.decrypt_file(args.decrypt_file)
        elif args.hash:
            crypto.generate_hashes(args.hash)
        elif args.brute_hash:
            crypto.brute_force_hash(args.brute_hash)
        elif args.mem_dump:
            forensic.memory_acquisition()
        elif args.disk_image:
            forensic.create_disk_image(args.disk_image)
        elif args.file_recover:
            forensic.recover_files(args.file_recover)
        elif args.meta_extract:
            forensic.extract_metadata(args.meta_extract)
        elif args.exploit_search:
            exploit.search_exploits(args.exploit_search)
        elif args.shell_gen:
            exploit.generate_shell(args.shell_gen)
        elif args.payload_gen:
            exploit.generate_payload(args.payload_gen)
        elif args.sys_audit:
            audit.system_audit()
        elif args.pass_audit:
            audit.password_audit()
        elif args.log_analysis:
            audit.analyze_logs(args.log_analysis)
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
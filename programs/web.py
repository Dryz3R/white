import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import concurrent.futures
import dns.resolver
import ssl
import socket
from datetime import datetime

def crawl_website(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
    
    visited = set()
    to_visit = {url}
    
    while to_visit:
        current_url = to_visit.pop()
        if current_url in visited:
            continue
        
        try:
            response = session.get(current_url, timeout=10)
            visited.add(current_url)
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(current_url, href)
                if urlparse(full_url).netloc == urlparse(url).netloc:
                    if full_url not in visited:
                        to_visit.add(full_url)
            
            print(f"Found: {current_url} ({response.status_code})")
            
        except:
            continue
    
    print(f"Total URLs found: {len(visited)}")

def directory_scan(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    wordlist = [
        'admin', 'login', 'wp-admin', 'administrator', 'dashboard',
        'css', 'js', 'images', 'uploads', 'backup', 'config',
        'database', 'include', 'tmp', 'temp', 'logs'
    ]
    
    session = requests.Session()
    
    def check_path(path):
        try:
            test_url = f"{url}/{path}"
            response = session.get(test_url, timeout=5)
            if response.status_code < 400:
                print(f"Found: {test_url} ({response.status_code})")
        except:
            pass
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(check_path, wordlist)

def find_subdomains(domain):
    subdomains = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
        'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
        'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
        'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static'
    ]
    
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    
    found = []
    for sub in subdomains:
        try:
            target = f"{sub}.{domain}"
            answers = resolver.resolve(target, 'A')
            for answer in answers:
                found.append((target, str(answer)))
                print(f"Found: {target} -> {answer}")
        except:
            continue
    
    print(f"Total subdomains found: {len(found)}")

def analyze_headers(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        response = requests.get(url, timeout=10)
        print("HTTP Headers Analysis:")
        print("-" * 50)
        
        security_headers = [
            'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection',
            'Strict-Transport-Security', 'Content-Security-Policy'
        ]
        
        for header, value in response.headers.items():
            if header in security_headers:
                print(f"{header}: {value} [SECURITY]")
            else:
                print(f"{header}: {value}")
        
        print("-" * 50)
        print(f"Server: {response.headers.get('Server', 'Unknown')}")
        print(f"Powered By: {response.headers.get('X-Powered-By', 'Unknown')}")
        
    except Exception as e:
        print(f"Error: {e}")
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import concurrent.futures
import re
import xmlrpc.client
import json
import dns.resolver
import socket
import ssl
from datetime import datetime

def wp_scan(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    print(f"Scanning WordPress site: {url}")
    
    scan_results = {
        'url': url,
        'timestamp': datetime.now().isoformat(),
        'wp_detected': False,
        'version': None,
        'users': [],
        'plugins': [],
        'themes': [],
        'paths': [],
        'vulnerabilities': [],
        'config_files': [],
        'security_headers': {}
    }
    
    try:
        response = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        scan_results['security_headers'] = dict(response.headers)
        
        if 'wp-content' in response.text or 'wp-includes' in response.text:
            scan_results['wp_detected'] = True
            print("WordPress detected")
            
            scan_results.update(detect_wp_version(url, response.text))
            scan_results.update(find_wp_users(url))
            scan_results.update(scan_wp_plugins(url))
            scan_results.update(scan_wp_themes(url))
            scan_results.update(check_wp_paths(url))
            scan_results.update(check_xmlrpc(url))
            scan_results.update(check_wp_config(url))
            scan_results.update(check_security_measures(url))
            scan_results.update(scan_wp_vulnerabilities(url, scan_results['plugins'], scan_results['themes']))
            
        else:
            print("WordPress not detected")
            
    except Exception as e:
        print(f"Scan error: {e}")
        scan_results['error'] = str(e)
    
    generate_wp_report(scan_results)
    return scan_results

def detect_wp_version(url, html_content):
    version_info = {'version': None, 'version_method': None}
    
    try:
        readme_url = urljoin(url, "readme.html")
        response = requests.get(readme_url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            version_tag = soup.find('h1')
            if version_tag:
                version_info['version'] = version_tag.text.strip()
                version_info['version_method'] = 'readme.html'
                return version_info
    except:
        pass
    
    try:
        generator_meta = re.search(r'<meta name="generator" content="WordPress (\d+\.\d+(?:\.\d+)?)"', html_content)
        if generator_meta:
            version_info['version'] = generator_meta.group(1)
            version_info['version_method'] = 'generator_meta'
            return version_info
    except:
        pass
    
    try:
        includes_url = urljoin(url, "wp-includes/version.php")
        response = requests.get(includes_url, timeout=5)
        if response.status_code == 200:
            version_match = re.search(r'\$wp_version\s*=\s*[\'"]([^\'"]+)[\'"]', response.text)
            if version_match:
                version_info['version'] = version_match.group(1)
                version_info['version_method'] = 'version.php'
                return version_info
    except:
        pass
    
    return version_info

def find_wp_users(url):
    users = []
    
    author_urls = [
        f"{url}/?author=1",
        f"{url}/wp-json/wp/v2/users",
        f"{url}/?rest_route=/wp/v2/users"
    ]
    
    for user_url in author_urls:
        try:
            response = requests.get(user_url, timeout=5)
            if response.status_code == 200:
                if 'application/json' in response.headers.get('content-type', ''):
                    user_data = response.json()
                    for user in user_data:
                        users.append({
                            'id': user.get('id'),
                            'name': user.get('name'),
                            'slug': user.get('slug'),
                            'url': user.get('url')
                        })
                else:
                    username_match = re.search(r'author/([^/]+)/', response.text)
                    if username_match:
                        users.append({'username': username_match.group(1)})
        except:
            continue
    
    return {'users': users}

def scan_wp_plugins(url):
    plugins = []
    
    plugin_list = [
        'akismet', 'contact-form-7', 'yoast', 'wordfence', 'jetpack',
        'woocommerce', 'elementor', 'divi', 'wpforms', 'all-in-one-seo-pack',
        'advanced-custom-fields', 'really-simple-ssl', 'wp-rocket', 'redirection',
        'duplicator', 'updraftplus', 'litespeed-cache', 'imagify', 'sucuri',
        'ithemes-security', 'google-site-kit', 'broken-link-checker'
    ]
    
    def check_plugin(plugin):
        try:
            plugin_urls = [
                f"{url}/wp-content/plugins/{plugin}/",
                f"{url}/wp-content/plugins/{plugin}/readme.txt",
                f"{url}/wp-content/plugins/{plugin}/{plugin}.php"
            ]
            
            for plugin_url in plugin_urls:
                response = requests.get(plugin_url, timeout=5)
                if response.status_code < 400:
                    version = None
                    if 'readme.txt' in plugin_url and response.status_code == 200:
                        version_match = re.search(r'Stable tag:\s*(\d+\.\d+(?:\.\d+)?)', response.text)
                        if version_match:
                            version = version_match.group(1)
                    
                    plugins.append({
                        'name': plugin,
                        'url': plugin_url,
                        'version': version,
                        'status': 'detected'
                    })
                    return
        except:
            pass
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(check_plugin, plugin_list)
    
    return {'plugins': plugins}

def scan_wp_themes(url):
    themes = []
    
    theme_list = [
        'twentytwentyfour', 'twentytwentythree', 'twentytwentytwo',
        'twentytwentyone', 'twentytwenty', 'twentyseventeen', 'twentysixteen',
        'twentyfifteen', 'astra', 'oceanwp', 'generatepress', 'avada',
        'divi', 'enfold', 'salient', 'the7', 'bridge', 'betheme', 'flatsome'
    ]
    
    def check_theme(theme):
        try:
            theme_urls = [
                f"{url}/wp-content/themes/{theme}/",
                f"{url}/wp-content/themes/{theme}/style.css",
                f"{url}/wp-content/themes/{theme}/readme.txt"
            ]
            
            for theme_url in theme_urls:
                response = requests.get(theme_url, timeout=5)
                if response.status_code < 400:
                    version = None
                    if 'style.css' in theme_url and response.status_code == 200:
                        version_match = re.search(r'Version:\s*(\d+\.\d+(?:\.\d+)?)', response.text)
                        if version_match:
                            version = version_match.group(1)
                    
                    themes.append({
                        'name': theme,
                        'url': theme_url,
                        'version': version,
                        'status': 'detected'
                    })
                    return
        except:
            pass
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(check_theme, theme_list)
    
    return {'themes': themes}

def check_wp_paths(url):
    paths = []
    
    wp_paths = [
        'wp-admin', 'wp-login.php', 'wp-content', 'wp-includes',
        'wp-config.php', 'xmlrpc.php', 'wp-json', 'wp-signup.php',
        'wp-cron.php', 'wp-load.php', 'wp-mail.php', 'wp-settings.php',
        'wp-trackback.php', 'wp-comments-post.php', 'wp-activate.php',
        'wp-links-opml.php', 'wp-admin/install.php', 'wp-admin/upgrade.php'
    ]
    
    def check_path(path):
        try:
            test_url = urljoin(url, path)
            response = requests.get(test_url, timeout=5)
            if response.status_code < 400:
                paths.append({
                    'path': path,
                    'url': test_url,
                    'status_code': response.status_code,
                    'content_length': len(response.content)
                })
        except:
            pass
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        executor.map(check_path, wp_paths)
    
    return {'paths': paths}

def check_xmlrpc(url):
    xmlrpc_url = urljoin(url, "xmlrpc.php")
    
    try:
        response = requests.get(xmlrpc_url, timeout=5)
        if response.status_code == 200 and 'XML-RPC' in response.text:
            try:
                server = xmlrpc.client.ServerProxy(xmlrpc_url)
                methods = server.system.listMethods()
                return {
                    'xmlrpc_enabled': True,
                    'methods_available': methods
                }
            except:
                return {'xmlrpc_enabled': True}
    except:
        pass
    
    return {'xmlrpc_enabled': False}

def check_wp_config(url):
    config_files = []
    
    config_paths = [
        'wp-config.php', 'wp-config.php.bak', 'wp-config.php.old',
        'wp-config.php.save', 'wp-config.php.orig', 'wp-config.php.dist',
        'wp-config.php.txt', '../wp-config.php'
    ]
    
    def check_config(path):
        try:
            test_url = urljoin(url, path)
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200 and 'DB_NAME' in response.text:
                config_files.append({
                    'file': path,
                    'url': test_url,
                    'vulnerable': True
                })
        except:
            pass
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(check_config, config_paths)
    
    return {'config_files': config_files}

def check_security_measures(url):
    security = {}
    
    try:
        login_url = urljoin(url, "wp-login.php")
        response = requests.get(login_url, timeout=5)
        
        if response.status_code == 200:
            security['login_page_accessible'] = True
            
            if 'log=out' in response.text:
                security['logout_confirmation'] = True
            
            if 'user_login' in response.text and 'user_pass' in response.text:
                security['login_form_present'] = True
    except:
        security['login_page_accessible'] = False
    
    return security

def scan_wp_vulnerabilities(url, plugins, themes):
    vulnerabilities = []
    
    for plugin in plugins:
        if plugin['version']:
            vuln_check = check_plugin_vulnerability(plugin['name'], plugin['version'])
            if vuln_check:
                vulnerabilities.append({
                    'type': 'plugin',
                    'name': plugin['name'],
                    'version': plugin['version'],
                    'vulnerabilities': vuln_check
                })
    
    for theme in themes:
        if theme['version']:
            vuln_check = check_theme_vulnerability(theme['name'], theme['version'])
            if vuln_check:
                vulnerabilities.append({
                    'type': 'theme',
                    'name': theme['name'],
                    'version': theme['version'],
                    'vulnerabilities': vuln_check
                })
    
    return {'vulnerabilities': vulnerabilities}

def check_plugin_vulnerability(plugin_name, version):
    return []

def check_theme_vulnerability(theme_name, version):
    return []

def generate_wp_report(scan_results):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"wp_scan_report_{urlparse(scan_results['url']).netloc}_{timestamp}.json"
    
    with open(filename, 'w') as f:
        json.dump(scan_results, f, indent=2)
    
    print(f"Scan report saved to: {filename}")
    
    print(f"\nWordPress Scan Summary for {scan_results['url']}")
    print("=" * 60)
    print(f"WordPress Detected: {scan_results.get('wp_detected', False)}")
    print(f"Version: {scan_results.get('version', 'Unknown')}")
    print(f"Users Found: {len(scan_results.get('users', []))}")
    print(f"Plugins Found: {len(scan_results.get('plugins', []))}")
    print(f"Themes Found: {len(scan_results.get('themes', []))}")
    print(f"Paths Found: {len(scan_results.get('paths', []))}")
    print(f"Vulnerabilities: {len(scan_results.get('vulnerabilities', []))}")
    print(f"Config Files Exposed: {len(scan_results.get('config_files', []))}")
    print(f"XML-RPC Enabled: {scan_results.get('xmlrpc_enabled', False)}")
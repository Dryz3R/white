import os
import sys
import subprocess
import requests

TOOLS = {
    'sqlmap': {'desc': 'SQL injection tool', 'install': 'sudo apt install sqlmap -y'},
    'gobuster': {'desc': 'Directory/file brute forcer', 'install': 'sudo apt install gobuster -y'},
    'hydra': {'desc': 'Network login cracker', 'install': 'sudo apt install hydra -y'},
    'wireshark': {'desc': 'Network protocol analyzer', 'install': 'sudo apt install wireshark -y'},
    'nmap': {'desc': 'Network exploration tool', 'install': 'sudo apt install nmap -y'},
    'ffuf': {'desc': 'Web fuzzing tool', 'install': 'sudo apt install ffuf -y'},
    'volatility': {'desc': 'Memory forensics framework', 'install': 'sudo apt install volatility -y'},
    'foremost': {'desc': 'File recovery tool', 'install': 'sudo apt install foremost -y'},
    'radare2': {'desc': 'Reverse engineering framework', 'install': 'sudo apt install radare2 -y'},
    'metasploit': {'desc': 'Penetration testing framework', 'install': 'curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall'},
    'yara': {'desc': 'Pattern matching tool', 'install': 'sudo apt install yara -y'},
    'ossec': {'desc': 'Host intrusion detection', 'install': 'sudo apt install ossec-hids -y'},
    'clamav': {'desc': 'Antivirus engine', 'install': 'sudo apt install clamav -y'},
    'john': {'desc': 'Password cracker', 'install': 'sudo apt install john -y'},
    'hashcat': {'desc': 'Advanced password recovery', 'install': 'sudo apt install hashcat -y'},
    'binwalk': {'desc': 'Firmware analysis tool', 'install': 'sudo apt install binwalk -y'},
    'burpsuite': {'desc': 'Web application security', 'install': 'sudo apt install burpsuite -y'},
    'aircrack-ng': {'desc': 'WiFi security auditing', 'install': 'sudo apt install aircrack-ng -y'},
    'nikto': {'desc': 'Web server scanner', 'install': 'sudo apt install nikto -y'},
    'wpscan': {'desc': 'WordPress vulnerability scanner', 'install': 'sudo apt install wpscan -y'}
}

def install_tool(tool_name):
    if tool_name.lower() in TOOLS:
        tool = TOOLS[tool_name.lower()]
        print(f"Installing {tool_name}: {tool['desc']}")
        try:
            result = subprocess.run(tool['install'], shell=True, check=True, capture_output=True, text=True)
            print(f"Successfully installed {tool_name}")
        except subprocess.CalledProcessError as e:
            print(f"Installation failed: {e.stderr}")
    else:
        print(f"Tool {tool_name} not found")
        list_tools()

def list_tools():
    print("Available tools:")
    for tool, info in TOOLS.items():
        print(f"  {tool}: {info['desc']}")
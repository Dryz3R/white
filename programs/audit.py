import os
import subprocess
import pwd
import grp
from datetime import datetime

def system_audit():
    print("System Security Audit")
    print("=" * 50)
    
    check_root_account()
    check_suid_files()
    check_world_writable_files()
    check_unowned_files()
    check_recent_logins()
    check_cron_jobs()
    check_services()

def check_root_account():
    print("\n[+] Checking root account access")
    try:
        with open('/etc/passwd', 'r') as f:
            for line in f:
                if line.startswith('root:'):
                    print(f"Root account: {line.strip()}")
    except:
        print("Cannot access /etc/passwd")

def check_suid_files():
    print("\n[+] Checking SUID files")
    try:
        result = subprocess.run(["find", "/", "-perm", "-4000", "-type", "f", "2>/dev/null"], 
                              capture_output=True, text=True)
        print("SUID files found:")
        for line in result.stdout.split('\n'):
            if line.strip():
                print(f"  {line}")
    except:
        print("SUID check failed")

def check_world_writable_files():
    print("\n[+] Checking world-writable files")
    try:
        result = subprocess.run(["find", "/", "-perm", "-2", "-type", "f", "2>/dev/null"], 
                              capture_output=True, text=True)
        print("World-writable files:")
        for line in result.stdout.split('\n'):
            if line.strip():
                print(f"  {line}")
    except:
        print("World-writable check failed")

def check_unowned_files():
    print("\n[+] Checking unowned files")
    try:
        result = subprocess.run(["find", "/", "-nouser", "-o", "-nogroup", "2>/dev/null"], 
                              capture_output=True, text=True)
        print("Unowned files:")
        for line in result.stdout.split('\n'):
            if line.strip():
                print(f"  {line}")
    except:
        print("Unowned files check failed")

def check_recent_logins():
    print("\n[+] Checking recent logins")
    try:
        result = subprocess.run(["last", "-n", "10"], capture_output=True, text=True)
        print("Recent logins:")
        print(result.stdout)
    except:
        print("Login check failed")

def check_cron_jobs():
    print("\n[+] Checking cron jobs")
    try:
        for user in pwd.getpwall():
            result = subprocess.run(["crontab", "-l", "-u", user.pw_name], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                print(f"Cron jobs for {user.pw_name}:")
                print(result.stdout)
    except:
        print("Cron check failed")

def check_services():
    print("\n[+] Checking running services")
    try:
        result = subprocess.run(["netstat", "-tulpn"], capture_output=True, text=True)
        print("Running services:")
        print(result.stdout)
    except:
        print("Service check failed")

def password_audit():
    print("\n[+] Password policy audit")
    try:
        with open('/etc/login.defs', 'r') as f:
            content = f.read()
            if "PASS_MAX_DAYS" in content:
                print("Password aging policy found")
    except:
        print("Password policy check failed")

def analyze_logs(log_file):
    print(f"Analyzing log file: {log_file}")
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()[-100:]
            print("Recent log entries:")
            for line in lines:
                if "error" in line.lower() or "fail" in line.lower():
                    print(f"ERROR: {line.strip()}")
                elif "login" in line.lower() or "auth" in line.lower():
                    print(f"AUTH: {line.strip()}")
    except:
        print("Log analysis failed")
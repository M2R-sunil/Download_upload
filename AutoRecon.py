#!/usr/bin/env python3

import os
import sys
import subprocess
import argparse
import re
import requests
import urllib3
from urllib.parse import urlparse, parse_qs
import concurrent.futures

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Terminal Colors
G = '\033[92m'  # Green
Y = '\033[93m'  # Yellow
R = '\033[91m'  # Red
C = '\033[96m'  # Cyan
W = '\033[0m'   # White

def print_banner():
    banner = fr"""{C}
    _         _        ____                    __  __
   / \  _   _| |_ ___ |  _ \ ___  ___ ___  _ __ \ \/ /
  / _ \| | | | __/ _ \| |_) / _ \/ __/ _ \| '_ \ \  / 
 / ___ \ |_| | || (_) |  _ <  __/ (_| (_) | | | |/  \ 
/_/   \_\__,_|\__\___/|_| \_\___|\___\___/|_| |_/_/\_\
    
    🔥 Automated Bug Bounty Recon Framework Created By sunil 🔥
    {W}"""
    print(banner)

def run_command(command):
    """Executes a shell command and suppresses output."""
    try:
        subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        pass

def check_dependencies():
    """Check if required Go tools are installed."""
    tools = ['subfinder', 'assetfinder', 'httpx-toolkit', 'gau']
    missing = []
    for tool in tools:
        if subprocess.call(f"type {tool}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            missing.append(tool)
    
    if missing:
        print(f"{R}[!] Missing tools: {', '.join(missing)}{W}")
        print(f"{Y}[*] Please install them via Go (e.g., go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest){W}")
        sys.exit(1)

def run_recon(domain):
    print(f"{G}[+] Starting AutoReconX for: {domain}{W}")
    
    # Create output directory
    out_dir = f"recon_{domain}"
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    os.chdir(out_dir)
    
    # Phase 1: Subdomain Enumeration
    print(f"\n{Y}[*] Phase 1: Subdomain Enumeration...{W}")
    run_command(f"subfinder -d {domain} -silent > subfinder.txt")
    run_command(f"assetfinder -subs-only {domain} > assetfinder.txt")
    run_command("cat subfinder.txt assetfinder.txt | sort -u > subs.txt")
    run_command("rm subfinder.txt assetfinder.txt")
    
    subs_count = sum(1 for line in open('subs.txt')) if os.path.exists('subs.txt') else 0
    print(f"{G}[+] Found {subs_count} unique subdomains.{W}")

    # Phase 2: Live Host Checking
    print(f"\n{Y}[*] Phase 2: Probing Live Hosts...{W}")
    run_command("httpx-toolkit -l subs.txt -silent -threads 100 > live.txt")
    
    live_count = sum(1 for line in open('live.txt')) if os.path.exists('live.txt') else 0
    print(f"{G}[+] Found {live_count} live hosts.{W}")

    # Phase 3: Crawling URLs
    print(f"\n{Y}[*] Phase 3: Crawling URLs (This might take a while)...{W}")
    run_command(f"cat live.txt | gau --threads 10 > urls.txt")
    
    urls_count = sum(1 for line in open('urls.txt')) if os.path.exists('urls.txt') else 0
    print(f"{G}[+] Found {urls_count} total URLs.{W}")

    # Phase 4: Data Processing
    print(f"\n{Y}[*] Phase 4: Data Processing & High-Value Extraction...{W}")
    process_urls()

def process_urls():
    if not os.path.exists('urls.txt'):
        print(f"{R}[!] urls.txt not found. Skipping extraction.{W}")
        return

    js_urls = set()
    params_urls = set()
    interesting_urls = set()
    high_value_urls = set()
    
    # Next Level High Value Keywords
    priority_keywords = [
        'admin', 'graphql', 'swagger', '.env', 'backup', 'debug', 
        'config', 'sql', 'db', 'database', 'root', 'secret', 
        'credentials', 'password', 'phpinfo', 'api/v1', 'api/v2', 
        's3.amazonaws', 'bucket', 'kubernetes', 'docker', 'jenkins', 
        'jira', '.git', '.svn', 'setup', 'install', 'auth'
    ]

    interesting_keywords = [
        'dashboard', 'panel', 'portal', 'backend', 'staff', 'internal',
        'docs', 'developer', 'sandbox', 'staging', 'test', 'qa',
        'login', 'signin', 'signup', 'register', 'reset', 'forgot',
        'upload', 'download', 'file', 'media', 'user', 'profile',
        'payment', 'billing', 'invoice', 'wallet', 'redirect', 'callback'
    ]

    with open('urls.txt', 'r') as f:
        for line in f:
            url = line.strip()
            parsed = urlparse(url)
            low = url.lower()
            
            # 1. JS Files
            if parsed.path.endswith('.js'):
                js_urls.add(url)
            
            # 2. Parameters
            if parsed.query:
                params_urls.add(url)
                
            # 3. High Value Logic
            if any(key in low for key in priority_keywords):
                high_value_urls.add(url)

            # 4. Interesting Logic
            if any(key in low for key in interesting_keywords):
                interesting_urls.add(url)

    # Save outputs
    with open('js.txt', 'w') as f:
        f.write('\n'.join(js_urls))
    with open('params.txt', 'w') as f:
        f.write('\n'.join(params_urls))
    with open('interesting.txt', 'w') as f:
        f.write('\n'.join(interesting_urls))
    with open('highvalue.txt', 'w') as f:
        f.write('\n'.join(high_value_urls))

    print(f"{G}[+] Extracted {len(js_urls)} JS files.{W}")
    print(f"{G}[+] Extracted {len(params_urls)} parameterized URLs.{W}")
    print(f"{G}[+] Extracted {len(interesting_urls)} interesting endpoints.{W}")
    print(f"{R}[!] Extracted {len(high_value_urls)} HIGH VALUE endpoints (Check highvalue.txt).{W}")

    # Phase 5: Scan JS for Secrets
    print(f"\n{Y}[*] Phase 5: Scanning JS files for secrets...{W}")
    scan_js_secrets(list(js_urls))

def scan_js_secrets(js_urls):
    secrets_found = []
    regex_patterns = {
        'Google_API': r'AIza[0-9A-Za-z-_]{35}',
        'Stripe_Standard_API': r'sk_live_[0-9a-zA-Z]{24}',
        'GitHub_Token': r'(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}',
        'AWS_Access_Key': r'AKIA[0-9A-Z]{16}',
        'Generic_Secret': r'(?i)(?:secret|token|password|auth_key|api_key)[\s:=]+["\']([a-zA-Z0-9\-_]{10,})["\']'
    }

    def fetch_and_scan(url):
        try:
            res = requests.get(url, timeout=5, verify=False)
            if res.status_code == 200:
                content = res.text
                for key, pattern in regex_patterns.items():
                    matches = re.findall(pattern, content)
                    for match in matches:
                        secrets_found.append(f"[{key}] found in {url} -> {match}")
        except Exception:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(fetch_and_scan, js_urls)

    if secrets_found:
        with open('secrets.txt', 'w') as f:
            f.write('\n'.join(secrets_found))
        print(f"{R}[!] FOUND {len(secrets_found)} POTENTIAL SECRETS! Saved to secrets.txt{W}")
    else:
        print(f"{G}[+] No obvious secrets found in JS files.{W}")

if __name__ == "__main__":
    print_banner()
    parser = argparse.ArgumentParser(description="AutoReconX - Automated Bug Bounty Recon")
    parser.add_argument("-d", "--domain", help="Target domain", required=True)
    args = parser.parse_args()

    check_dependencies()
    run_recon(args.domain)
    
    print(f"\n{G}[★] Recon completed! Folder: 'recon_{args.domain}'{W}")

#!/usr/bin/env python3
"""
scout.py
Single-file CLI for Scout (passive recon + basic checks).
Usage:
  python scout.py scan example.com -o scout_output
  or via batch wrapper: scout scan example.com -o scout_output
"""

import argparse
import csv
import json
import random
import socket
import string
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict
from urllib.parse import quote_plus

import dns.resolver
import requests
from colorama import init, Fore
from tqdm import tqdm

init(autoreset=True)

# ---------------- Banner ----------------
def print_banner():
    # Enhanced banner with properly aligned ASCII art
    banner = f"""
{Fore.CYAN}{'='*60}
{Fore.RED}💻 🔍 ⚡ 🛡️  👨‍💻 💀 🔒 ⚡ 🔍 💻 🔍 ⚡ 🛡️  👨‍💻 💀 🔒 💻

{Fore.GREEN}  █████ ██  ██████  ██████  ██    ██ ████████ 
  ██       ██      ██    ██ ██    ██    ██    
  ███████  ██      ██    ██ ██    ██    ██    
       ██  ██      ██    ██ ██    ██    ██    
  ███████   ██████  ██████   ██████     ██    

{Fore.MAGENTA}            🔥 RECONNAISSANCE TOOL 🔥
{Fore.YELLOW}              By Jaideep Raj Dutta

{Fore.RED}💻 🔍 ⚡ 🛡️  👨‍💻 💀 🔒 ⚡ 🔍 💻 🔍 ⚡ 🛡️  👨‍💻 💀 🔒 💻
{Fore.CYAN}{'='*60}
"""
    print(banner)

# ---------------- Config ----------------
CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
THREADS_DEFAULT = 30
HTTP_TIMEOUT = 6
COMMON_BRUTE = ["www", "mail", "api", "dev", "test", "staging", "admin", "portal", "beta"]

# ---------------- Helpers ----------------
def fetch_crtsh(domain: str) -> List[str]:
    """Fetch subdomains from crt.sh certificate transparency logs."""
    try:
        url = CRT_SH_URL.format(domain=quote_plus(domain))
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        
        subdomains = set()
        for entry in data:
            name = entry.get('name_value', '').strip()
            if name:
                # Handle multiple names separated by newlines
                for sub in name.split('\n'):
                    sub = sub.strip().lower()
                    if sub and not sub.startswith('*'):
                        subdomains.add(sub)
        
        return list(subdomains)
    except Exception as e:
        print(Fore.RED + f"[!] Error fetching from crt.sh: {e}")
        return []

def resolve_a(hostname: str) -> List[str]:
    """Resolve A record for hostname."""
    try:
        answers = dns.resolver.resolve(hostname, 'A')
        return [str(rdata) for rdata in answers]
    except:
        return []

def resolve_cname(hostname: str) -> List[str]:
    """Resolve CNAME record for hostname."""
    try:
        answers = dns.resolver.resolve(hostname, 'CNAME')
        return [str(rdata).rstrip('.') for rdata in answers]
    except:
        return []

def random_token(length: int = 10) -> str:
    """Generate random token for wildcard detection."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def detect_wildcard(domain: str) -> tuple:
    """Detect if domain has wildcard DNS configured."""
    random_sub = f"{random_token()}.{domain}"
    ips = resolve_a(random_sub)
    return len(ips) > 0, ips

def score_takeover(cnames: List[str]) -> int:
    """Basic scoring for potential subdomain takeover based on CNAME patterns."""
    takeover_indicators = [
        'amazonaws.com', 'cloudfront.net', 'github.io', 'herokuapp.com',
        'netlify.com', 'surge.sh', 'ghost.io', 'gitbook.com',
        'zendesk.com', 'unbounce.com', 'tumblr.com'
    ]
    
    score = 0
    for cname in cnames:
        for indicator in takeover_indicators:
            if indicator in cname.lower():
                score += 1
                break
    return score

def http_probe(hostname: str) -> Dict:
    """Probe HTTP/HTTPS status for hostname."""
    result = {"hostname": hostname, "http": None, "https": None}
    
    for scheme in ["http", "https"]:
        try:
            url = f"{scheme}://{hostname}"
            resp = requests.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True)
            result[scheme] = {
                "status": resp.status_code,
                "title": "",
                "redirect": url != resp.url
            }
            # Try to extract title
            try:
                import re
                title_match = re.search(r'<title[^>]*>(.*?)</title>', resp.text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    result[scheme]["title"] = title_match.group(1).strip()[:100]
            except:
                pass
        except:
            result[scheme] = None
    
    return result

def aggregate_targets(domain: str, wordlist_path: str = None) -> List[str]:
    """Aggregate target hostnames from various sources."""
    targets = set()
    
    # Add base domain
    targets.add(domain)
    
    # Add common subdomains
    for sub in COMMON_BRUTE:
        targets.add(f"{sub}.{domain}")
    
    # Fetch from crt.sh
    print(Fore.CYAN + "[*] Fetching subdomains from crt.sh...")
    crt_domains = fetch_crtsh(domain)
    targets.update(crt_domains)
    print(Fore.CYAN + f"[+] Found {len(crt_domains)} domains from crt.sh")
    
    # Add from wordlist if provided
    if wordlist_path:
        try:
            with open(wordlist_path, 'r') as f:
                for line in f:
                    sub = line.strip().lower()
                    if sub:
                        targets.add(f"{sub}.{domain}")
            print(Fore.CYAN + f"[+] Added wordlist entries")
        except Exception as e:
            print(Fore.RED + f"[!] Error reading wordlist: {e}")
    
    return list(targets)

def analyze_single_target(hostname: str, wildcard_ips: List[str]) -> Dict:
    """Analyze a single target hostname."""
    result = {
        "hostname": hostname,
        "a_records": [],
        "cnames": [],
        "takeover_score": 0,
        "http_probe": None,
        "is_wildcard": False
    }
    
    # DNS resolution
    a_records = resolve_a(hostname)
    cnames = resolve_cname(hostname)
    
    result["a_records"] = a_records
    result["cnames"] = cnames
    
    # Check if this matches wildcard pattern
    if a_records and wildcard_ips:
        result["is_wildcard"] = set(a_records) == set(wildcard_ips)
    
    # Skip further analysis if it's a wildcard
    if result["is_wildcard"]:
        return result
    
    # Only continue if we have valid DNS records
    if not (a_records or cnames):
        return result
    
    # Takeover scoring
    result["takeover_score"] = score_takeover(cnames)
    
    # HTTP probing
    if a_records:  # Only probe if it resolves
        result["http_probe"] = http_probe(hostname)
    
    return result

def analyze_targets(targets: List[str], wildcard_ips: List[str], threads: int) -> List[Dict]:
    """Analyze multiple targets concurrently."""
    results = []
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Submit all tasks
        future_to_hostname = {
            executor.submit(analyze_single_target, hostname, wildcard_ips): hostname
            for hostname in targets
        }
        
        # Process results with progress bar
        with tqdm(total=len(targets), desc="Analyzing", unit="host") as pbar:
            for future in as_completed(future_to_hostname):
                try:
                    result = future.result()
                    # Only include non-wildcard results with valid DNS records
                    if not result["is_wildcard"] and (result["a_records"] or result["cnames"]):
                        results.append(result)
                except Exception as e:
                    hostname = future_to_hostname[future]
                    print(Fore.RED + f"[!] Error analyzing {hostname}: {e}")
                finally:
                    pbar.update(1)
    
    return results

def save_json(path: str, data: Dict):
    """Save results to JSON file."""
    try:
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(Fore.RED + f"[!] Error saving JSON: {e}")

def save_csv(path: str, results: List[Dict]):
    """Save results to CSV file."""
    try:
        if not results:
            return
        
        with open(path, 'w', newline='') as f:
            fieldnames = ['hostname', 'a_records', 'cnames', 'takeover_score', 'http_status', 'https_status']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                row = {
                    'hostname': result['hostname'],
                    'a_records': ';'.join(result['a_records']),
                    'cnames': ';'.join(result['cnames']),
                    'takeover_score': result['takeover_score'],
                    'http_status': '',
                    'https_status': ''
                }
                
                if result['http_probe']:
                    if result['http_probe']['http']:
                        row['http_status'] = result['http_probe']['http']['status']
                    if result['http_probe']['https']:
                        row['https_status'] = result['http_probe']['https']['status']
                
                writer.writerow(row)
    except Exception as e:
        print(Fore.RED + f"[!] Error saving CSV: {e}")

def save_md(path: str, domain: str, wildcard_info: tuple, results: List[Dict]):
    """Save results to Markdown file."""
    try:
        with open(path, 'w') as f:
            f.write(f"# Scout Report: {domain}\n\n")
            f.write(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            wildcard_detected, wildcard_ips = wildcard_info
            f.write(f"**Wildcard DNS:** {'Yes' if wildcard_detected else 'No'}\n")
            if wildcard_ips:
                f.write(f"**Wildcard IPs:** {', '.join(wildcard_ips)}\n")
            f.write("\n")
            
            f.write(f"## Results ({len(results)} hosts)\n\n")
            
            for result in results:
                f.write(f"### {result['hostname']}\n")
                
                if result['a_records']:
                    f.write(f"**A Records:** {', '.join(result['a_records'])}\n")
                
                if result['cnames']:
                    f.write(f"**CNAME:** {', '.join(result['cnames'])}\n")
                
                if result['takeover_score'] > 0:
                    f.write(f"**Takeover Score:** {result['takeover_score']} ⚠️\n")
                
                if result['http_probe']:
                    probe = result['http_probe']
                    if probe['http']:
                        f.write(f"**HTTP:** {probe['http']['status']}")
                        if probe['http']['title']:
                            f.write(f" - {probe['http']['title']}")
                        f.write("\n")
                    
                    if probe['https']:
                        f.write(f"**HTTPS:** {probe['https']['status']}")
                        if probe['https']['title']:
                            f.write(f" - {probe['https']['title']}")
                        f.write("\n")
                
                f.write("\n")
    except Exception as e:
        print(Fore.RED + f"[!] Error saving Markdown: {e}")

# ---------------- Core flow ----------------
def run_recon_command(domain: str, wordlist: str, outfile_base: str, threads: int):
    start = time.time()
    targets = aggregate_targets(domain, wordlist)
    print(Fore.CYAN + f"[+] Total candidate names: {len(targets)}")
    
    wildcard_detected, wildcard_ips = detect_wildcard(domain)
    print(Fore.CYAN + f"[+] Wildcard detected: {wildcard_detected}; example IPs: {', '.join(wildcard_ips) if wildcard_ips else 'n/a'}")
    
    print(Fore.CYAN + "[*] Analyzing targets (this can take a few seconds)...")
    results = analyze_targets(targets, wildcard_ips, threads)
    print(Fore.CYAN + f"[+] Analysis complete. Found {len(results)} non-wildcard candidates.")
    
    json_path = f"{outfile_base}.json"
    csv_path = f"{outfile_base}.csv"
    md_path = f"{outfile_base}.md"
    
    save_json(json_path, {
        "domain": domain,
        "wildcard": {
            "detected": wildcard_detected,
            "ips": wildcard_ips
        },
        "results": results
    })
    save_csv(csv_path, results)
    save_md(md_path, domain, (wildcard_detected, wildcard_ips), results)
    
    elapsed = time.time() - start
    print(Fore.GREEN + f"[+] Saved JSON -> {json_path}, CSV -> {csv_path}, MD -> {md_path}")
    print(Fore.GREEN + f"[+] Done in {elapsed:.1f}s")

# ---------------- Run / CLI ----------------
def main():
    parser = argparse.ArgumentParser(prog="scout", description="Scout CLI — passive recon + basic takeover checks")
    sub = parser.add_subparsers(dest="cmd", required=True)
    
    p_scan = sub.add_parser("scan", help="Scan a domain")
    p_scan.add_argument("domain", help="domain to scan (you must own or have permission)")
    p_scan.add_argument("-w", "--wordlist", default=None, help="optional wordlist path")
    p_scan.add_argument("-o", "--outfile", default="scout_out", help="base name for outputs")
    p_scan.add_argument("--threads", type=int, default=THREADS_DEFAULT, help="concurrency threads")
    
    args = parser.parse_args()
    
    print_banner()
    if args.cmd == "scan":
        run_recon_command(args.domain.strip().lower(), args.wordlist, args.outfile, args.threads)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + Fore.RED + "[!] Interrupted by user")
        sys.exit(0)
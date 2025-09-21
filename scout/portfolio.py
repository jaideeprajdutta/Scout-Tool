import socket
import json

def run_scan(domain, output=None):
    try:
        ip = socket.gethostbyname(domain)
        result = {"domain": domain, "ip": ip}
        print(f"[+] Domain: {domain}")
        print(f"[+] IP: {ip}")

        if output:
            with open(output, "w") as f:
                json.dump(result, f, indent=2)
            print(f"[+] Results saved to {output}")
    except Exception as e:
        print(f"[!] Error: {e}")

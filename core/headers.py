import requests
from colorama import Fore
from urllib.parse import urlparse

# List of important security headers
SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps prevent XSS and data injection.",
    "Strict-Transport-Security": "Enforces secure (https) connections.",
    "X-Frame-Options": "Prevents clickjacking.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing.",
    "Referrer-Policy": "Controls how much referrer info is sent.",
    "Permissions-Policy": "Restricts access to browser features."
}

def scan(url, timeout=10):
    print(Fore.CYAN + "[*] Scanning for security headers...")

    results = []

    try:
        response = requests.get(url, timeout=timeout)
        headers = response.headers

        for header, description in SECURITY_HEADERS.items():
            if header in headers:
                print(Fore.GREEN + f"[✓] {header} found: {headers[header]}")
                results.append({
                    "name": header,
                    "status": "present",
                    "value": headers[header]
                })
            else:
                print(Fore.RED + f"[!] {header} missing! ({description})")
                results.append({
                    "name": header,
                    "status": "missing",
                    "description": description
                })

    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[!] Failed to connect to {url} for header scan: {e}")

    return results

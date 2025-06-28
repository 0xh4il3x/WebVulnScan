import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style
from urllib.parse import urlparse

def validate_url(url):
    if not url.startswith("http"):
        url = "http://" + url
    return url

def analyze(url, timeout=10):
    url = validate_url(url)
    data = {
        "url": url,
        "status_code": None,
        "title": None,
        "tech": [],
        "reachable": False,
        "error": None
    }

    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        data["status_code"] = response.status_code
        data["reachable"] = True

        print(Fore.GREEN + f"[+] Target is reachable: {url} (Status: {response.status_code})")

        # Extract page title
        soup = BeautifulSoup(response.text, "html.parser")
        title_tag = soup.title.string.strip() if soup.title else "No Title Found"
        data['title'] = title_tag
        print(Fore.CYAN + f"[+] Page Title: {title_tag}" + Style.RESET_ALL)

        # Technology Detection from headers
        server = response.headers.get("Server")
        powered_by = response.headers.get("X-Powered-By")

        if server:
            data["tech"].append(f"Server: {server}")
            print(Fore.MAGENTA + f"[+] Server: {server}" + Style.RESET_ALL)
        if powered_by:
            data["tech"].append(f"Powered By: {powered_by}")
            print(Fore.MAGENTA + f"[+] Powered By: {powered_by}" + Style.RESET_ALL)

    except requests.exceptions.RequestException as e:
        data["error"] = str(e)
        print(Fore.RED + f"[!] Failed to reach {url}: {e}" + Style.RESET_ALL)

    return data

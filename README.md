# WebVulnScan

![banner](https://img.shields.io/badge/WebVulnScan-Penetration%20Testing-blue?style=flat-square)
> 🔍 Lightweight and extensible Web Application Vulnerability Scanner built with Python.

**WebVulnScan** is a modular web vulnerability scanner designed to identify common security misconfigurations, outdated headers, sensitive files, and injection flaws such as XSS and SQLi. Built for learning, rapid prototyping, and extensibility.

---

## ✨ Features

- ✅ **Target Reachability Check** before scanning
- 🕵️ **Reconnaissance**: Extract page titles, tech stack hints from headers
- 🛡 **Security Headers Analysis**: Checks for missing recommended headers
- 💉 **SQL Injection Detection**: Basic GET-based payload injection
- 🔓 **XSS Scanner**: Large set of reflective XSS payloads with validation
- 🔍 **Sensitive File Finder**: Detects exposed `.env`, `.git`, backups, and open directories
- 📄 **Markdown Report Generation** with scan results
- ⏱ **Timeout Customization** for slow targets


---

## ⚙️ Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/webvulnscan.git
cd webvulnscan

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt


🧪 Usage

python3 main.py --url http://example.com

Optional arguments:

Flag	     Description
-u, --url	    Target URL (required)
-o, --output	Output file name (default: scan_report.md)
-t, --timeout	Timeout in seconds for requests (default: 10 seconds)

Example:

python3 main.py --url https://target.com -o/--output result.md -t/--timeout 5


📁 Sample Output

[*] Validating target reachability...
[✓] Target is reachable

[*] Starting Recon...
[+] Page Title: Welcome to Target
[+] Server: Apache
[+] Powered By: PHP/8.1.0

[*] Checking Security Headers...
[✓] X-Content-Type-Options found
[!] Content-Security-Policy missing! (Helps prevent XSS and data injection.)

[*] Testing for SQL Injection...
[!] Potential SQLi found at ?id=...

[*] Testing for XSS...
[!!!] Reflected XSS in parameter 'search' with payload: <svg/onload=alert('XSSTEST123')>

[*] Sensitive Files Scan...
[!!!] Open Directory Detected: https://target.com/.git/



📑 Report Format
Generates a structured scan_report.md:

Recon Summary

Security Headers Table (✓/✗)

SQL Injection Results

XSS Reflections Found

Sensitive Files Detected




🔐 Legal Disclaimer
This tool is intended for educational purposes and authorized security assessments only. Unauthorized use is prohibited.



📌 Roadmap / To-Do
 Add POST-based XSS/SQLi fuzzing

 Support for proxying (e.g., Burp or Caido)

 Full sitemap crawler

 Authentication handling (cookies, tokens)

 JSON & JavaScript endpoint scanning

 CVE lookup & vulnerability database linking



 🧠 Author
Haileamlak Sahle
Passionate Penetration Tester | Ethical Hacker

GitHub: @0xh4il3x
Linkedin:@haileamlaksahle



🤝 Contributions
Pull requests, bug reports, and suggestions are welcome! Please open an issue or fork and submit your changes.




📜 License
MIT License. See LICENSE file.
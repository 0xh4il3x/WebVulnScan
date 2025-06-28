import argparse
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Import core modules
from core import recon, headers, sqli, xss, sensitive_files, utils
from reports import report_generator

# Define the banner
def banner():
    print(Fore.CYAN + Style.BRIGHT + r"""
W     W EEEE BBBB  V     V U   U L    N   N  SSS   CCC  AA  N   N 
W     W E    B   B V     V U   U L    NN  N S     C    A  A NN  N 
W  W  W EEE  BBBB   V   V  U   U L    N N N  SSS  C    AAAA N N N 
 W W W  E    B   B   V V   U   U L    N  NN     S C    A  A N  NN 
  W W   EEEE BBBB     V     UUU  LLLL N   N SSSS   CCC A  A N   N 
                                                   
    """)
    print(Fore.GREEN + "    Web Vulnerability Scanner - by 0xh4il3x\n" + Style.RESET_ALL)

def parse_args():
    parser = argparse.ArgumentParser(description="Web Application Vulnerability Scanner")
    parser.add_argument("-u", "--url", help="Target URL to scan (e.g., https://example.com)", required=True)
    parser.add_argument("-o", "--output", help="Output report file (e.g., report.md)", default="scan_report.md")
    parser.add_argument("-t", "--timeout", help="Request timeout in seconds (default: 10)", type=int, default=10)
    return parser.parse_args()

def main():
    args = parse_args()
    banner()
    target = args.url

    print(Fore.YELLOW + "[*] Validating target reachability...")

    if not utils.is_target_alive(target, args.timeout):
        print(Fore.RED + f"[!] Target {target} is not reachable. Aborting scan.")
        return
    
    print(Fore.YELLOW + f"[*] Starting Recon on target: {target}" + Style.RESET_ALL)
    recon_data = recon.analyze(target, timeout=args.timeout)

    print(Fore.YELLOW + "[*] Checking Security Headers..." + Style.RESET_ALL)
    headers_data = headers.scan(target, timeout=args.timeout)

    print(Fore.YELLOW + "[*] Testing for SQL Injection..." + Style.RESET_ALL)
    sqli_data = sqli.scan(target, timeout=args.timeout)

    print(Fore.YELLOW + "[*] Testing for XSS vulnerabilities..." + Style.RESET_ALL)
    xss_data = xss.scan(target, timeout=args.timeout)

    print(Fore.YELLOW + "[*] Scanning for sensitive files..." + Style.RESET_ALL)
    sensitive_data = sensitive_files.scan(target, timeout=args.timeout)

    print(Fore.YELLOW + "[*] Generating final report..." + Style.RESET_ALL)
    report_generator.generate(
        recon_data=recon_data,
        headers_data=headers_data,
        sqli_data=sqli_data,
        xss_data=xss_data,
        sensitive_files_data=sensitive_data,
        output_path=args.output
    )

    print(Fore.GREEN + f"[✓] Scan complete. Report saved to: {args.output}" + Style.RESET_ALL)

if __name__ == "__main__":
    main()

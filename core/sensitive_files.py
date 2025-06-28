import requests
from urllib.parse import urljoin
from colorama import Fore, Style # Import Style for resetting color

# A comprehensive list of common sensitive files and directories
COMMON_PATHS = [
    # --- Configuration Files & Credentials ---
    ".env",                     # Environment variables (Laravel, Node.js, etc.)
    "config.php",               # PHP configuration
    "wp-config.php",            # WordPress configuration
    "configuration.php",        # Joomla configuration
    "settings.py",              # Django settings
    "web.config",               # ASP.NET configuration
    "application.properties",   # Spring Boot configuration
    "application.yml",          # Spring Boot configuration
    "database.yml",             # Ruby on Rails database config
    "credentials.json",         # Google Cloud/AWS credentials
    "id_rsa",                   # SSH private key (can be directly exposed if web server serves dotfiles)
    "id_rsa.pub",               # SSH public key
    "key.pem",                  # Private key (SSL/TLS or general purpose)
    "certificate.pem",          # Certificate file
    "server.key",               # Server private key
    "server.crt",               # Server certificate
    "client.crt",               # Client certificate
    "passwd",                   # Unix password file (rarely exposed directly)
    "shadow",                   # Unix shadow password file (even rarer)
    "/etc/passwd",              # Absolute path for some server misconfigurations
    "/etc/shadow",
    "composer.json",            # PHP Composer dependencies
    "package.json",             # Node.js/NPM dependencies
    "Gemfile",                  # Ruby Gemfile
    "requirements.txt",         # Python requirements

    # --- Database Backups & Dumps ---
    "db.sql",
    "database.sql",
    "dump.sql",
    "backup.sql",
    "data.sql",
    "db_backup.zip",
    "database_backup.zip",
    "dump.tar.gz",
    "backup.tgz",
    "backup.rar",
    "backup.7z",
    "latest.sql",
    "sqldump.sql",
    "mysql.sql",
    "postgresql.sql",
    "sqlite.db",
    "backup.bak",               # SQL Server backup

    # --- Version Control Systems (exposed repositories) ---
    ".git/",                    # Git repository directory
    ".git/config",              # Git config file (contains remote URLs)
    ".git/HEAD",                # Git HEAD file
    ".git/logs/HEAD",           # Git logs
    ".git/index",               # Git index file
    ".svn/",                    # SVN repository directory
    ".svn/entries",             # SVN entries file
    ".hg/",                     # Mercurial repository directory
    ".bzr/",                    # Bazaar repository directory
    "/.git/logs/HEAD",          # Absolute path for some server configurations

    # --- Backup & Archive Files (various formats) ---
    "backup.zip",
    "website.zip",
    "site.zip",
    "archive.zip",
    "web.zip",
    "www.zip",
    "backup.tar",
    "backup.tar.gz",
    "backup.tgz",
    "backup.rar",
    "backup.7z",
    "data.zip",
    "old.zip",
    "temp.zip",
    "project.zip",
    "upload.zip",
    "files.zip",
    "*.bak",                    # Wildcard for common backup extension 
    "file.bak",                 # Specific common backup file
    "index.php.bak",
    "index.html.bak",

    # --- Logs & Temporary Files ---
    "logs/",
    "error.log",
    "access.log",
    "debug.log",
    "application.log",
    "system.log",
    "install.log",
    "temp/",
    "tmp/",
    ".tmp",                     # Example: file.php.tmp
    "error_log",                # PHP default error log

    # --- Administration & Testing Interfaces/Files ---
    "admin/",
    "admin.php",
    "dashboard/",
    "controlpanel/",
    "phpinfo.php",
    "test/",
    "dev/",
    "debug/",
    "status",                   # Nginx/Apache status page
    "server-status",            # Apache server status
    "console",                  # Laravel / Symfony console
    "phpmyadmin/",              # Common database administration tool
    "adminer.php",              # Single file database administration tool
    "test.php",
    "info.php",
    "backup.php",
    "db_connect.php",           # Common filename for DB connection script
    "connection.php",

    # --- Web Server Specific Files ---
    ".htaccess",                # Apache access control file
    ".htpasswd",                # Apache password file
    "robots.txt",               # Robot exclusion standard file
    "sitemap.xml",              # Sitemap
    "crossdomain.xml",          # Flash cross-domain policy
    "clientaccesspolicy.xml",   # Silverlight cross-domain policy
    "nginx.conf",               # Nginx configuration
    "apache2.conf",             # Apache configuration
    "httpd.conf",               # Apache configuration

    # --- CMS/Framework Specific Paths ---
    # WordPress
    "wp-admin/",
    "wp-includes/",
    "wp-content/",
    "wp-content/uploads/",
    "wp-json/",
    # Joomla
    "administrator/",
    "components/",
    "media/",
    # Drupal
    "sites/default/files/",
    "core/",
    # Laravel
    "storage/logs/",
    "vendor/",
    # Symfony
    "var/log/",
    # Node.js
    "node_modules/",
    "yarn.lock",
    "package-lock.json",
    # Flask/Python
    "app.pyc",                  # Python compiled bytecode
    "__pycache__/",
    "wsgi.py",

    # --- Miscellaneous ---
    "README.md",
    "CHANGELOG.md",
    "INSTALL.md",
    "license.txt",
    "php.ini",                  # PHP configuration file
    "info.txt",
    "notes.txt",
    "api_key.txt",
    "credentials.txt",
    "passwords.txt",
    "userlist.txt",
    "accounts.txt",
    "secret.txt",
    "data.txt",
    "config.txt",
    "url.txt",
    "admin.txt",
    "test.txt",
    "debug.txt",
    "install.txt",
    "logs.txt",
    "access.log",
    "error.log",
    "users.csv",
    "passwords.csv",
    "emails.csv",
    "emails.txt",
    "creditcards.txt",
    "payment_info.txt",
    "dump.txt",
    "private/",                 # Common directory for private files
    "uploads/",                 # Common directory for user uploads
    "files/",                   # Generic files directory
]

def is_directory_listing(response_text):
    """
    Checks if the response text indicates an open directory listing.
    """
    markers = [
        "Index of /",
        "Directory listing for",
        "Parent Directory",
        "Apache/2.4 Server at", # Common Apache directory listing footer
        "nginx/1.18.0",         # Nginx directory listing footer (version may vary)
        "FTP directory",        # Sometimes FTP servers expose HTTP as well
        "<title>Index of /",
        "Name Size Last modified"
    ]
    return any(marker.lower() in response_text.lower() for marker in markers)


def scan(base_url, timeout=10):
    """
    Scans a given base URL for common sensitive files and open directories.
    Returns a list of structured findings.
    """
    print(Fore.CYAN + "[*] Scanning for sensitive files and open directories..." + Style.RESET_ALL)

    if not base_url.endswith('/'):
        base_url += '/'

    findings = []

    for path in COMMON_PATHS:
        target_url = urljoin(base_url, path)

        try:
            print(Fore.BLUE + f"[*] Checking: {target_url}" + Style.RESET_ALL)
            response = requests.get(target_url, timeout=timeout, allow_redirects=True)
            code = response.status_code

            if code == 200:
                if is_directory_listing(response.text):
                    print(Fore.RED + f"[!!!] Open Directory Detected: {target_url}" + Style.RESET_ALL)
                    findings.append({
                        "type": "Open Directory",
                        "path": path,
                        "url": target_url,
                        "status": 200
                    })
                else:
                    is_not_found_content = any(
                        phrase in response.text.lower() for phrase in ["not found", "page not found", "error 404"]
                    )
                    if not is_not_found_content and len(response.text) > 50:
                        print(Fore.RED + f"[!!!] Found Sensitive File/Resource: {target_url} (Status: 200)" + Style.RESET_ALL)
                        findings.append({
                            "type": "Sensitive File",
                            "path": path,
                            "url": target_url,
                            "status": 200
                        })
                    else:
                        print(Fore.GREEN + f"[-] Found (but likely benign/empty): {target_url} (Status: 200)" + Style.RESET_ALL)

            elif code in [401, 403]:
                print(Fore.YELLOW + f"[-] Forbidden/Protected: {target_url} (Status: {code})" + Style.RESET_ALL)
                findings.append({
                    "type": "Access Denied",
                    "path": path,
                    "url": target_url,
                    "status": code
                })

            elif code == 404:
                print(Fore.GREEN + f"[-] Not Found: {target_url} (Status: 404)" + Style.RESET_ALL)

            elif code == 500:
                print(Fore.MAGENTA + f"[!] Server error on: {target_url} (Status: 500)" + Style.RESET_ALL)
                findings.append({
                    "type": "Server Error",
                    "path": path,
                    "url": target_url,
                    "status": 500
                })

            elif 300 <= code < 400:
                print(Fore.BLUE + f"[i] Redirect found: {target_url} (Status: {code} -> {response.headers.get('Location', 'N/A')})" + Style.RESET_ALL)

            else:
                print(Fore.WHITE + f"[?] Unexpected Status: {target_url} (Status: {code})" + Style.RESET_ALL)

        except requests.exceptions.Timeout:
            print(Fore.YELLOW + f"[!] Request timed out for {target_url}" + Style.RESET_ALL)
        except requests.exceptions.ConnectionError:
            print(Fore.RED + f"[!] Connection error to {target_url}. Host might be down or blocked." + Style.RESET_ALL)
            break
        except requests.exceptions.RequestException as e:
            print(Fore.RED + f"[!] An unexpected error occurred for {target_url}: {e}" + Style.RESET_ALL)

    return findings
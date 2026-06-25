import requests

# ────────────────────────────────────────────
#  HEADERS SCANNER
#  Checks the target URL's HTTP response headers
#  for missing or misconfigured security headers.
# ────────────────────────────────────────────

# Every header we check, with its severity and remediation advice
SECURITY_HEADERS = [
    {
        "header":      "Content-Security-Policy",
        "severity":    "high",
        "title":       "Missing Content-Security-Policy header",
        "description": "No CSP header found. Without CSP, browsers allow inline scripts "
                       "and resources from any origin, greatly expanding the XSS attack surface.",
        "remediation": "Add: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'"
    },
    {
        "header":      "Strict-Transport-Security",
        "severity":    "medium",
        "title":       "Missing Strict-Transport-Security (HSTS) header",
        "description": "HSTS is not set. Users who visit via HTTP are not automatically "
                       "upgraded to HTTPS on return visits, leaving them open to downgrade attacks.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    {
        "header":      "X-Frame-Options",
        "severity":    "medium",
        "title":       "Missing X-Frame-Options header",
        "description": "The page can be embedded in an iframe on any domain, "
                       "making it vulnerable to clickjacking attacks.",
        "remediation": "Add: X-Frame-Options: DENY  (or SAMEORIGIN if you need iframes on your own domain)"
    },
    {
        "header":      "X-Content-Type-Options",
        "severity":    "low",
        "title":       "Missing X-Content-Type-Options header",
        "description": "Without this header, browsers may MIME-sniff responses and "
                       "interpret non-script files as executable scripts.",
        "remediation": "Add: X-Content-Type-Options: nosniff"
    },
    {
        "header":      "Referrer-Policy",
        "severity":    "low",
        "title":       "Missing Referrer-Policy header",
        "description": "Without a Referrer-Policy, full URLs (including sensitive paths "
                       "and query strings) may be sent to third-party sites in the Referer header.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    {
        "header":      "Permissions-Policy",
        "severity":    "low",
        "title":       "Missing Permissions-Policy header",
        "description": "No Permissions-Policy header found. This header lets you restrict "
                       "access to browser features like camera, microphone, and geolocation.",
        "remediation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"
    },
    {
        "header":      "X-XSS-Protection",
        "severity":    "info",
        "title":       "Missing X-XSS-Protection header",
        "description": "X-XSS-Protection is a legacy header for older browsers. "
                       "Modern browsers use CSP instead, but setting this provides a fallback.",
        "remediation": "Add: X-XSS-Protection: 1; mode=block  (and prioritise a strong CSP)"
    },
]


def scan_headers(url: str) -> list:
    """
    Fetches the target URL and checks for missing security headers.

    Returns a list of finding dicts, one per missing header.
    Returns an error finding if the URL cannot be reached.
    """
    findings = []

    # ── Step 1: Fetch the target URL ──
    try:
        response = requests.get(
            url,
            timeout=10,                # don't wait forever
            allow_redirects=True,      # follow redirects (e.g. http -> https)
            headers={
                # Identify ourselves as a scanner, not a browser
                "User-Agent": "VulnScan-SecurityScanner/1.0"
            }
        )
    except requests.exceptions.ConnectionError:
        return [{
            "severity":    "info",
            "module":      "Headers",
            "title":       "Could not connect to target",
            "description": f"The scanner could not reach {url}. The server may be offline or blocking requests.",
            "evidence":    f"Connection refused or DNS resolution failed for {url}",
            "remediation": "Verify the URL is correct and the server is reachable."
        }]
    except requests.exceptions.Timeout:
        return [{
            "severity":    "info",
            "module":      "Headers",
            "title":       "Connection timed out",
            "description": f"The request to {url} timed out after 10 seconds.",
            "evidence":    f"Timeout on GET {url}",
            "remediation": "Check if the server is responding. Try again later."
        }]
    except Exception as e:
        return [{
            "severity":    "info",
            "module":      "Headers",
            "title":       "Unexpected error during header scan",
            "description": str(e),
            "evidence":    f"Error on GET {url}",
            "remediation": "Check the URL and try again."
        }]

    # ── Step 2: Get actual headers from response ──
    # Convert to lowercase keys so comparison is case-insensitive
    actual_headers = {k.lower(): v for k, v in response.headers.items()}

    print(f"[Headers] Scanned {url} -- Status: {response.status_code}")
    print(f"[Headers] Found headers: {list(actual_headers.keys())}")

    # ── Step 3: Check each required security header ──
    for check in SECURITY_HEADERS:
        header_name = check["header"].lower()

        if header_name not in actual_headers:
            # Header is MISSING -- add a finding
            findings.append({
                "severity":    check["severity"],
                "module":      "Headers",
                "title":       check["title"],
                "description": check["description"],
                "evidence":    f"GET {url} (HTTP {response.status_code}) -- "
                               f"No '{check['header']}' header in response",
                "remediation": check["remediation"]
            })
            print(f"[Headers] MISSING: {check['header']}")
        else:
            print(f"[Headers] OK: {check['header']} = {actual_headers[header_name]}")

    # ── Step 4: Extra check — is the site using HTTPS? ──
    if url.startswith("http://"):
        findings.append({
            "severity":    "high",
            "module":      "Headers",
            "title":       "Site served over HTTP (not HTTPS)",
            "description": "The target is accessible over plain HTTP. All traffic is unencrypted "
                           "and vulnerable to man-in-the-middle attacks.",
            "evidence":    f"GET {url} returned HTTP {response.status_code} over unencrypted connection",
            "remediation": "Obtain an SSL/TLS certificate (free via Let's Encrypt) and redirect all "
                           "HTTP traffic to HTTPS."
        })

    # ── Step 5: Check for server version disclosure ──
    server_header = actual_headers.get("server", "")
    if any(char.isdigit() for char in server_header):
        findings.append({
            "severity":    "low",
            "module":      "Headers",
            "title":       "Server version disclosed in headers",
            "description": f"The server header reveals version information: '{server_header}'. "
                           "This helps attackers identify known vulnerabilities for your specific version.",
            "evidence":    f"Response header -- Server: {server_header}",
            "remediation": "Configure your web server to hide version information. "
                           "In Apache: ServerTokens Prod. In Nginx: server_tokens off."
        })

    if not findings:
        findings.append({
            "severity":    "info",
            "module":      "Headers",
            "title":       "All security headers present",
            "description": "The target has all recommended security headers configured correctly.",
            "evidence":    f"GET {url} -- All headers found",
            "remediation": "No action needed. Review header values periodically."
        })

    return findings


# ────────────────────────────────────────────
#  QUICK TEST
#  Run this file directly to test the scanner:
#  python headers.py
# ────────────────────────────────────────────
if __name__ == "__main__":
    import json

    test_url = "https://example.com"
    print(f"\nScanning: {test_url}\n" + "-" * 40)

    results = scan_headers(test_url)

    print(f"\n{'='*40}")
    print(f"Found {len(results)} findings:\n")
    for i, f in enumerate(results, 1):
        print(f"[{i}] [{f['severity'].upper()}] {f['title']}")
        print(f"     Evidence:    {f['evidence']}")
        print(f"     Remediation: {f['remediation']}\n")

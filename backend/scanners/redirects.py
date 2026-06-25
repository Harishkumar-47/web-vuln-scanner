import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, urlencode, parse_qs

# ────────────────────────────────────────────
#  OPEN REDIRECT SCANNER
#  Tests URL parameters and form actions for
#  unvalidated redirect vulnerabilities.
# ────────────────────────────────────────────

# External domains used as redirect targets in payloads
REDIRECT_TEST_DOMAINS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com/phish",
    "//evil.com%2F",
    "https:evil.com",
    "/\\evil.com",
]

# Common parameter names that often control redirects
REDIRECT_PARAMS = [
    "next", "url", "redirect", "redirect_url", "return",
    "return_url", "returnUrl", "goto", "dest", "destination",
    "target", "redir", "ref", "referer", "forward", "location",
    "continue", "path", "callback", "successUrl", "failureUrl",
]


def extract_redirect_params(url: str) -> list:
    """
    Returns list of query param names from the URL that match
    known redirect parameter names.
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    found  = []
    for p in params:
        if p.lower() in [r.lower() for r in REDIRECT_PARAMS]:
            found.append(p)
    return found


def test_url_redirect_params(url: str, session: requests.Session) -> list:
    """
    Injects redirect payloads into known redirect parameters
    in the URL query string and checks if the response
    Location header points to an external domain.
    """
    findings = []
    parsed   = urlparse(url)
    params   = parse_qs(parsed.query)

    # Test both existing redirect params AND add common redirect params
    params_to_test = list(params.keys()) + [
        p for p in REDIRECT_PARAMS if p not in params
    ]

    for param in params_to_test:
        for payload in REDIRECT_TEST_DOMAINS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload

            test_url = parsed._replace(query=urlencode(test_params)).geturl()

            try:
                resp = session.get(
                    test_url,
                    timeout=10,
                    allow_redirects=False   # IMPORTANT: don't follow redirect, just inspect it
                )

                # Check if response is a redirect (3xx)
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    location_host = urlparse(location).netloc

                    # If redirect goes to an external domain — vulnerable!
                    if location_host and location_host not in urlparse(url).netloc:
                        findings.append({
                            "severity":    "high",
                            "module":      "Redirects",
                            "title":       f"Open Redirect via '{param}' parameter",
                            "description": f"The '{param}' parameter accepts external URLs without "
                                           f"validation. An attacker can craft a link that redirects "
                                           f"users to a phishing or malware site after they click a "
                                           f"legitimate-looking URL on your domain.",
                            "evidence":    f"GET {test_url} -- HTTP {resp.status_code} "
                                           f"Location: {location}",
                            "remediation": "Validate redirect targets against an allowlist of your own "
                                           "domains. Reject any URL that is not a relative path or "
                                           "does not belong to your domain. Never trust user-supplied "
                                           "redirect destinations."
                        })
                        return findings   # one finding is enough
            except Exception:
                continue

    return findings


def get_page_links(url: str, session: requests.Session) -> list:
    """
    Fetches the page and extracts all anchor href links
    that contain common redirect parameter names.
    """
    try:
        resp  = session.get(url, timeout=10)
        soup  = BeautifulSoup(resp.text, "html.parser")
        links = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            full = urljoin(url, href)
            # Only keep links that have redirect-like params
            parsed = urlparse(full)
            params = parse_qs(parsed.query)
            for p in params:
                if p.lower() in [r.lower() for r in REDIRECT_PARAMS]:
                    links.append(full)
                    break
        return list(set(links))   # deduplicate
    except Exception:
        return []


def test_links_for_redirect(url: str, session: requests.Session) -> list:
    """
    Finds links on the page that contain redirect parameters
    and tests each one for open redirect.
    """
    findings = []
    links    = get_page_links(url, session)

    print(f"[Redirects] Found {len(links)} links with redirect params")

    for link in links[:10]:   # limit to 10 links to avoid flooding
        result = test_url_redirect_params(link, session)
        findings.extend(result)
        if findings:
            break   # stop after first confirmed finding

    return findings


def scan_redirects(url: str) -> list:
    """
    Main open redirect scanner entry point.
    Tests the URL itself and all links found on the page.
    """
    findings = []
    session  = requests.Session()
    session.headers.update({"User-Agent": "VulnScan-SecurityScanner/1.0"})

    print(f"[Redirects] Starting scan on {url}")

    # Test 1 -- inject redirect params directly into the main URL
    direct = test_url_redirect_params(url, session)
    findings.extend(direct)
    print(f"[Redirects] Direct param test: {len(direct)} findings")

    # Test 2 -- find links on the page with redirect params and test them
    if not findings:
        link_findings = test_links_for_redirect(url, session)
        findings.extend(link_findings)
        print(f"[Redirects] Link test: {len(link_findings)} findings")

    if not findings:
        findings.append({
            "severity":    "info",
            "module":      "Redirects",
            "title":       "No open redirect detected",
            "description": "No unvalidated redirect parameters were found or exploitable. "
                           "Common redirect parameter names were tested with external payloads.",
            "evidence":    f"Tested {len(REDIRECT_TEST_DOMAINS)} payloads on "
                           f"{len(REDIRECT_PARAMS)} common redirect param names at {url}",
            "remediation": "Keep validating redirect destinations server-side against an allowlist."
        })

    return findings


# ── Quick test ──
if __name__ == "__main__":
    test_url = "https://example.com"
    print(f"\nRedirect Scan: {test_url}\n" + "-"*40)
    results = scan_redirects(test_url)
    for i, f in enumerate(results, 1):
        print(f"[{i}] [{f['severity'].upper()}] {f['title']}")
        print(f"     {f['evidence']}\n")

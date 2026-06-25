import requests
from bs4 import BeautifulSoup
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

# ────────────────────────────────────────────
#  XSS SCANNER
#  Tests query parameters and HTML form inputs
#  for reflected Cross-Site Scripting (XSS).
# ────────────────────────────────────────────

# Payloads to inject — each one tests a different bypass technique
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
]

# Strings that confirm a payload was reflected (not filtered)
XSS_SIGNATURES = [
    "<script>alert",
    "onerror=alert",
    "onload=alert",
    "javascript:alert",
    "<svg onload",
]


def get_all_forms(url: str, session: requests.Session) -> list:
    """
    Fetches the page and extracts all HTML forms with their
    action URL, method (GET/POST), and input fields.
    """
    try:
        resp = session.get(url, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            action  = form.get("action", "")
            method  = form.get("method", "get").lower()
            inputs  = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inp_type  = inp.get("type", "text")
                inp_name  = inp.get("name")
                inp_value = inp.get("value", "test")
                if inp_name:
                    inputs.append({
                        "type":  inp_type,
                        "name":  inp_name,
                        "value": inp_value
                    })
            forms.append({
                "action": urljoin(url, action) if action else url,
                "method": method,
                "inputs": inputs
            })
        return forms
    except Exception:
        return []


def test_xss_in_url_params(url: str, session: requests.Session) -> list:
    """
    Injects XSS payloads into existing URL query parameters.
    e.g. if URL is /?q=hello, tests /?q=<script>alert(1)</script>
    """
    findings = []
    parsed   = urlparse(url)
    params   = parse_qs(parsed.query)

    if not params:
        return findings   # no query params to test

    for param_name in params:
        for payload in XSS_PAYLOADS:
            # Build new params with payload injected into this param
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = payload
            test_url = parsed._replace(query=urlencode(test_params)).geturl()

            try:
                resp = session.get(test_url, timeout=10)
                for sig in XSS_SIGNATURES:
                    if sig.lower() in resp.text.lower():
                        findings.append({
                            "severity":    "critical",
                            "module":      "XSS",
                            "title":       f"Reflected XSS in URL parameter '{param_name}'",
                            "description": f"The '{param_name}' query parameter reflects "
                                           f"unsanitized input directly into the HTML response.",
                            "evidence":    f"GET {test_url} -- payload '{payload}' reflected in response",
                            "remediation": "Encode all user-supplied input before rendering in HTML. "
                                           "Use a CSP header. Apply output encoding with DOMPurify on frontend."
                        })
                        return findings   # one finding per param is enough
            except Exception:
                continue

    return findings


def test_xss_in_forms(url: str, session: requests.Session) -> list:
    """
    Finds all forms on the page and submits XSS payloads
    into every text input field, checking if the payload
    is reflected back in the response.
    """
    findings = []
    forms    = get_all_forms(url, session)

    for form in forms:
        for payload in XSS_PAYLOADS:
            # Fill all inputs with the payload
            data = {}
            for inp in form["inputs"]:
                if inp["type"] in ("text", "search", "email", "url", "textarea", ""):
                    data[inp["name"]] = payload
                else:
                    data[inp["name"]] = inp["value"]   # keep defaults for hidden/submit

            try:
                if form["method"] == "post":
                    resp = session.post(form["action"], data=data, timeout=10)
                else:
                    resp = session.get(form["action"], params=data, timeout=10)

                for sig in XSS_SIGNATURES:
                    if sig.lower() in resp.text.lower():
                        input_names = [i["name"] for i in form["inputs"]]
                        findings.append({
                            "severity":    "critical",
                            "module":      "XSS",
                            "title":       "Reflected XSS in HTML form",
                            "description": f"A form at '{form['action']}' reflects unsanitized "
                                           f"user input back in the response, enabling script injection.",
                            "evidence":    f"{form['method'].upper()} {form['action']} "
                                           f"with fields {input_names} -- payload '{payload}' reflected",
                            "remediation": "Sanitize and encode all form inputs server-side before "
                                           "rendering. Use parameterized templates. Add a CSP header."
                        })
                        return findings   # one XSS form finding is enough
            except Exception:
                continue

    return findings


def scan_xss(url: str) -> list:
    """
    Main XSS scanner entry point.
    Tests both URL parameters and HTML forms for reflected XSS.
    """
    findings = []
    session  = requests.Session()
    session.headers.update({"User-Agent": "VulnScan-SecurityScanner/1.0"})

    print(f"[XSS] Starting scan on {url}")

    # Test 1 — URL query parameters
    url_findings = test_xss_in_url_params(url, session)
    findings.extend(url_findings)
    print(f"[XSS] URL param test: {len(url_findings)} findings")

    # Test 2 — HTML form inputs
    form_findings = test_xss_in_forms(url, session)
    findings.extend(form_findings)
    print(f"[XSS] Form test: {len(form_findings)} findings")

    if not findings:
        findings.append({
            "severity":    "info",
            "module":      "XSS",
            "title":       "No reflected XSS detected",
            "description": "No XSS payloads were reflected in URL parameters or form inputs. "
                           "This does not rule out stored or DOM-based XSS.",
            "evidence":    f"Tested {len(XSS_PAYLOADS)} payloads on URL params and forms at {url}",
            "remediation": "Continue to sanitize all user input. Consider a manual review for DOM XSS."
        })

    return findings


# ── Quick test ──
if __name__ == "__main__":
    test_url = "https://example.com"
    print(f"\nXSS Scan: {test_url}\n" + "-"*40)
    results = scan_xss(test_url)
    for i, f in enumerate(results, 1):
        print(f"[{i}] [{f['severity'].upper()}] {f['title']}")
        print(f"     {f['evidence']}\n")

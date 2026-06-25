import requests
from bs4 import BeautifulSoup
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

# ────────────────────────────────────────────
#  SQL INJECTION SCANNER
#  Tests URL parameters and form inputs for
#  error-based SQL injection vulnerabilities.
# ────────────────────────────────────────────

# Classic SQLi probe payloads
SQLI_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR 1=1--',
    "' AND 1=2--",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    "'; DROP TABLE users--",
]

# Database error messages that confirm SQLi vulnerability
SQLI_SIGNATURES = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    # PostgreSQL
    "pg_query",
    "psql error",
    "postgresql",
    # SQLite
    "sqlite_",
    "sqlite3.",
    # MSSQL
    "unclosed quotation mark",
    "microsoft sql",
    "odbc sql server",
    "syntax error converting",
    # Oracle
    "ora-01756",
    "oracle error",
    # Generic
    "sql syntax",
    "sql error",
    "syntax error",
    "database error",
    "query failed",
    "db error",
]


def get_forms(url: str, session: requests.Session) -> list:
    """Extract all forms from the page (same helper as XSS scanner)."""
    try:
        resp = session.get(url, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            inputs = []
            for inp in form.find_all(["input", "textarea"]):
                name  = inp.get("name")
                value = inp.get("value", "1")
                itype = inp.get("type", "text")
                if name:
                    inputs.append({"name": name, "value": value, "type": itype})
            forms.append({
                "action": urljoin(url, action) if action else url,
                "method": method,
                "inputs": inputs
            })
        return forms
    except Exception:
        return []


def has_sqli_error(response_text: str) -> str | None:
    """
    Checks if the response contains any known database error message.
    Returns the matched signature string if found, else None.
    """
    lower = response_text.lower()
    for sig in SQLI_SIGNATURES:
        if sig in lower:
            return sig
    return None


def test_sqli_in_url_params(url: str, session: requests.Session) -> list:
    """
    Injects SQLi payloads into URL query parameters and checks
    if the response contains database error messages.
    """
    findings = []
    parsed   = urlparse(url)
    params   = parse_qs(parsed.query)

    if not params:
        return findings

    for param_name in params:
        for payload in SQLI_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = payload
            test_url = parsed._replace(query=urlencode(test_params)).geturl()

            try:
                resp      = session.get(test_url, timeout=10)
                matched   = has_sqli_error(resp.text)

                if matched:
                    findings.append({
                        "severity":    "critical",
                        "module":      "SQLi",
                        "title":       f"SQL Injection in URL parameter '{param_name}'",
                        "description": f"The '{param_name}' parameter is vulnerable to error-based "
                                       f"SQL injection. A database error was triggered by a probe payload.",
                        "evidence":    f"GET {test_url} -- payload '{payload}' triggered error: '{matched}'",
                        "remediation": "Use parameterized queries or prepared statements. "
                                       "Never concatenate user input into SQL strings. "
                                       "Consider using an ORM like SQLAlchemy."
                    })
                    return findings
            except Exception:
                continue

    return findings


def test_sqli_in_forms(url: str, session: requests.Session) -> list:
    """
    Submits SQLi payloads into HTML form fields and checks
    the response for database error signatures.
    """
    findings = []
    forms    = get_forms(url, session)

    for form in forms:
        for payload in SQLI_PAYLOADS:
            data = {}
            for inp in form["inputs"]:
                if inp["type"] in ("text", "email", "search", "password", ""):
                    data[inp["name"]] = payload
                else:
                    data[inp["name"]] = inp["value"]

            try:
                if form["method"] == "post":
                    resp = session.post(form["action"], data=data, timeout=10)
                else:
                    resp = session.get(form["action"], params=data, timeout=10)

                matched = has_sqli_error(resp.text)
                if matched:
                    input_names = [i["name"] for i in form["inputs"]]
                    findings.append({
                        "severity":    "critical",
                        "module":      "SQLi",
                        "title":       "SQL Injection in HTML form",
                        "description": f"A form at '{form['action']}' is vulnerable to SQL injection. "
                                       f"A database error was returned when a probe payload was submitted.",
                        "evidence":    f"{form['method'].upper()} {form['action']} "
                                       f"fields={input_names} payload='{payload}' -- error: '{matched}'",
                        "remediation": "Use parameterized queries or prepared statements. "
                                       "Validate and sanitize all form inputs server-side. "
                                       "Display generic error messages — never raw database errors."
                    })
                    return findings
            except Exception:
                continue

    return findings


def scan_sqli(url: str) -> list:
    """
    Main SQLi scanner entry point.
    Tests both URL parameters and HTML forms.
    """
    findings = []
    session  = requests.Session()
    session.headers.update({"User-Agent": "VulnScan-SecurityScanner/1.0"})

    print(f"[SQLi] Starting scan on {url}")

    url_findings  = test_sqli_in_url_params(url, session)
    findings.extend(url_findings)
    print(f"[SQLi] URL param test: {len(url_findings)} findings")

    form_findings = test_sqli_in_forms(url, session)
    findings.extend(form_findings)
    print(f"[SQLi] Form test: {len(form_findings)} findings")

    if not findings:
        findings.append({
            "severity":    "info",
            "module":      "SQLi",
            "title":       "No error-based SQL injection detected",
            "description": "No database error messages were triggered by probe payloads. "
                           "This does not rule out blind or time-based SQLi.",
            "evidence":    f"Tested {len(SQLI_PAYLOADS)} payloads on URL params and forms at {url}",
            "remediation": "Continue using parameterized queries. Consider a manual test for blind SQLi."
        })

    return findings


# ── Quick test ──
if __name__ == "__main__":
    test_url = "https://example.com"
    print(f"\nSQLi Scan: {test_url}\n" + "-"*40)
    results = scan_sqli(test_url)
    for i, f in enumerate(results, 1):
        print(f"[{i}] [{f['severity'].upper()}] {f['title']}")
        print(f"     {f['evidence']}\n")

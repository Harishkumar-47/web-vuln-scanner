from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import List, Optional
import uuid
import time
import asyncio
from datetime import datetime

# ── Import scanner modules (we will build these next) ──
# from scanners.headers   import scan_headers
# from scanners.xss       import scan_xss
# from scanners.sqli      import scan_sqli
# from scanners.redirects import scan_redirects

# ────────────────────────────────────────────
#  APP SETUP
# ────────────────────────────────────────────
app = FastAPI(
    title="VulnScan API",
    description="Web Vulnerability Scanner Backend",
    version="1.0.0"
)

# Allow frontend (running on Live Server port 5500) to talk to this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5500", "http://127.0.0.1:5500"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ────────────────────────────────────────────
#  IN-MEMORY STORAGE (replace with MongoDB later)
#  Stores scan jobs: { scan_id: { status, results } }
# ────────────────────────────────────────────
scan_store = {}

# ────────────────────────────────────────────
#  REQUEST / RESPONSE MODELS
# ────────────────────────────────────────────

class ScanRequest(BaseModel):
    url: str                        # target URL to scan
    modules: List[str]              # e.g. ["xss", "sqli", "headers", "redirects"]

class Finding(BaseModel):
    severity: str                   # critical | high | medium | low | info
    module: str                     # which scanner found this
    title: str
    description: str
    evidence: str
    remediation: str

class ScanResponse(BaseModel):
    scan_id: str
    status: str                     # queued | running | complete | error
    url: str
    started_at: str
    completed_at: Optional[str]
    risk_score: Optional[int]
    findings: Optional[List[Finding]]


# ────────────────────────────────────────────
#  PRIVATE HELPERS
# ────────────────────────────────────────────

BLOCKED_HOSTS = [
    "localhost", "127.0.0.1", "0.0.0.0",
    "::1", "169.254.", "192.168.", "10.", "172.16."
]

def is_safe_url(url: str) -> bool:
    """Block private/loopback IPs to prevent SSRF attacks."""
    for blocked in BLOCKED_HOSTS:
        if blocked in url:
            return False
    return True

def calculate_risk_score(findings: list) -> int:
    """
    Score 0-100 based on findings severity.
    Critical = 25pts, High = 15pts, Medium = 8pts, Low = 3pts
    """
    weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
    score = sum(weights.get(f["severity"], 0) for f in findings)
    return min(score, 100)   # cap at 100

def run_mock_scanner(url: str, modules: List[str]) -> List[dict]:
    """
    MOCK scanner — returns fake findings so you can test the
    full pipeline before the real scanner modules are written.
    Replace this function body with real scanner calls later.
    """
    findings = []

    if "headers" in modules:
        findings += [
            {
                "severity": "high",
                "module": "Headers",
                "title": "Missing Content-Security-Policy header",
                "description": "No CSP header found on the target. This allows inline scripts from any origin.",
                "evidence": f"GET {url} → Response has no Content-Security-Policy header",
                "remediation": "Add: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'"
            },
            {
                "severity": "medium",
                "module": "Headers",
                "title": "Missing X-Frame-Options header",
                "description": "The page can be embedded in iframes, enabling clickjacking attacks.",
                "evidence": f"GET {url} → No X-Frame-Options header in response",
                "remediation": "Add: X-Frame-Options: DENY to all HTTP responses"
            },
            {
                "severity": "low",
                "module": "Headers",
                "title": "Missing Strict-Transport-Security",
                "description": "HSTS not set. Users are not forced to HTTPS on return visits.",
                "evidence": f"GET {url} → No Strict-Transport-Security header",
                "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
            }
        ]

    if "xss" in modules:
        findings += [
            {
                "severity": "critical",
                "module": "XSS",
                "title": "Reflected XSS in query parameter",
                "description": "User input in the 'q' parameter is reflected unsanitized into the HTML response.",
                "evidence": f"GET {url}?q=<script>alert(1)</script> → payload reflected in response body",
                "remediation": "Sanitize and encode all user input before rendering. Use DOMPurify on frontend."
            }
        ]

    if "sqli" in modules:
        findings += [
            {
                "severity": "high",
                "module": "SQLi",
                "title": "SQL Injection in search field",
                "description": "The search parameter is vulnerable to error-based SQL injection.",
                "evidence": f"GET {url}?search=' OR 1=1-- → MySQL syntax error in response",
                "remediation": "Use parameterized queries. Never concatenate user input into SQL strings."
            }
        ]

    if "redirects" in modules:
        findings += [
            {
                "severity": "medium",
                "module": "Redirects",
                "title": "Open redirect via 'next' parameter",
                "description": "The 'next' parameter accepts external URLs without validation.",
                "evidence": f"GET {url}/login?next=https://evil.com → 302 redirect to evil.com",
                "remediation": "Validate redirect targets against an allowlist of your own domains only."
            }
        ]

    return findings


# ────────────────────────────────────────────
#  BACKGROUND SCAN RUNNER
# ────────────────────────────────────────────

async def run_scan_background(scan_id: str, url: str, modules: List[str]):
    """
    Runs the scan asynchronously so the API doesn't block.
    Updates scan_store as it progresses.
    """
    try:
        scan_store[scan_id]["status"] = "running"

        # Simulate scan delay (remove when using real scanners)
        await asyncio.sleep(2)

        # ── Run scanner modules ──
        # When real modules are ready, replace run_mock_scanner with:
        #
        # findings = []
        # if "headers"   in modules: findings += await scan_headers(url)
        # if "xss"       in modules: findings += await scan_xss(url)
        # if "sqli"      in modules: findings += await scan_sqli(url)
        # if "redirects" in modules: findings += await scan_redirects(url)

        findings = run_mock_scanner(url, modules)
        risk     = calculate_risk_score(findings)

        scan_store[scan_id].update({
            "status":       "complete",
            "completed_at": datetime.now().isoformat(),
            "risk_score":   risk,
            "findings":     findings
        })

    except Exception as e:
        scan_store[scan_id].update({
            "status": "error",
            "error":  str(e)
        })


# ────────────────────────────────────────────
#  ROUTES
# ────────────────────────────────────────────

@app.get("/")
def root():
    """Health check — visit http://localhost:8000 to confirm API is running."""
    return {
        "service": "VulnScan API",
        "status":  "running",
        "version": "1.0.0",
        "docs":    "http://localhost:8000/docs"
    }


@app.post("/api/scan", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def start_scan(request: ScanRequest, background_tasks=Depends(lambda: None)):
    """
    Start a new vulnerability scan.

    - Validates the URL
    - Blocks private/internal IPs (SSRF protection)
    - Creates a scan job and runs it in the background
    - Returns a scan_id immediately so frontend can poll for results
    """

    url = str(request.url).rstrip("/")

    # ── Validation ──
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

    if not is_safe_url(url):
        raise HTTPException(status_code=400, detail="Scanning private or internal IP addresses is not allowed.")

    if not request.modules:
        raise HTTPException(status_code=400, detail="Select at least one scan module.")

    valid_modules = {"xss", "sqli", "headers", "redirects"}
    bad = set(request.modules) - valid_modules
    if bad:
        raise HTTPException(status_code=400, detail=f"Unknown modules: {bad}. Valid: {valid_modules}")

    # ── Create scan job ──
    scan_id = str(uuid.uuid4())
    scan_store[scan_id] = {
        "scan_id":      scan_id,
        "status":       "queued",
        "url":          url,
        "modules":      request.modules,
        "started_at":   datetime.now().isoformat(),
        "completed_at": None,
        "risk_score":   None,
        "findings":     []
    }

    # ── Run in background (non-blocking) ──
    asyncio.create_task(run_scan_background(scan_id, url, request.modules))

    return ScanResponse(
        scan_id    = scan_id,
        status     = "queued",
        url        = url,
        started_at = scan_store[scan_id]["started_at"],
        completed_at = None,
        risk_score = None,
        findings   = []
    )


@app.get("/api/scan/{scan_id}", response_model=ScanResponse)
def get_scan_result(scan_id: str):
    """
    Poll this endpoint with the scan_id to get current status and results.
    Frontend polls every 2 seconds until status = 'complete'.
    """
    if scan_id not in scan_store:
        raise HTTPException(status_code=404, detail="Scan not found. Invalid scan_id.")

    job = scan_store[scan_id]

    return ScanResponse(
        scan_id      = job["scan_id"],
        status       = job["status"],
        url          = job["url"],
        started_at   = job["started_at"],
        completed_at = job.get("completed_at"),
        risk_score   = job.get("risk_score"),
        findings     = [Finding(**f) for f in job.get("findings", [])]
    )


@app.get("/api/scans")
def list_all_scans():
    """
    Returns all scans done in this session.
    In production this would query MongoDB for the user's scan history.
    """
    return {
        "total": len(scan_store),
        "scans": [
            {
                "scan_id":    v["scan_id"],
                "url":        v["url"],
                "status":     v["status"],
                "risk_score": v.get("risk_score"),
                "started_at": v["started_at"]
            }
            for v in scan_store.values()
        ]
    }


@app.delete("/api/scan/{scan_id}")
def delete_scan(scan_id: str):
    """Delete a scan result from memory."""
    if scan_id not in scan_store:
        raise HTTPException(status_code=404, detail="Scan not found.")
    del scan_store[scan_id]
    return {"message": f"Scan {scan_id} deleted."}

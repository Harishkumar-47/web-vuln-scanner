from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import uuid
import asyncio
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Import real scanner modules
from scanners.headers   import scan_headers
from scanners.xss       import scan_xss
from scanners.sqli      import scan_sqli
from scanners.redirects import scan_redirects

# ── APP SETUP ──
app = FastAPI(title="VulnScan API", description="Web Vulnerability Scanner Backend", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5500", "http://127.0.0.1:5500"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

executor   = ThreadPoolExecutor(max_workers=4)
scan_store = {}

# ── MODELS ──
class ScanRequest(BaseModel):
    url:     str
    modules: List[str]

class Finding(BaseModel):
    severity:    str
    module:      str
    title:       str
    description: str
    evidence:    str
    remediation: str

class ScanResponse(BaseModel):
    scan_id:      str
    status:       str
    url:          str
    started_at:   str
    completed_at: Optional[str]
    risk_score:   Optional[int]
    findings:     Optional[List[Finding]]

# ── HELPERS ──
BLOCKED_HOSTS = [
    "localhost", "127.0.0.1", "0.0.0.0",
    "::1", "169.254.", "192.168.", "10.", "172.16."
]

def is_safe_url(url: str) -> bool:
    for blocked in BLOCKED_HOSTS:
        if blocked in url:
            return False
    return True

def calculate_risk_score(findings: list) -> int:
    weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
    score   = sum(weights.get(f.get("severity", "info"), 0) for f in findings)
    return min(score, 100)

# ── SCANNER RUNNER ──
def run_all_modules(url: str, modules: List[str]) -> list:
    findings = []
    if "headers"   in modules:
        print("[main] Running headers scanner...")
        findings += scan_headers(url)
    if "xss"       in modules:
        print("[main] Running XSS scanner...")
        findings += scan_xss(url)
    if "sqli"      in modules:
        print("[main] Running SQLi scanner...")
        findings += scan_sqli(url)
    if "redirects" in modules:
        print("[main] Running redirect scanner...")
        findings += scan_redirects(url)
    return findings

async def run_scan_background(scan_id: str, url: str, modules: List[str]):
    try:
        scan_store[scan_id]["status"] = "running"
        print(f"[main] Scan {scan_id} started for {url}")
        loop     = asyncio.get_event_loop()
        findings = await loop.run_in_executor(executor, run_all_modules, url, modules)
        risk     = calculate_risk_score(findings)
        scan_store[scan_id].update({
            "status":       "complete",
            "completed_at": datetime.now().isoformat(),
            "risk_score":   risk,
            "findings":     findings
        })
        print(f"[main] Scan {scan_id} complete -- {len(findings)} findings, score={risk}")
    except Exception as e:
        scan_store[scan_id].update({"status": "error", "error": str(e)})
        print(f"[main] Scan {scan_id} ERROR: {e}")

# ── ROUTES ──
@app.get("/")
def root():
    return {"service": "VulnScan API", "status": "running", "version": "2.0.0", "docs": "http://localhost:8000/docs"}

@app.post("/api/scan", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def start_scan(request: ScanRequest):
    url = str(request.url).rstrip("/")
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")
    if not is_safe_url(url):
        raise HTTPException(status_code=400, detail="Scanning private/internal IPs is not allowed.")
    if not request.modules:
        raise HTTPException(status_code=400, detail="Select at least one scan module.")
    valid_modules = {"xss", "sqli", "headers", "redirects"}
    bad = set(request.modules) - valid_modules
    if bad:
        raise HTTPException(status_code=400, detail=f"Unknown modules: {bad}")

    scan_id = str(uuid.uuid4())
    scan_store[scan_id] = {
        "scan_id": scan_id, "status": "queued", "url": url,
        "modules": request.modules, "started_at": datetime.now().isoformat(),
        "completed_at": None, "risk_score": None, "findings": []
    }
    asyncio.create_task(run_scan_background(scan_id, url, request.modules))
    return ScanResponse(scan_id=scan_id, status="queued", url=url,
                        started_at=scan_store[scan_id]["started_at"],
                        completed_at=None, risk_score=None, findings=[])

@app.get("/api/scan/{scan_id}", response_model=ScanResponse)
def get_scan_result(scan_id: str):
    if scan_id not in scan_store:
        raise HTTPException(status_code=404, detail="Scan not found.")
    job = scan_store[scan_id]
    return ScanResponse(
        scan_id=job["scan_id"], status=job["status"], url=job["url"],
        started_at=job["started_at"], completed_at=job.get("completed_at"),
        risk_score=job.get("risk_score"),
        findings=[Finding(**f) for f in job.get("findings", [])]
    )

@app.get("/api/scans")
def list_scans():
    return {"total": len(scan_store), "scans": [
        {"scan_id": v["scan_id"], "url": v["url"], "status": v["status"],
         "risk_score": v.get("risk_score"), "started_at": v["started_at"]}
        for v in scan_store.values()
    ]}

@app.delete("/api/scan/{scan_id}")
def delete_scan(scan_id: str):
    if scan_id not in scan_store:
        raise HTTPException(status_code=404, detail="Scan not found.")
    del scan_store[scan_id]
    return {"message": f"Scan {scan_id} deleted."}

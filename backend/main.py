"""
ZeroPath - Autonomous Exploit Chain Generator
Backend API Server
"""
import asyncio
import json
import time
import uuid
from typing import Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import aiofiles
import os

from scanner import VulnerabilityScanner
from chain_ai import ExploitChainAI
from reporter import ReportGenerator

app = FastAPI(title="ZeroPath API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage
scans: dict = {}
connections: dict = {}

# Resource limits
MAX_CONCURRENT_SCANS = 2
current_scans = 0


class ScanRequest(BaseModel):
    target_url: str
    user_id: int
    username: Optional[str] = None


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: int
    findings: list
    attack_chains: list
    created_at: float


async def broadcast_to_user(user_id: int, message: dict):
    """Broadcast message to all WebSocket connections for a user."""
    if user_id in connections:
        for ws in connections[user_id]:
            try:
                await ws.send_json(message)
            except:
                pass


async def run_scan(scan_id: str, target_url: str, user_id: int):
    """Main scan execution with progress updates."""
    global current_scans
    
    scan = scans[scan_id]
    
    try:
        current_scans += 1
        
        # Phase 1: Reconnaissance
        await broadcast_to_user(user_id, {
            "type": "progress",
            "scan_id": scan_id,
            "phase": "reconnaissance",
            "progress": 5,
            "message": "Starting reconnaissance..."
        })
        
        scanner = VulnerabilityScanner(target_url)
        findings = await scanner.run_full_scan(
            progress_callback=lambda p, m: asyncio.create_task(
                broadcast_to_user(user_id, {
                    "type": "progress",
                    "scan_id": scan_id,
                    "phase": "scanning",
                    "progress": int(p * 0.6),
                    "message": m
                })
            )
        )
        
        scan["findings"] = findings
        
        await broadcast_to_user(user_id, {
            "type": "progress",
            "scan_id": scan_id,
            "phase": "analysis",
            "progress": 65,
            "message": f"Found {len(findings)} vulnerabilities. Analyzing attack paths..."
        })
        
        # Phase 2: AI Chain Analysis
        chain_ai = ExploitChainAI()
        attack_chains = await chain_ai.generate_chains(
            findings,
            progress_callback=lambda p, m: asyncio.create_task(
                broadcast_to_user(user_id, {
                    "type": "progress",
                    "scan_id": scan_id,
                    "phase": "chain_analysis",
                    "progress": int(65 + p * 0.25),
                    "message": m
                })
            )
        )
        
        scan["attack_chains"] = attack_chains
        
        await broadcast_to_user(user_id, {
            "type": "progress",
            "scan_id": scan_id,
            "phase": "report",
            "progress": 95,
            "message": "Generating report..."
        })
        
        # Phase 3: Generate Report
        reporter = ReportGenerator()
        report_path = await reporter.generate(scan_id, target_url, findings, attack_chains)
        
        scan["report_path"] = report_path
        scan["status"] = "completed"
        scan["progress"] = 100
        
        await broadcast_to_user(user_id, {
            "type": "completed",
            "scan_id": scan_id,
            "progress": 100,
            "findings_count": len(findings),
            "chains_count": len(attack_chains),
            "report_url": f"/api/report/{scan_id}"
        })
        
    except Exception as e:
        scan["status"] = "error"
        scan["error"] = str(e)
        
        await broadcast_to_user(user_id, {
            "type": "error",
            "scan_id": scan_id,
            "message": str(e)
        })
    
    finally:
        current_scans -= 1


@app.post("/api/scan")
async def start_scan(request: ScanRequest):
    """Start a new vulnerability scan."""
    global current_scans
    
    if current_scans >= MAX_CONCURRENT_SCANS:
        raise HTTPException(429, "Too many concurrent scans. Try again later.")
    
    scan_id = str(uuid.uuid4())[:8]
    
    scans[scan_id] = {
        "scan_id": scan_id,
        "target_url": request.target_url,
        "user_id": request.user_id,
        "username": request.username,
        "status": "running",
        "progress": 0,
        "findings": [],
        "attack_chains": [],
        "created_at": time.time()
    }
    
    asyncio.create_task(run_scan(scan_id, request.target_url, request.user_id))
    
    return {"scan_id": scan_id, "status": "started"}


@app.get("/api/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get scan status and results."""
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    
    scan = scans[scan_id]
    return ScanStatus(
        scan_id=scan_id,
        status=scan["status"],
        progress=scan["progress"],
        findings=scan["findings"],
        attack_chains=scan["attack_chains"],
        created_at=scan["created_at"]
    )


@app.get("/api/report/{scan_id}")
async def get_report(scan_id: str):
    """Download scan report."""
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    
    scan = scans[scan_id]
    report_path = scan.get("report_path")
    
    if not report_path or not os.path.exists(report_path):
        raise HTTPException(404, "Report not generated yet")
    
    return FileResponse(report_path, filename=f"zeropath_report_{scan_id}.html")


@app.get("/api/scans")
async def list_scans(user_id: Optional[int] = None):
    """List all scans, optionally filtered by user."""
    result = []
    for scan_id, scan in scans.items():
        if user_id is None or scan["user_id"] == user_id:
            result.append({
                "scan_id": scan_id,
                "target": scan["target_url"],
                "status": scan["status"],
                "progress": scan["progress"],
                "findings_count": len(scan["findings"]),
                "chains_count": len(scan["attack_chains"]),
                "created_at": scan["created_at"]
            })
    return result


@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int):
    """WebSocket for real-time updates."""
    await websocket.accept()
    
    if user_id not in connections:
        connections[user_id] = []
    connections[user_id].append(websocket)
    
    try:
        while True:
            data = await websocket.receive_text()
            # Handle ping/pong
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        connections[user_id].remove(websocket)
        if not connections[user_id]:
            del connections[user_id]


@app.get("/health")
@app.get("/api/health")
async def health():
    return {"status": "ok", "active_scans": current_scans}


# Serve frontend
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

app.mount("/static", StaticFiles(directory="/root/zeropath/frontend"), name="static")

@app.get("/")
async def home():
    return FileResponse("/root/zeropath/frontend/index.html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5002)

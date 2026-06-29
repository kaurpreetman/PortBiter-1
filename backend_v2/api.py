import asyncio
import os
import uuid
import json

from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fpdf import FPDF
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel

from backend_v2.langgraph_orchestrator import LangGraphOrchestrator
from backend_v2.policy.engine import PolicyViolationError, validate
from backend_v2.state import ScanState, state_db

load_dotenv()

app = FastAPI(title="PortBiter APIs v2 (LangGraph + Groq)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target_url: str


@app.post("/scan")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    try:
        validate(req.target_url)
    except PolicyViolationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    if not os.getenv("GROQ_API_KEY"):
        raise HTTPException(status_code=503, detail="Autonomous planning is unavailable because GROQ_API_KEY is not configured.")

    scan_id = str(uuid.uuid4())
    scan_state = ScanState(target_url=req.target_url, scan_id=scan_id)
    scan_state.save()
    state_db[scan_id] = scan_state

    orchestrator = LangGraphOrchestrator(scan_id, req.target_url)
    background_tasks.add_task(orchestrator.run_scan)

    return {"scan_id": scan_id}


@app.get("/scans")
async def list_scans():
    result = []
    for scan_id, state in state_db.items():
        result.append({
            "scan_id": scan_id,
            "target_url": state.target_url,
            "status": state.status,
            "progress": state.progress,
            "vulnerability_count": len(state.vulnerabilities),
            "started_at": state.started_at,
        })
    return result


@app.get("/scan/{scan_id}")
async def get_scan(scan_id: str):
    if scan_id not in state_db:
        return {"error": "Scan not found"}
    state = state_db[scan_id]
    return {
        "status": state.status,
        "progress": state.progress,
        "vulnerabilities": state.vulnerabilities,
        "logs": state.logs,
        "target_url": state.target_url,
        "started_at": state.started_at,
    }


@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    if scan_id not in state_db:
        await websocket.close()
        return

    state = state_db[scan_id]
    last_log_idx = 0
    try:
        while True:
            new_logs = state.logs[last_log_idx:]

            if new_logs or state.progress > 0:
                payload = {
                    "progress": state.progress,
                    "status": state.status,
                    "new_logs": new_logs,
                    "vulnerabilities": list(state.vulnerabilities),
                }

                await websocket.send_json(payload)
                last_log_idx = len(state.logs)

            if state.status in ["completed", "error"] and last_log_idx >= len(state.logs):
                break

            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        pass


@app.get("/report/{scan_id}")
async def generate_report_ep(scan_id: str):
    if scan_id not in state_db:
        return {"error": "Scan not found"}
    state = state_db[scan_id]
    scan_json = {
        "target_url": state.target_url,
        "logs": state.logs,
        "visited_urls": list(set(state.visited_urls)),
        "vulnerabilities": state.vulnerabilities,
    }

    from backend_v2.report_builder import build_report_markdown

    try:
        markdown = build_report_markdown(scan_json)
        if not markdown:
            return {"error": "report generation failed"}
        return {"markdown": markdown}
    except Exception as exc:
        return {"error": str(exc)}


@app.get("/report/pdf/{scan_id}")
async def generate_pdf_report_ep(scan_id: str):
    if scan_id not in state_db:
        raise HTTPException(status_code=404, detail="Scan not found")

    res = await generate_report_ep(scan_id)
    if "error" in res:
        raise HTTPException(status_code=500, detail=res["error"])

    markdown_text = res["markdown"]

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "PortBiter Security Assessment Report", ln=True, align="C")
    pdf.ln(10)

    pdf.set_font("Arial", size=11)
    clean_text = markdown_text.replace("### ", "").replace("## ", "").replace("# ", "").replace("**", "")
    pdf.multi_cell(0, 10, txt=clean_text)

    file_name = f"PortBiter_Report_{scan_id}.pdf"
    pdf_path = os.path.join(os.getcwd(), file_name)
    pdf.output(pdf_path)

    return FileResponse(path=pdf_path, filename=file_name, media_type="application/pdf")

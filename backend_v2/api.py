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
from langchain_groq import ChatGroq
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

    scan_id = str(uuid.uuid4())
    state_db[scan_id] = ScanState(target_url=req.target_url)

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

    system_prompt = """You are a senior penetration tester and security report writer.

Your task is to generate a professional, client-ready PDF security assessment report for an AI-powered vulnerability scanner called "PortBiter v3.0".

⚠️ Requirements:
- The report must be detailed, structured, and professional.
- Write in formal, clear, non-technical language for executives, but include technical depth where needed.
- Assume all testing was authorized and conducted safely (non-destructive).

---

📄 REPORT STRUCTURE (STRICTLY FOLLOW)

1. COVER PAGE
- Title: "Security Assessment Report"
- Tool: PortBiter v3.0
- Target URL
- Scan Date
- Prepared by: AI Security Auditor
- Confidentiality note

---

2. EXECUTIVE SUMMARY
- High-level overview (non-technical)
- Overall risk level (LOW/MEDIUM/HIGH/CRITICAL)
- Key findings summary
- Business impact

---

3. SCOPE & METHODOLOGY
- Scope (target URL)
- Testing type: Safe, simulated vulnerability scanning
- Methodology inspired by OWASP standards
- Limitations (no destructive testing)

---

4. ATTACK SURFACE ANALYSIS
- Total endpoints discovered
- Sensitive endpoints
- Public vs authenticated routes
- Observations

---

5. RISK SUMMARY
- Table of vulnerabilities by severity
- Pie-chart style description (textual)

---

6. DETAILED FINDINGS (MOST IMPORTANT)

For EACH vulnerability include:

- ID
- Title
- Severity
- CVSS Score + Vector
- Affected Endpoint
- Description
- Impact
- Proof of Concept (safe payload)
- Reproduction Steps
- Recommendation
- Remediation Priority
- Confidence Score

---

7. AI EXECUTION INSIGHTS (UNIQUE FEATURE)
- Explain how AI decided what to scan
- Show step-by-step reasoning
- Highlight adaptive scanning behavior

---

8. RECOMMENDATIONS SUMMARY
- Prioritized fixes
- Quick wins vs long-term fixes

---

9. CONCLUSION
- Overall security posture
- Final risk statement

---

10. APPENDIX
- Tools used
- Scan metadata
- Timestamp logs

---

🎯 STYLE REQUIREMENTS:
- Use headings and subheadings
- Use bullet points where appropriate
- Keep tone professional (like Deloitte / PwC reports)
- Avoid overly casual language
- Explain technical terms briefly

---

🚀 OUTPUT FORMAT:
Return a fully formatted report in MARKDOWN suitable for PDF conversion.

Do NOT return JSON.
Do NOT skip sections.
Ensure content is detailed and polished."""

    try:
        llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0.2)
        msg = llm.invoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=f"{{SCAN_RESULTS_JSON}}: {json.dumps(scan_json)}"),
        ])
        return {"markdown": msg.content}
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

# 🛡️ PortBiter

PortBiter is an AI-assisted web security scanner that combines a FastAPI backend, a LangGraph-style planner, and a Next.js dashboard to run safe, evidence-based scans and generate reports.

## What is implemented

- Safe target validation with a policy engine
- Live scan progress over WebSocket
- Evidence-based vulnerability reporting
- PDF report export from the backend
- A dashboard for launching scans and viewing findings

## Quick start

1. Create a Python environment and install dependencies:
   - `python -m venv .venv`
   - `.venv\Scripts\activate`
   - `pip install -r backend_v2/requirements.txt`
2. Copy [.env.example](.env.example) to `.env` and add a `GROQ_API_KEY` if you want the autonomous planner enabled.
3. Start the backend:
   - `uvicorn backend_v2.api:app --reload --host 0.0.0.0 --port 8000`
4. Start the frontend:
   - `cd frontend && npm install && npm run dev`

## Notes

- Without `GROQ_API_KEY`, the API will return an explicit `503` when a scan is requested, which keeps the workflow honest and avoids pretending a scan completed.
- `ALLOW_LOCALHOST`, `ALLOW_INTERNAL`, and `ALLOWED_DOMAINS` control whether local/private targets are allowed; set them explicitly for internal test environments.
- The scanner is intended for authorized testing only.

## API highlights

- `POST /scan`
- `GET /scan/{scan_id}`
- `GET /scans`
- `WS /ws/{scan_id}`
- `GET /report/{scan_id}`
- `GET /report/pdf/{scan_id}`


# PortBiter v3.0 (Groq Edition) Implementation

Building an AI-powered autonomous web security scanner utilizing FastAPI, Next.js, and Groq.

## Goal Description
The objective is to build a modular, testable, and production-ready system that:
- Uses Groq for AI-agent planning and analysis
- Validates all AI outputs and actions using a Policy Engine
- Orchestrates asynchronous security scans
- Publishes real-time scanning progress and findings over WebSockets to a Next.js dashboard
- Outputs structured Markdown vulnerabilities

## User Review Required
> [!IMPORTANT]
> - Since we are building an agentic security scanner, **what specific Groq Model** would you like as the default (e.g. `llama3-70b-8192` or `mixtral-8x7b-32768`)? We can make it configurable. Let's use `llama3-70b-8192` for planning and analysis by default.
> - **Groq API Key**: You'll need to set `GROQ_API_KEY` in the environment before we can run the backend.
> - **In-Memory Storage**: Given the MVP status, I plan to use in-memory dictionaries `dict` to store active scans and results. We can add Redis later.

## Proposed Architecture

### Backend (Python / FastAPI)
- **Framework**: `fastapi`, `uvicorn`, `websockets`
- **AI Agent Orchestration**: Standard async Python state-machine loop where the AI (using `groq` python SDK) emits JSON choices validated by Pydantic.
- **Folder Structure**:
  - `backend/main.py`: Entrypoint
  - `backend/core/scan_manager.py`: Manages start/stop and state
  - `backend/core/config.py`: Loads Groq Key
  - `backend/models/schemas.py`: Pydantic definitions
  - `backend/policy/engine.py`: Domain validation, payload safety
  - `backend/agents/planner.py`: Groq request for Next Step
  - `backend/agents/analyzer.py`: Groq request for Vulnerability Classification
  - `backend/tools/registry.py`: Valid Tools + Dispatcher
  - `backend/tools/crawler.py` & `xss.py`: Implementation of scanners
  - `backend/orchestrator/workflow.py`: The Main Event Loop (Planner -> Policy -> Executor -> Analyzer)

### Frontend (Next.js)
- **Framework**: Next.js 14 (App Router) + Tailwind CSS
- **Features**:
  - Websocket Client (`useWebSocket` hook)
  - Real-time Log Stream
  - Vulnerability list & severity pie-chart (`recharts`)
- **Folder Structure**:
  - `frontend/app/page.tsx`: Main dashboard
  - `frontend/components/`: Modular UI fragments

## Implementation Phases

### Phase 1: Backend Scaffolding & Setup
1. Setup Python virtual environment & install requirements (`fastapi`, `groq`, `websockets`, `pydantic`).
2. Create `backend/models/schemas.py` for strictly typed Action/Vulnerability JSON formats.

### Phase 2: Core Scanner Components
1. Implement the **Policy Engine** (`policy/engine.py`) ensuring AI choices are within target domain and safe.
2. Implement **Tools** (`tools/crawler.py`, `tools/xss.py`) with mocked/simulated payloads.
3. Build **LLM Agents** (`agents/planner.py`, `agents/analyzer.py`) using Groq to return JSON mode outputs.

### Phase 3: Orchestrator & Scan Manager
1. Stitch together `workflow.py` handling the actual queue & background tasks.
2. Spin up `main.py` FastAPI app containing REST `/scan` API and `WebSocket` endpoints broadcasting logs.

### Phase 4: Frontend Development
1. Bootstrap Next.js (`npx create-next-app@latest`).
2. Create WebSocket connection slice, displaying incoming vulnerabilities.
3. Build professional, dark-mode, animated UI fitting for PortBiter v3.0.

## Open Questions
> [!WARNING]
> - Do you have a specific target URL you'd like to use for testing during development, or should I create a simple mock FASTAPI vulnerable endpoint alongside the system?
> - Are there any specific TailWind theme colors you prefer for the PortBiter brand (e.g. Neon Green + Dark Gray)?

## Verification Plan

### Automated Tests
- Running simple payload strings safely against a local testing server to verify the analyzer logic correctly identifies and rates vulnerabilities using Groq.

### Manual Verification
1. Open the PortBiter Next.js frontend.
2. Click "Start Scan" with target `http://example.com` or local mock server.
3. Validate WebSocket logs stream live on the page.
4. Conclude scan and view final Markdown export representation in the frontend.

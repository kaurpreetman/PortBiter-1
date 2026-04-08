# 🛡️ ThreatLens — AI-Powered Autonomous Security Scanner

ThreatLens is a next-generation web security scanning platform that uses agentic AI to autonomously detect vulnerabilities in web applications and generate structured, actionable security reports.

---

## 🚀 Features

- 🤖 **Agentic AI Orchestration**
  - LLM-driven decision making (Groq-powered)
  - Dynamically selects and executes security tests

- 🔍 **Automated Vulnerability Detection**
  - XSS (Cross-Site Scripting)
  - SQL Injection (safe simulation)
  - Security headers misconfiguration
  - File exposure (.env, backups, configs)
  - File upload vulnerabilities

- ⚡ **Real-Time Live Dashboard**
  - WebSocket-based updates
  - Live scan progress & logs
  - Vulnerabilities appear instantly

- 🛡️ **Policy Engine (Safety First)**
  - Prevents destructive payloads
  - Restricts unauthorized scanning
  - Enforces safe testing rules

- 📊 **Structured Reporting**
  - CVSS-based severity scoring
  - Clear explanation of vulnerabilities
  - Impact + remediation guidance
  - PDF report generation

---

## 🧠 How It Works

ThreatLens follows an intelligent agent loop:

1. **Planner (AI)** → decides next action  
2. **Policy Engine** → validates safety  
3. **Executor** → runs security tool  
4. **Analyzer (AI)** → interprets results  
5. **State Update** → stores findings  
6. 🔁 Repeat until scan completes  

---

## 🏗️ Tech Stack

**Frontend**
- React / Next.js
- Tailwind CSS
- WebSockets (live updates)

**Backend**
- FastAPI
- Async execution
- WebSocket server

**AI Layer**
- Groq (LLM inference)
- Agent-based orchestration

**Core Systems**
- Tool Registry (anti-hallucination)
- Policy Engine
- Scan Manager
- Reporting Engine

---

## 📡 API Endpoints

- `POST /scan` → Start scan  
- `GET /scan/{id}` → Get status  
- `GET /scans` → List scans  
- `WS /ws/{scan_id}` → Live updates  
- `GET /report/pdf/{scan_id}` → Download report  

---

## 🎯 Use Cases

- Security testing for your own applications  
- Bug bounty research (authorized targets only)  
- Educational security labs  
- AI-driven penetration testing research  

---

## ⚠️ Disclaimer

This tool is intended **only for authorized security testing**.  
Do NOT use against systems without permission.

---

## 💡 Vision

ThreatLens aims to redefine security testing by combining:
- AI reasoning
- autonomous agents
- real-time intelligence

into a single powerful platform.

---

## ⭐ Future Improvements

- Advanced vulnerability coverage
- Multi-target scanning
- Authentication testing
- Scan replay & history
- Team collaboration features

---


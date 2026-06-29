import asyncio
import re

from langchain_core.messages import HumanMessage
from backend_v2.langgraph_workflow import create_workflow
from backend_v2.state import state_db
from backend_v2.tool_registry import SECURITY_TOOLS


class LangGraphOrchestrator:
    def __init__(self, scan_id: str, target_url: str):
        self.scan_id = scan_id
        self.target_url = target_url
        self.app = create_workflow()

    def append_log(self, text: str):
        state = state_db[self.scan_id]
        state.logs.append(text)
        print(f"[{self.scan_id}] {text}")

    def _build_system_prompt(self) -> str:
        tool_descriptions = "\n".join([f"- {tool.name}: {tool.description}" for tool in SECURITY_TOOLS])
        return f"""
        You are PortBiter v2.0 - An autonomous security testing AI.
        Target: {self.target_url}

        Available tools:
        {tool_descriptions}

        Strategy:
        1. Start with the web_crawler tool to map the application.
        2. Run the header_checker on the target root URL.
        3. Run the file_exposer on the target root URL.
        4. If a login or authentication endpoint is discovered, run auth_tester on that login URL directly, not on the root URL.
        5. Run xss_scanner on endpoints that contain query parameters or forms.
        6. If an upload endpoint is discovered, run upload_checker on that endpoint.

        CRITICAL: When you have found a vulnerability, report it in a concise format and do not include extra conversation.
        Format each vulnerability as:
        VULNERABILITY: [Title]
        RISK: [CRITICAL/HIGH/MEDIUM/LOW]
        ENDPOINT: [URL/Path]
        REASON: [Root cause explanation]
        IMPACT: [What attacker can do]
        PAYLOAD: [Evidence/Test Payload]
        FIX: [Actionable remediation]
        CONFIDENCE: [0-100]
        """.format(self=self, tool_descriptions=tool_descriptions)

    def _extract_urls(self, text: str):
        return re.findall(r"https?://[^\s)\]'\"]+", text)

    def _build_vulnerability(self, content: str):
        lines = [line.strip() for line in content.splitlines() if line.strip()]
        if not lines:
            return None

        if "VULNERABILITY:" in content:
            title = lines[0].split(":", 1)[1].strip() if ":" in lines[0] else lines[0]
            data = {
                "type": title,
                "severity": "MEDIUM",
                "endpoint": "N/A",
                "reason": "Unknown",
                "impact": "Unknown",
                "payload": "",
                "fix": "Review endpoint",
                "confidence": 50,
                "cvss": 5.0,
            }
            for line in lines[1:]:
                if line.startswith("RISK:"):
                    data["severity"] = line.split(":", 1)[1].strip().upper().replace("*", "")
                elif line.startswith("ENDPOINT:"):
                    data["endpoint"] = line.split(":", 1)[1].strip()
                elif line.startswith("REASON:"):
                    data["reason"] = line.split(":", 1)[1].strip()
                elif line.startswith("IMPACT:"):
                    data["impact"] = line.split(":", 1)[1].strip()
                elif line.startswith("PAYLOAD:"):
                    data["payload"] = line.split(":", 1)[1].strip()
                elif line.startswith("FIX:"):
                    data["fix"] = line.split(":", 1)[1].strip().replace("*", "")
                elif line.startswith("CONFIDENCE:"):
                    try:
                        data["confidence"] = int(line.split(":", 1)[1].strip().replace("%", ""))
                    except ValueError:
                        pass
            sev = data["severity"]
            if "CRITICAL" in sev:
                data["cvss"] = 9.8
            elif "HIGH" in sev:
                data["cvss"] = 8.0
            elif "MEDIUM" in sev:
                data["cvss"] = 5.0
            else:
                data["cvss"] = 3.0
            return data

        return None

    def _parse_tool_findings(self, content: str):
        findings = []
        if "XSS FOUND" in content:
            severity = "HIGH"
            endpoint = self.target_url
            if self._extract_urls(content):
                endpoint = self._extract_urls(content)[0]
            findings.append({
                "type": "Reflected XSS",
                "severity": severity,
                "endpoint": endpoint,
                "reason": "The target reflected a test payload in the response body",
                "impact": "An attacker could execute script in the victim's browser",
                "payload": content,
                "fix": "Sanitize and encode untrusted input before rendering it in HTML",
                "confidence": 90,
                "cvss": 8.0,
            })
        elif "SQL INJECTION FOUND" in content:
            findings.append({
                "type": "SQL Injection",
                "severity": "HIGH",
                "endpoint": self._extract_urls(content)[0] if self._extract_urls(content) else self.target_url,
                "reason": "The authentication endpoint accepted a crafted SQL payload and returned a success-like response",
                "impact": "An attacker could bypass authentication or extract data",
                "payload": content,
                "fix": "Use parameterized queries and proper input validation",
                "confidence": 90,
                "cvss": 8.0,
            })
        elif "MISSING HEADER" in content or "WEAK HEADER" in content:
            findings.append({
                "type": "Security Headers Misconfiguration",
                "severity": "MEDIUM",
                "endpoint": self.target_url,
                "reason": "One or more important security headers were missing or weak",
                "impact": "Attackers may exploit clickjacking, MIME sniffing, or downgrade attacks",
                "payload": content,
                "fix": "Add or harden security headers such as CSP, HSTS, and X-Frame-Options",
                "confidence": 80,
                "cvss": 5.0,
            })
        elif "UPLOAD VULNERABILITY" in content:
            findings.append({
                "type": "Insecure File Upload",
                "severity": "HIGH",
                "endpoint": self._extract_urls(content)[0] if self._extract_urls(content) else self.target_url,
                "reason": "The target accepted file uploads without visible validation",
                "impact": "An attacker may upload malicious content or exploit server-side handling",
                "payload": content,
                "fix": "Enforce file type, size, and content validation before storing uploads",
                "confidence": 85,
                "cvss": 8.0,
            })
        return findings

    async def run_scan(self):
        self.append_log("Initializing LangGraph Autonomous Scan...")

        system_prompt = self._build_system_prompt()

        initial_state = {
            "messages": [HumanMessage(content=system_prompt)],
            "target_url": self.target_url,
            "scan_id": self.scan_id,
        }

        try:
            config = {"recursion_limit": 15}
            tool_call_count = 0
            expected_tool_steps = max(1, len(SECURITY_TOOLS) * 2)

            for event in self.app.stream(initial_state, config=config):
                for key, value in event.items():
                    if key == "planner":
                        msg = value["messages"][-1]
                        if msg.tool_calls:
                            for tool_call in msg.tool_calls:
                                self.append_log(f"🧠 Strategy Phase: Planner decided to run `{tool_call['name']}` against `{tool_call['args'].get('target', '')}`")
                        elif msg.content:
                            content = msg.content.strip()
                            if "VULNERABILITY:" in content:
                                self.append_log("🧠 Vulnerability Identified!")
                                parsed = self._build_vulnerability(content)
                                if parsed:
                                    state_db[self.scan_id].vulnerabilities.append(parsed)
                            else:
                                self.append_log(f"🧠 Analysis: {content}")
                    elif key == "tools":
                        msg = value["messages"][-1]
                        self.append_log(f"🛠️ Execution Phase: Tool Result: {msg.content}")
                        tool_call_count += 1
                        progress = min(int((tool_call_count / expected_tool_steps) * 95), 95)
                        state_db[self.scan_id].progress = progress
                        state_db[self.scan_id].visited_urls.extend(self._extract_urls(msg.content))
                        if self.target_url not in state_db[self.scan_id].visited_urls:
                            state_db[self.scan_id].visited_urls.append(self.target_url)

                        parsed_findings = self._parse_tool_findings(msg.content)
                        for finding in parsed_findings:
                            state_db[self.scan_id].vulnerabilities.append(finding)

                await asyncio.sleep(1)

            state_db[self.scan_id].status = "completed"
            state_db[self.scan_id].progress = 100
            self.append_log("Scan completed successfully via LangGraph.")
        except Exception as exc:
            self.append_log(f"LangGraph execution error: {exc}")
            state_db[self.scan_id].status = "error"

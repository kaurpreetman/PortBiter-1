import asyncio
from langchain_core.messages import HumanMessage
from langgraph_workflow import create_workflow
from state import state_db

class LangGraphOrchestrator:
    def __init__(self, scan_id: str, target_url: str):
        self.scan_id = scan_id
        self.target_url = target_url
        self.app = create_workflow()
        
    def append_log(self, text: str):
        state = state_db[self.scan_id]
        state.logs.append(text)
        print(f"[{self.scan_id}] {text}")

    async def run_scan(self):
        self.append_log("Initializing LangGraph Autonomous Scan...")
        
        system_prompt = f"""
        You are PortBiter v2.0 - An autonomous security testing AI.
        Target: {self.target_url}
        
        Strategy:
        1. Always start by using the web_crawler tool to map the application.
        2. Once you have a list of endpoints from the crawler, use file_exposer on the root or other directories.
        3. Finally, use auth_tester on any endpoints that look like login or authentication.
        
        CRITICAL: When you are done routing tools and have found vulnerabilities, DO NOT output any conversational text. Be straight to the point.
        Format your finding EXACTLY like this for each issue:
        VULNERABILITY: [Title]
        RISK: [CRITICAL/HIGH/MEDIUM/LOW]
        ENDPOINT: [URL/Path]
        REASON: [Root cause explanation]
        IMPACT: [What attacker can do]
        PAYLOAD: [Evidence/Test Payload]
        FIX: [Actionable remediation]
        CONFIDENCE: [0-100]
        """
        
        initial_state = {
            "messages": [HumanMessage(content=system_prompt)],
            "target_url": self.target_url,
            "scan_id": self.scan_id
        }
        
        try:
            # We use an async loop to step through the graph so we can stream logs
            config = {"recursion_limit": 15}
            
            # Using synchronous stream for simplicity since ChatGroq and Tools handle async nicely
            for event in self.app.stream(initial_state, config=config):
                for key, value in event.items():
                    if key == "planner":
                        msg = value["messages"][-1]
                        if msg.tool_calls:
                            for t in msg.tool_calls:
                                self.append_log(f"🧠 Strategy Phase: Planner decided to run `{t['name']}` against `{t['args'].get('target', '')}`")
                        elif msg.content:
                            content = msg.content.strip()
                            if "VULNERABILITY:" in content:
                                self.append_log(f"🧠 Vulnerability Identified!")
                                for block in content.split("VULNERABILITY:")[1:]:
                                    lines = block.strip().split('\n')
                                    vuln = lines[0].strip()
                                    data = {
                                        "type": vuln,
                                        "severity": "MEDIUM",
                                        "endpoint": "N/A",
                                        "reason": "Unknown",
                                        "impact": "Unknown",
                                        "payload": "",
                                        "fix": "Review endpoint",
                                        "confidence": 50,
                                        "cvss": 5.0
                                    }
                                    
                                    for line in lines:
                                        line = line.strip()
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
                                            except: pass
                                            
                                    # Calc CVSS based on severity
                                    sev = data["severity"]
                                    if "CRITICAL" in sev: data["cvss"] = 9.8
                                    elif "HIGH" in sev: data["cvss"] = 8.0
                                    elif "MEDIUM" in sev: data["cvss"] = 5.0
                                    else: data["cvss"] = 3.0
                                    
                                    state_db[self.scan_id].vulnerabilities.append(data)
                            else:
                                self.append_log(f"🧠 Analysis: {content}")
                    elif key == "tools":
                        msg = value["messages"][-1]
                        self.append_log(f"🛠️ Execution Phase: Tool Result: {msg.content}")
                        state_db[self.scan_id].visited_urls.append(self.target_url)  # Basic tracking
                        
                await asyncio.sleep(1)
                
            state_db[self.scan_id].status = "completed"
            state_db[self.scan_id].progress = 100
            self.append_log("Scan completed successfully via LangGraph.")
            
        except Exception as e:
            self.append_log(f"LangGraph execution error: {str(e)}")
            state_db[self.scan_id].status = "error"

import os
import json
from langchain_core.messages import SystemMessage, HumanMessage


def _build_system_prompt(vuln_types):
    allowed = ', '.join(vuln_types) if vuln_types else 'none'
    return f"""
You are a senior security report writer for PortBiter.
Only produce findings that are present in the input data. Do NOT invent new vulnerability categories or findings.
Allowed findings: {allowed}
Produce a polished markdown report based exclusively on the provided scan JSON.
Include a cover, executive summary, scope and methodology, risk summary, detailed findings (one per provided finding), prioritized recommendations, and an appendix.
Use concise executive language, include CVSS-style severity labels when available, and keep the content evidence-grounded.
"""


def build_report_markdown(scan_json: dict) -> str:
    """Builds a markdown report from scan results.

    If `GROQ_API_KEY` is set, send a constrained prompt to ChatGroq to improve prose.
    Otherwise, generate a conservative markdown that only formats the provided findings.
    """
    vulnerabilities = scan_json.get("vulnerabilities", []) or []
    vuln_types = sorted({v.get("type", "Unknown") for v in vulnerabilities})

    if os.getenv("GROQ_API_KEY"):
        try:
            from langchain_groq import ChatGroq
            llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0.2)
            system_prompt = _build_system_prompt(vuln_types)
            msg = llm.invoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=f"SCAN_JSON: {json.dumps(scan_json, default=str)}")
            ])
            if getattr(msg, "content", None):
                return msg.content
        except Exception:
            # Fall through to local renderer on error
            pass

    # Local deterministic renderer (no LLM) - safe, no hallucinations
    lines = []
    lines.append("# Security Assessment Report")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append(f"Target: {scan_json.get('target_url','N/A')}")
    lines.append("")
    lines.append("This report contains only findings that were directly observed by automated tools. No additional issues were inferred.")
    lines.append("")
    lines.append("## Scope & Methodology")
    lines.append("Automated, non-destructive HTTP-based scanning. Tools exercised: web_crawler, security_headers_checker, xss_tester, file_upload_tester, sql_injection_tester, auth_tester, port_scanner.")
    lines.append("")
    lines.append("## Risk Summary")
    if vulnerabilities:
        for v in vulnerabilities:
            lines.append(f"- **{v.get('type','Unknown')}** — {v.get('severity','UNKNOWN')} — {v.get('endpoint','N/A')}")
    else:
        lines.append("No vulnerabilities detected by active tools.")
    lines.append("")
    lines.append("## Detailed Findings")
    for i, v in enumerate(vulnerabilities, start=1):
        lines.append(f"### {i}. {v.get('type','Unknown')}")
        lines.append(f"- **Severity:** {v.get('severity','UNKNOWN')}")
        lines.append(f"- **Endpoint:** {v.get('endpoint','N/A')}")
        lines.append(f"- **Evidence:** {v.get('payload') or v.get('reason') or 'n/a'}")
        lines.append(f"- **Recommendation:** {v.get('fix','See remediation guidelines')}")
        lines.append("")

    lines.append("## Appendix")
    lines.append("### Visited URLs")
    for u in scan_json.get('visited_urls', [])[:50]:
        lines.append(f"- {u}")

    return "\n".join(lines)

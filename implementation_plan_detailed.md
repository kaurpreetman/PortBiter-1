# PortBiter v3.0 Detailed Implementation Plan

This document describes the detailed plan for completing the PortBiter security scanner implementation without modifying existing code yet.

## Goal
Implement the remaining core security features for PortBiter:
- XSS detection
- SQL injection detection
- Security headers validation
- File upload vulnerability testing
- Policy engine and safe payload validation
- Real evidence-backed vulnerability findings
- Professional scanning reports

---

## 1. Scope and Architecture

### 1.1 Existing Architecture
The current backend contains:
- `backend_v2/api.py`: HTTP scan API, WebSocket streaming, report endpoint
- `backend_v2/langgraph_orchestrator.py`: autonomous scan orchestration
- `backend_v2/tool_registry.py`: current tool set definitions
- `backend_v2/langgraph_workflow.py`: workflow graph for planner and tool execution
- `backend_v2/state.py`: scan state storage

### 1.2 Target Architecture
Add the following modules:
- `backend_v2/policy_engine.py`
- `backend_v2/report_builder.py`
- `backend_v2/tools/xss_tester.py`
- `backend_v2/tools/sql_injection_tester.py`
- `backend_v2/tools/security_headers_checker.py`
- `backend_v2/tools/file_upload_tester.py`
- `backend_v2/tools/recon_helper.py`

---

## 2. Feature Breakdown

### 2.1 XSS Detection
#### Objective
Detect reflected and stored XSS risks in discovered web inputs.

#### Implementation Tasks
1. Crawl pages and extract forms, query parameters, JSON endpoints.
2. Identify input names and available injection points.
3. Submit safe XSS payloads using HTTP GET/POST where appropriate.
4. Inspect returned HTML for reflected payload text.
5. Report issues with:
   - affected endpoint
   - vulnerable parameter
   - payload
   - evidence snippet
   - severity and remediation guidance

#### Expected Output
A vulnerability entry with a real evidence snippet showing the reflected input.

---

### 2.2 SQL Injection Detection
#### Objective
Find SQL injection weaknesses using non-destructive, safe payloads.

#### Implementation Tasks
1. Enumerate input points from forms, query strings, and login/auth endpoints.
2. Submit semantically safe SQLi test payloads such as `"' OR '1'='1"` and `"' AND 1=1--"`.
3. Detect anomalies such as SQL error messages, response differences, or authentication bypass indications.
4. Report findings with:
   - vulnerable parameter
   - injection type
   - payload used
   - evidence
   - recommended fix

#### Expected Output
Findings should be based on actual HTTP responses, not just AI inference.

---

### 2.3 Security Headers Check
#### Objective
Validate the presence and strength of critical HTTP security headers.

#### Headers to verify
- `Content-Security-Policy`
- `X-Frame-Options`
- `Strict-Transport-Security`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

#### Implementation Tasks
1. Request the target root URL and discovered endpoints.
2. Check header presence and known weak values.
3. Generate findings for missing or misconfigured headers.
4. Provide remediation recommendations for each missing header.

#### Expected Output
A list of header hardening issues backed by actual response headers.

---

### 2.4 File Upload Vulnerability Testing
#### Objective
Detect unsafe file upload handling and validation issues.

#### Implementation Tasks
1. Discover upload endpoints by crawling and inspecting forms.
2. Test file upload endpoints with safe test files and content types.
3. Verify application behavior for allowed/disallowed file types.
4. Detect issues such as:
   - missing validation
   - arbitrary file write
   - unsafe file handling
5. Report with endpoint details, file type tested, and vulnerability classification.

#### Expected Output
A real issue entry for upload endpoints that accept unsafe content or mishandle uploads.

---

### 2.5 Policy Engine and Safe Payload Validation
#### Objective
Ensure the scanner only executes safe, non-destructive actions.

#### Implementation Tasks
1. Create a policy module that validates every tool action.
2. Enforce allowed domains and in-scope URLs.
3. Block destructive payloads and unsupported HTTP methods.
4. Validate scanned payloads against an approved safe list.
5. Log policy decisions and allow tool flows to proceed only when safe.

#### Expected Output
A safe scanning pipeline that clearly documents which actions were permitted or denied.

---

### 2.6 Real Vulnerability Findings
#### Objective
Produce structured, evidence-based vulnerability findings rather than generic AI summaries.

#### Implementation Tasks
1. Define a structured vulnerability model with fields such as:
   - `id`
   - `title`
   - `type`
   - `endpoint`
   - `parameter`
   - `severity`
   - `cvss`
   - `description`
   - `impact`
   - `evidence`
   - `payload`
   - `recommendation`
   - `confidence`
2. Build analyzer logic that translates tool outputs into this model.
3. Keep the AI role focused on classification, explanation, and report text generation.
4. Avoid adding issues unless there is actual tool evidence.

#### Expected Output
Consistent vulnerability entries suitable for reporting and remediation.

---

### 2.7 Professional Report Generation
#### Objective
Build a professional report pipeline from scan results.

#### Report Structure
- Cover page
- Executive summary
- Scope and methodology
- Attack surface analysis
- Risk summary
- Detailed findings
- AI execution insights
- Recommendations summary
- Conclusion
- Appendix

#### Implementation Tasks
1. Create a `report_builder.py` to generate PDF and Markdown summaries.
2. Use the structured vulnerability model and scan metadata as input.
3. Ensure tone is professional and formal, with clear remediation guidance.
4. Keep report generation non-destructive and based on completed scan data.

#### Expected Output
A client-ready report format that can be exported via API.

---

## 3. Implementation Phases and Timeline

### Phase 1: Planning and Data Modeling
- Finalize vulnerability schema
- Design policy engine interface
- Define tool contract and safe payload rules
- Estimate dependencies and library needs

### Phase 2: Tool Modules
- Implement `xss_tester.py`
- Implement `sql_injection_tester.py`
- Implement `security_headers_checker.py`
- Implement `file_upload_tester.py`
- Add helper functions in `recon_helper.py`

### Phase 3: Policy Layer
- Build `policy_engine.py`
- Integrate policy checks into tool execution flow
- Add safe payload validation rules

### Phase 4: Orchestrator and Scan Flow
- Update `langgraph_orchestrator.py` or workflow graph to use new tools
- Map actual tool outputs to structured findings
- Ensure scan state logs progress and evidence clearly

### Phase 5: Report Builder
- Implement `report_builder.py`
- Connect existing `/report/{scan_id}` endpoint to the report generator
- Generate structured PDF/Markdown output

### Phase 6: Validation and Test Cases
- Create safe local test targets for XSS and SQLi
- Validate header checks and upload tests
- Confirm policy engine blocks unsafe payloads
- Review report format and content quality

---

## 4. Detailed Task List

### 4.1 Backend Enhancements
- `backend_v2/policy_engine.py`
  - Permission checks
  - Payload validation
  - Domain scope enforcement
- `backend_v2/report_builder.py`
  - Report data assembly
  - PDF/Markdown export
  - Executive summary generation
- `backend_v2/tools/xss_tester.py`
  - Input discovery
  - Safe reflection checks
- `backend_v2/tools/sql_injection_tester.py`
  - Parameter fuzzing
  - Error and logic detection
- `backend_v2/tools/security_headers_checker.py`
  - Header enumeration and evaluation
- `backend_v2/tools/file_upload_tester.py`
  - Upload endpoint discovery
  - Safe file validation tests
- `backend_v2/tools/recon_helper.py`
  - URL normalization
  - Form parsing
  - Parameter enumeration

### 4.2 Workflow and State
- Add new tools to `backend_v2/tool_registry.py`
- Enhance `backend_v2/langgraph_workflow.py` to support tool selection and tool chaining
- Improve `backend_v2/langgraph_orchestrator.py` to parse evidence-based outputs
- Update `backend_v2/state.py` if needed to store richer scan metadata

### 4.3 Report and Presentation
- Standardize vulnerability output shape
- Add scan metadata and timeline to report
- Ensure findings are evidence-based and include remediation
- Keep report style formal and structured

---

## 5. Risk Mitigation

- Do not perform destructive testing.
- Keep all payloads safe and validated by policy.
- Use only target-domain requests.
- Log denied actions and policy blocks for transparency.

---

## 6. Success Criteria

- New scans detect XSS, SQLi, header, and upload issues with actual evidence.
- Policy engine prevents unsafe payloads and out-of-scope actions.
- Generated reports are professional, structured, and actionable.
- Scan state is auditable and provides clear progress/log output.
- Existing API surface remains compatible with current endpoints.

---

## 7. Next Step
Create the implementation ticket list and begin coding in the backend modules above, starting with the policy engine and structured vulnerability model.

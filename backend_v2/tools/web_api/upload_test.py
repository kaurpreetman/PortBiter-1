import json
from pydantic import BaseModel

class ToolResult(BaseModel):
    id: str
    title: str
    severity: str
    cvss: float
    endpoint: str
    description: str
    impact: str
    reproduction: str
    recommendation: str
    confidence: float

def upload_check(url: str) -> str:
    """
    Simulates checking for unrestricted file upload vulnerabilities.
    """
    if "upload" in url.lower():
        result = ToolResult(
            id="PB-UPL-001",
            title="Unrestricted File Upload",
            severity="HIGH",
            cvss=8.1,
            endpoint=url,
            description="The application allows uploading files without proper extension or content-type validation.",
            impact="An attacker could upload a web shell (.php, .aspx) to achieve Remote Code Execution (RCE).",
            reproduction="1. Navigate to the upload page\n2. Attempt to upload a .txt file containing PHP code renamed to .php\n3. Check if the file is accessible on the server.",
            recommendation="Implement a whitelist of allowed file extensions, rename uploaded files, and store them in a non-executable directory.",
            confidence=0.8
        )
        return json.dumps(result.model_dump())
    
    return json.dumps({"status": "secure", "message": "No unrestricted upload endpoints identified."})

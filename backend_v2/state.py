from datetime import datetime


class ScanState:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.visited_urls = []
        self.vulnerabilities = []
        self.logs = []
        self.status = "running"
        self.progress = 0
        self.started_at = datetime.utcnow().isoformat()


state_db = {}

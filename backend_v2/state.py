import os
import json
from langchain_groq import ChatGroq
from langchain_core.tools import tool

class ScanState:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.visited_urls = []
        self.vulnerabilities = []
        self.logs = []
        self.status = "running"
        self.progress = 0

state_db = {}

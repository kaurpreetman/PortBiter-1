import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_create_workflow_without_groq_api_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    from backend_v2.langgraph_workflow import NoLLMConfiguredError, create_workflow

    with pytest.raises(NoLLMConfiguredError):
        create_workflow()


def test_orchestrator_prompt_uses_registered_tool_names():
    from backend_v2.langgraph_orchestrator import LangGraphOrchestrator
    from backend_v2.tool_registry import SECURITY_TOOLS

    orchestrator = LangGraphOrchestrator.__new__(LangGraphOrchestrator)
    orchestrator.scan_id = "scan-test"
    orchestrator.target_url = "https://example.test"

    prompt = orchestrator._build_system_prompt()
    registered_names = {tool.name for tool in SECURITY_TOOLS}
    for tool_name in registered_names:
        assert tool_name in prompt

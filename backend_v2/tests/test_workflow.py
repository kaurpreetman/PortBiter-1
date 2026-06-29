import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_create_workflow_without_groq_api_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    from langgraph_workflow import create_workflow

    workflow = create_workflow()

    assert workflow is not None

from typing import TypedDict, Annotated, Sequence
import operator
import os
from langchain_core.messages import BaseMessage
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from backend_v2.tool_registry import SECURITY_TOOLS


class NoLLMConfiguredError(RuntimeError):
    """Raised when autonomous planning was requested without a configured LLM backend."""


class _LocalFallbackLLM:
    def __init__(self, *args, **kwargs):
        pass

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        class _Resp:
            def __init__(self):
                self.tool_calls = []
                self.content = "[local-fallback] no-op planner response"

        return _Resp()

class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], operator.add]
    target_url: str
    scan_id: str

def create_workflow():
    if not os.getenv("GROQ_API_KEY"):
        raise NoLLMConfiguredError("GROQ_API_KEY is not configured. Set it to enable autonomous planning.")

    # 1. Setup Planner
    try:
        from langchain_groq import ChatGroq
        llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0.1)
    except Exception as exc:
        raise NoLLMConfiguredError("Unable to initialize the Groq-backed planner. Check LANGCHAIN or Groq installation details.") from exc

    llm_with_tools = llm.bind_tools(SECURITY_TOOLS)
    
    # 2. Nodes
    def planner_node(state: AgentState):
        messages = state["messages"]
        response = llm_with_tools.invoke(messages)
        return {"messages": [response]}
        
    tool_node = ToolNode(SECURITY_TOOLS)

    def route_tools(state: AgentState):
        messages = state["messages"]
        last_message = messages[-1]
        
        if last_message.tool_calls:
            return "tools"
        return "end"
        
    # 3. Graph
    workflow = StateGraph(AgentState)
    
    workflow.add_node("planner", planner_node)
    workflow.add_node("tools", tool_node)
    
    workflow.set_entry_point("planner")
    workflow.add_conditional_edges(
        "planner",
        route_tools,
        {"tools": "tools", "end": END}
    )
    workflow.add_edge("tools", "planner")
    
    return workflow.compile()

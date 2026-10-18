from pydantic import BaseModel


class MCPToolCallRequest(BaseModel):
    tool: str
    arguments: dict = {}


class MCPAgentRequest(BaseModel):
    task: str
    model: str = "deepseek-r1"

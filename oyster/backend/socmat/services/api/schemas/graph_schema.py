from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict


class GraphNode(BaseModel):
    id: str
    type: str
    label: str
    description: Optional[str] = None
    severity: str = "info"
    confidence: str = "medium"
    source_ids: List[int] = []
    properties: Dict[str, Any] = {}

    model_config = ConfigDict(from_attributes=True)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    type: str
    label: str
    confidence: str = "medium"
    evidence_reference: Optional[str] = None
    properties: Dict[str, Any] = {}

    model_config = ConfigDict(from_attributes=True)


class GraphMetadata(BaseModel):
    total_nodes: int
    total_edges: int
    node_type_counts: Dict[str, int]
    case_id: int
    filters_applied: Dict[str, Any]


class GraphResponse(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    metadata: GraphMetadata

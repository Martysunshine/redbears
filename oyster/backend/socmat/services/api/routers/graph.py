from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from socmat.services.api.database import get_db
from socmat.services.api.graph_builder import build_graph
from socmat.services.api.schemas.graph_schema import GraphResponse

router = APIRouter(tags=["graph"])


@router.get("/cases/{case_id}/graph", response_model=GraphResponse)
def get_case_graph(
    case_id: int,
    show_hosts: bool = Query(True),
    show_users: bool = Query(True),
    show_ips: bool = Query(True),
    show_domains: bool = Query(True),
    show_processes: bool = Query(True),
    show_detections: bool = Query(True),
    show_mitre: bool = Query(True),
    show_iocs: bool = Query(True),
    show_evidence: bool = Query(False),
    only_suspicious: bool = Query(False),
    db: Session = Depends(get_db),
):
    from socmat.services.api.models.case import Case
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")

    return build_graph(
        db,
        case_id,
        show_hosts=show_hosts,
        show_users=show_users,
        show_ips=show_ips,
        show_domains=show_domains,
        show_processes=show_processes,
        show_detections=show_detections,
        show_mitre=show_mitre,
        show_iocs=show_iocs,
        show_evidence=show_evidence,
        only_suspicious=only_suspicious,
    )

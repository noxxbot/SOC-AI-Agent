from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database.db import get_db
from app.models.models import Agent
from app.schemas.agents import AgentResponse
from typing import List

router = APIRouter()

@router.get("/agents", response_model=List[AgentResponse])
def get_agents(db: Session = Depends(get_db)):
    """
    Returns a list of all registered security agents and their last seen status.
    """
    return db.query(Agent).order_by(Agent.last_seen.desc().nullslast()).all()

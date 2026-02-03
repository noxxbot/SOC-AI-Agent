from fastapi import APIRouter
from datetime import datetime, timezone

from app.services.ai_service import AIService

router = APIRouter()
_STARTED_AT = datetime.now(timezone.utc)
_ai_service = AIService()

@router.get("/health")
async def get_health():
    """
    Standard health check endpoint.
    """
    return { "status": "ok", "service": "soc-ai-agent-backend" }


@router.get("/api/v1/health")
async def get_health_v1():
    """
    Health check with backend + Ollama status and uptime.
    """
    now = datetime.now(timezone.utc)
    uptime_seconds = int((now - _STARTED_AT).total_seconds())
    try:
        ollama_ready = await _ai_service.check_ollama_ready()
    except Exception:
        ollama_ready = False
    return {
        "status": "ok",
        "service": "soc-ai-agent-backend",
        "server_time": now.isoformat(),
        "uptime_seconds": uptime_seconds,
        "ollama": {
            "ready": bool(ollama_ready),
            "model": _ai_service.model
        }
    }

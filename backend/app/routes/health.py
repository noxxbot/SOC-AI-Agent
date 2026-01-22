from fastapi import APIRouter

router = APIRouter()

@router.get("/health")
async def get_health():
    """
    Standard health check endpoint.
    """
    return { "status": "ok", "service": "soc-ai-agent-backend" }

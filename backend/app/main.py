from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database.db import engine, Base
from app.models.models import Agent, Alert
from app.models.correlation_finding import CorrelationFinding
from app.models.detection_alert import DetectionAlert
from app.models.ai_investigation import AIInvestigation
from app.models.incident import Incident
from app.routes import health, analysis, alerts, telemetry, agents, logs, correlation, detections
from app.routes import ai_investigations, incidents
from app.core.config import settings
from app.routes import threat_intel
from app.services.correlation_scheduler import start_scheduler


app = FastAPI(
    title=settings.APP_NAME,
    description="Advanced AI-driven Security Operations Center Backend",
    version="1.0.0"
)

Base.metadata.create_all(bind=engine)

# CORS Configuration - Allow all origins for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
# Health check is included at the root for easy access
app.include_router(health.router)


# V1 API Routes
app.include_router(analysis.router, prefix="/api/v1", tags=["security-analysis"])
app.include_router(alerts.router, prefix="/api/v1", tags=["alerts"])
app.include_router(telemetry.router, prefix="/api/v1", tags=["telemetry"])
app.include_router(agents.router, prefix="/api/v1", tags=["agents"])
app.include_router(threat_intel.router, prefix="/api/v1", tags=["threat-intel"])
app.include_router(logs.router, prefix="/api/v1", tags=["logs"])
app.include_router(correlation.router, prefix="/api/v1", tags=["correlation"])
app.include_router(detections.router, prefix="/api/v1", tags=["detections"])
app.include_router(ai_investigations.router, prefix="/api/v1", tags=["ai-investigations"])
app.include_router(incidents.router, prefix="/api/v1", tags=["incidents"])


@app.on_event("startup")
def start_background_tasks():
    start_scheduler()


if __name__ == "__main__":
    import uvicorn
    # The run command recommended: uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
    uvicorn.run("app.main:app", host="0.0.0.0", port=settings.PORT, reload=True)

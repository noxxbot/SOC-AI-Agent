from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database.db import engine, Base
from app.models.models import Agent, Alert
from app.routes import health, analysis, alerts, telemetry, agents
from app.core.config import settings
from app.routes import threat_intel


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


if __name__ == "__main__":
    import uvicorn
    # The run command recommended: uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
    uvicorn.run("app.main:app", host="0.0.0.0", port=settings.PORT, reload=True)

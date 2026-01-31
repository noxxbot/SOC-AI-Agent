from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # App Config
    APP_NAME: str = "SOC-AI Agent"
    APP_ENV: str = "development"
    PORT: int = 8000
    DEBUG: bool = True

    # Database
    DATABASE_URL: str = "sqlite:///./soc_ai.db"

    # ✅ Local LLM (Ollama)
    OLLAMA_URL: str = Field(default="http://localhost:11434")
    OLLAMA_MODEL: str = Field(default="llama3:8b")
    AI_INVESTIGATE_MODE: str = Field(default="all")
    AI_INVESTIGATE_ON_CREATE: bool = Field(default=True)
    AI_LOG_NOTES_MODE: str = Field(default="suspicious_only")
    AI_MAX_RETRIES: int = Field(default=2)
    AI_RETRY_DELAY_SECONDS: int = Field(default=2)
    INCIDENT_AUTO_CREATE: bool = Field(default=True)
    INCIDENT_DEDUP_WINDOW_SECONDS: int = Field(default=1800)
    INCIDENT_MIN_SEVERITY: str = Field(default="medium")
    INCIDENT_AI_MIN_CONFIDENCE: int = Field(default=60)

    class Config:
        env_file = ".env"
        extra = "ignore"   # ignore unused env variables like API_KEY


# ✅ this is what your project imports
settings = Settings()

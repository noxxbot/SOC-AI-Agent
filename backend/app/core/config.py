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

    class Config:
        env_file = ".env"
        extra = "ignore"   # ignore unused env variables like API_KEY


# ✅ this is what your project imports
settings = Settings()

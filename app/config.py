from pydantic_settings import BaseSettings
from dotenv import load_dotenv
import os

load_dotenv()

class Settings(BaseSettings):
    # Supabase configuration
    supabase_url: str = os.getenv("SUPABASE_URL", "")
    supabase_key: str = os.getenv("SUPABASE_KEY", "")
    
    # API configuration
    project_name: str = "QuickNote API"
    version: str = "1.0.0"
    description: str = "API para QuickNote - App de notas moderna"
    
    # Environment
    environment: str = os.getenv("ENVIRONMENT", "development")
    
    # CORS
    allowed_origins: list = [
        "http://localhost:5173",
        "http://localhost:3000",
        "https://quicknote-app.vercel.app",
    ]
    
    class Config:
        env_file = ".env"
        case_sensitive = False

settings = Settings()

# Validar configuración crítica
if not settings.supabase_url or not settings.supabase_key:
    raise ValueError("SUPABASE_URL y SUPABASE_KEY deben estar configuradas en el archivo .env")
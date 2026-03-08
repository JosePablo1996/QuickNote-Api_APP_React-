# config.py - VERSIÓN CORREGIDA
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
    
    # CORS - Definir como campos normales
    allowed_origins_dev: list = [
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:5175",
        "http://localhost:3000",
        "http://localhost:3001",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://127.0.0.1:3000",
    ]
    
    allowed_origins_prod: list = [
        "https://quicknote-app.vercel.app",
        "https://quicknote-web-app.vercel.app",
        "https://quicknote-web-app.netlify.app",
    ]
    
    class Config:
        env_file = ".env"
        case_sensitive = False

    # ✅ NUEVO: Método para obtener orígenes según entorno
    def get_allowed_origins(self):
        """Retorna orígenes permitidos según el entorno"""
        if self.environment == "development":
            return self.allowed_origins_dev
        else:
            return self.allowed_origins_prod

settings = Settings()

# Validar configuración crítica
if not settings.supabase_url or not settings.supabase_key:
    raise ValueError("SUPABASE_URL y SUPABASE_KEY deben estar configuradas en el archivo .env")
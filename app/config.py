# config.py
from pydantic_settings import BaseSettings
from dotenv import load_dotenv
import os

load_dotenv()

class Settings(BaseSettings):
    # Supabase
    supabase_url: str = os.getenv("SUPABASE_URL", "")
    supabase_key: str = os.getenv("SUPABASE_KEY", "")
    
    # ✅ JWT - AHORA CON EL SECRETO CORRECTO DE SUPABASE
    jwt_secret: str = os.getenv("JWT_SECRET", "bpt3Y5ayZtaZSydhOFg7400mY0gzOxhH0gP0wdPjGmns/iqu0D5n0BGM4Kjzd+OIGgCXBi4RAyp+4usk4fwyXQ==")
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 24 * 7  # 7 días
    
    # API Info
    project_name: str = "QuickNote API"
    version: str = "1.0.0"
    description: str = "API para QuickNote - App de notas moderna"
    environment: str = os.getenv("ENVIRONMENT", "development")
    
    # CORS - ORÍGENES EXPLÍCITOS
    allowed_origins: list = [
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:5175",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://127.0.0.1:3000",
        "https://quicknote-web-app.vercel.app",
        "https://quicknote-web-app-git-main-josepablo1996s-projects.vercel.app",
    ]
    
    class Config:
        env_file = ".env"
        case_sensitive = False

    def get_allowed_origins(self):
        return self.allowed_origins

settings = Settings()

# Validaciones
if not settings.supabase_url or not settings.supabase_key:
    raise ValueError("SUPABASE_URL y SUPABASE_KEY deben estar configuradas en el archivo .env")

# Log de configuración (solo en desarrollo)
if settings.environment == "development":
    print(f"🔧 Configuración cargada:")
    print(f"  - Entorno: {settings.environment}")
    print(f"  - Supabase URL: {settings.supabase_url[:20]}...")
    print(f"  - JWT Secret: {settings.jwt_secret[:20]}... (configurado)")
    print(f"  - CORS Origins: {len(settings.allowed_origins)} orígenes")
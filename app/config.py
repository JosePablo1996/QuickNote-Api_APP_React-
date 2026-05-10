# config.py
from pydantic_settings import BaseSettings
from dotenv import load_dotenv
import os
import logging
from pathlib import Path

# Cargar variables de entorno desde el archivo .env en la raiz del proyecto
env_path = Path(__file__).resolve().parent.parent / '.env'
print(f"🔍 Buscando archivo .env en: {env_path}")
print(f"📁 ¿Existe el archivo?: {env_path.exists()}")
load_dotenv(dotenv_path=env_path)

# Tambien cargar desde el directorio actual por si acaso
load_dotenv()

logger = logging.getLogger(__name__)

class Settings(BaseSettings):
    # Supabase
    supabase_url: str = os.getenv("SUPABASE_URL", "")
    supabase_key: str = os.getenv("SUPABASE_KEY", "")
    
    # JWT
    jwt_secret: str = os.getenv("JWT_SECRET", "")
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 24 * 7  # 7 dias
    
    # SendGrid Email
    sendgrid_api_key: str = os.getenv("SENDGRID_API_KEY", "")
    sendgrid_from_email: str = os.getenv("SENDGRID_FROM_EMAIL", "noreply@quicknote.com")
    sendgrid_from_name: str = os.getenv("SENDGRID_FROM_NAME", "QuickNote")
    
    # SMTP Email (respaldo)
    smtp_host: str = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    smtp_user: str = os.getenv("SMTP_USER", "")
    smtp_password: str = os.getenv("SMTP_PASSWORD", "")
    smtp_from: str = os.getenv("SMTP_FROM", "")
    smtp_from_name: str = os.getenv("SMTP_FROM_NAME", "QuickNote")
    
    # API Info
    project_name: str = "QuickNote API"
    version: str = "1.1.0"
    description: str = "API para QuickNote - App de notas moderna"
    environment: str = os.getenv("ENVIRONMENT", "development")
    
    # CORS - ORIGENES EXPLICITOS
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
        "https://quicknote-api-app-react.onrender.com",
    ]
    
    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "allow"

    def get_allowed_origins(self):
        return self.allowed_origins

# Crear instancia de settings
settings = Settings()

# VALIDACIONES IMPORTANTES
if not settings.supabase_url or not settings.supabase_key:
    logger.error(f"❌ ERROR: Variables de Supabase no encontradas")
    raise ValueError("SUPABASE_URL y SUPABASE_KEY deben estar configuradas en el archivo .env")

if not settings.jwt_secret:
    settings.jwt_secret = os.environ.get("JWT_SECRET", "")
    if not settings.jwt_secret:
        raise ValueError("JWT_SECRET debe estar configurado en las variables de entorno")

# Mostrar informacion de depuracion
logger.info("=" * 60)
logger.info("✅ CONFIGURACION COMPLETA:")
logger.info(f"Archivo .env existe: {env_path.exists()}")
logger.info(f"  - Entorno: {settings.environment}")
logger.info(f"  - Supabase URL: {settings.supabase_url[:40]}...")
logger.info(f"  - JWT Secret configurado: {'✅ SI' if settings.jwt_secret else '❌ NO'}")
logger.info(f"  - SendGrid API Key: {'✅ SI' if settings.sendgrid_api_key else '❌ NO'}")
logger.info(f"  - SendGrid From: {settings.sendgrid_from_email}")
logger.info(f"  - SMTP Host: {settings.smtp_host}")
logger.info(f"  - CORS Origins: {len(settings.allowed_origins)} origenes")
logger.info("=" * 60)
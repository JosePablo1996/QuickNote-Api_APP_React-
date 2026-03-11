# config.py
from pydantic_settings import BaseSettings
from dotenv import load_dotenv
import os
import logging
from pathlib import Path

# ✅ Cargar variables de entorno desde el archivo .env en la raíz del proyecto
env_path = Path(__file__).resolve().parent.parent / '.env'
load_dotenv(dotenv_path=env_path)

# También cargar desde el directorio actual por si acaso
load_dotenv()

logger = logging.getLogger(__name__)

class Settings(BaseSettings):
    # Supabase
    supabase_url: str = os.getenv("SUPABASE_URL", "")
    supabase_key: str = os.getenv("SUPABASE_KEY", "")
    
    # ✅ JWT - AHORA LEE DESDE VARIABLES DE ENTORNO
    jwt_secret: str = os.getenv("JWT_SECRET", "")  # Vacío por defecto para forzar configuración
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
        "https://quicknote-api-app-react.onrender.com",
    ]
    
    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "allow"  # Permitir variables extra

    def get_allowed_origins(self):
        return self.allowed_origins

# Crear instancia de settings
settings = Settings()

# ✅ VALIDACIONES IMPORTANTES
if not settings.supabase_url or not settings.supabase_key:
    raise ValueError("SUPABASE_URL y SUPABASE_KEY deben estar configuradas en el archivo .env")

if not settings.jwt_secret:
    # Intentar leer directamente desde os.environ como último recurso
    settings.jwt_secret = os.environ.get("JWT_SECRET", "")
    if not settings.jwt_secret:
        raise ValueError("JWT_SECRET debe estar configurado en las variables de entorno")

# Mostrar información de depuración
logger.info("=" * 60)
logger.info("🔧 CONFIGURACIÓN COMPLETA:")
logger.info(f"📂 Archivo .env buscado en: {env_path}")
logger.info(f"📂 Archivo .env existe: {env_path.exists()}")
logger.info(f"  - Entorno: {settings.environment}")
logger.info(f"  - Supabase URL: {settings.supabase_url[:30]}...")
logger.info(f"  - JWT Secret configurado: {'✅ SI' if settings.jwt_secret else '❌ NO'}")
logger.info(f"  - JWT Secret length: {len(settings.jwt_secret)} caracteres")
logger.info(f"  - JWT Secret primeros 20: {settings.jwt_secret[:20]}...")
logger.info(f"  - CORS Origins: {len(settings.allowed_origins)} orígenes")

# Verificar si el JWT_SECRET coincide con el esperado
expected_prefix = "bpt3Y5ayZtaZSydh"
if settings.jwt_secret.startswith(expected_prefix):
    logger.info("✅ JWT_SECRET coincide con el formato esperado")
else:
    logger.warning(f"⚠️ JWT_SECRET no coincide con el formato esperado. Comienza con: {settings.jwt_secret[:15]}...")

logger.info("=" * 60)
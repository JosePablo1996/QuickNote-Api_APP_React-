# app/main.py
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
import sys
import os

# Agregar el directorio raiz al path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import settings
from app.routes import notes_router, passkeys_router, auth_router, backup_router, upload_router

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Crear la aplicacion FastAPI
app = FastAPI(
    title="QuickNote API",
    description="API para la aplicacion de notas QuickNote con autenticacion biometrica, OTP, 2FA, Backup en la Nube y Seguridad Avanzada",
    version="2.5.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ============================================
# CONFIGURACION DE CORS
# ============================================

logger.info("Configurando CORS...")

origins = [
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:5175",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
    "http://127.0.0.1:3000",
    "https://quicknote-web-app.vercel.app",
    "https://quicknote-web-app-git-main-josepablo1996s-projects.vercel.app",
    "https://quicknote-web-app.onrender.com",
    "https://quicknote-api-app-react.onrender.com",
]

logger.info(f"✅ Origenes CORS permitidos ({len(origins)}):")
for origin in origins:
    logger.info(f"   - {origin}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "Accept",
        "Origin",
        "Access-Control-Request-Method",
        "Access-Control-Request-Headers",
    ],
    expose_headers=["*"],
    max_age=600,
)

# ============================================
# MIDDLEWARE PERSONALIZADO
# ============================================

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Middleware para loguear todas las peticiones."""
    logger.info(f"{request.method} {request.url.path}")
    
    auth_header = request.headers.get("Authorization")
    origin = request.headers.get("Origin")
    
    if auth_header:
        token_parts = auth_header.split(' ')
        if len(token_parts) > 1:
            logger.info(f"Authorization: {token_parts[0]} {token_parts[1][:30]}...")
        else:
            logger.info(f"Authorization: {auth_header[:30]}...")
    
    if origin:
        logger.info(f"Origin: {origin}")
        if origin in origins:
            logger.info(f"✅ Origin permitido por CORS")
        else:
            logger.warning(f"⚠️ Origin NO permitido por CORS: {origin}")
    
    response = await call_next(request)
    logger.info(f"Response status: {response.status_code}")
    
    return response

# ============================================
# EXCEPCION GLOBAL
# ============================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Manejador global de excepciones."""
    logger.error(f"Error no manejado: {str(exc)}")
    logger.exception("Stacktrace completo:")
    
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Error interno del servidor",
            "error": str(exc) if settings.debug else "Internal Server Error"
        }
    )

# ============================================
# INCLUIR ROUTERS
# ============================================

logger.info("Incluyendo rutas...")

app.include_router(notes_router, prefix="/api/v1")
app.include_router(passkeys_router, prefix="/api/v1")
app.include_router(auth_router, prefix="/api/v1")
app.include_router(backup_router, prefix="/api/v1")
app.include_router(upload_router, prefix="/api/v1")

logger.info("Rutas incluidas correctamente")
logger.info("  - /api/v1/notes/* -> CRUD de notas")
logger.info("  - /api/v1/passkeys/* -> Gestion de passkeys")
logger.info("  - /api/v1/auth/* -> Autenticacion")
logger.info("  - /api/v1/backup/* -> Backup en la Nube")
logger.info("  - /api/v1/upload/* -> Subida de imagenes")

# ============================================
# ENDPOINTS BASICOS
# ============================================

@app.get("/")
async def root():
    """Endpoint raiz."""
    return {
        "message": "QuickNote API",
        "version": "2.5.0",
        "status": "online",
        "docs": "/docs",
        "endpoints": {
            "health": "/health",
            "info": "/info",
            "notes": "/api/v1/notes",
            "passkeys": "/api/v1/passkeys",
            "auth": "/api/v1/auth",
            "backup": "/api/v1/backup",
            "upload": "/api/v1/upload",
            "2fa": "/api/v1/auth/2fa",
        }
    }

@app.get("/health")
async def health_check():
    """Endpoint de health check."""
    return {
        "status": "healthy",
        "service": "QuickNote API",
        "version": "2.5.0",
        "environment": settings.environment,
        "features": {
            "passkeys": True,
            "otp_auth": True,
            "two_factor": True,
            "notes_crud": True,
            "cloud_backup": True,
            "upload_images": True,
            "supabase": True
        }
    }

@app.get("/info")
async def api_info():
    """Endpoint de informacion de la API."""
    return {
        "name": "QuickNote API",
        "version": "2.5.0",
        "environment": settings.environment,
        "endpoints_disponibles": [
            "/docs",
            "/health",
            "/info",
            "/api/v1/notes",
            "/api/v1/passkeys",
            "/api/v1/auth",
            "/api/v1/backup",
            "/api/v1/upload/avatar - POST",
            "/api/v1/upload/banner - POST",
            "/api/v1/upload/avatar - DELETE",
            "/api/v1/upload/banner - DELETE"
        ],
        "upload": {
            "formatos_permitidos": ["JPEG", "PNG", "WEBP"],
            "tamano_maximo_avatar": "5MB",
            "tamano_maximo_banner": "10MB"
        }
    }

# ============================================
# EVENTOS DE INICIO
# ============================================

@app.on_event("startup")
async def startup_event():
    """Evento ejecutado al iniciar la aplicacion."""
    logger.info("=" * 60)
    logger.info("QUICKNOTE API INICIADA CORRECTAMENTE")
    logger.info(f"Version: 2.5.0")
    logger.info(f"Entorno: {settings.environment}")
    logger.info("")
    logger.info("Funcionalidades activas:")
    logger.info("   ✅ Passkeys (WebAuthn)")
    logger.info("   ✅ OTP por Email")
    logger.info("   ✅ 2FA (TOTP - Google Authenticator)")
    logger.info("   ✅ CRUD de Notas")
    logger.info("   ✅ Soft Delete (Papelera)")
    logger.info("   ✅ Restaurar Notas")
    logger.info("   ✅ Vaciar Papelera")
    logger.info("   ✅ Backup en la Nube")
    logger.info("   ✅ Subida de imagenes (Avatar/Banner)")
    logger.info("")
    logger.info("Endpoints principales:")
    logger.info("   - /docs - Documentacion")
    logger.info("   - /api/v1/upload/avatar - Subir avatar")
    logger.info("   - /api/v1/upload/banner - Subir banner")
    logger.info("=" * 60)

@app.on_event("shutdown")
async def shutdown_event():
    """Evento ejecutado al detener la aplicacion."""
    logger.info("Aplicacion detenida")
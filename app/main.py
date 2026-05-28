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
from app.routes import notes_router, passkeys_router, auth_router, backup_router

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
    version="2.4.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ============================================
# CONFIGURACION DE CORS (CORREGIDA)
# ============================================

logger.info("Configurando CORS...")

# ✅ LISTA COMPLETA Y CORREGIDA DE ORIGENES PERMITIDOS
origins = [
    # ==========================================
    # DESARROLLO LOCAL
    # ==========================================
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:5175",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
    "http://127.0.0.1:3000",
    
    # ==========================================
    # PRODUCCION - FRONTEND EN VERCEL
    # ==========================================
    "https://quicknote-web-app.vercel.app",
    "https://quicknote-web-app-git-main-josepablo1996s-projects.vercel.app",
    
    # ==========================================
    # ✅ CORREGIDO: PRODUCCION - FRONTEND EN RENDER
    # ==========================================
    "https://quicknote-web-app.onrender.com",
    
    # ==========================================
    # PRODUCCION - BACKEND EN RENDER (para auto-solicitudes)
    # ==========================================
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
        # Verificar si el origen está permitido
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

logger.info("Rutas incluidas correctamente")
logger.info("  - /api/v1/notes/* -> CRUD de notas")
logger.info("  - /api/v1/passkeys/* -> Gestion de passkeys")
logger.info("  - /api/v1/auth/* -> Autenticacion (OTP + 2FA + Seguridad)")
logger.info("  - /api/v1/backup/* -> Backup en la Nube")

# ============================================
# ENDPOINTS BASICOS
# ============================================

@app.get("/")
async def root():
    """Endpoint raiz."""
    return {
        "message": "QuickNote API",
        "version": "2.4.0",
        "status": "online",
        "docs": "/docs",
        "endpoints": {
            "health": "/health",
            "info": "/info",
            "notes": "/api/v1/notes",
            "passkeys": "/api/v1/passkeys",
            "auth": "/api/v1/auth",
            "backup": "/api/v1/backup",
            "2fa": "/api/v1/auth/2fa",
            "security": "/api/v1/auth/change-password",
            "forgot_password": "/api/v1/auth/forgot-password/send-otp"
        }
    }

@app.get("/health")
async def health_check():
    """Endpoint de health check."""
    return {
        "status": "healthy",
        "service": "QuickNote API",
        "version": "2.4.0",
        "environment": settings.environment,
        "features": {
            "passkeys": True,
            "otp_auth": True,
            "two_factor": True,
            "notes_crud": True,
            "cloud_backup": True,
            "password_history": True,
            "password_expiry": True,
            "security_events": True,
            "session_management": True,
            "forgot_password_otp": True,
            "supabase": True
        },
        "cors": {
            "allowed_origins": origins,
            "credentials_allowed": True
        }
    }

@app.get("/info")
async def api_info():
    """Endpoint de informacion de la API."""
    return {
        "name": "QuickNote API",
        "version": "2.4.0",
        "description": "API para gestion de notas con autenticacion biometrica, OTP, 2FA, Backup en la Nube y Seguridad Avanzada",
        "environment": settings.environment,
        "cors_origins": len(origins),
        "cors_allowed_origins": origins,
        "endpoints_disponibles": [
            "/docs - Documentacion Swagger",
            "/redoc - Documentacion ReDoc",
            "/health - Health check",
            "/info - Informacion de la API",
            "/api/v1/notes/* - CRUD de notas",
            "/api/v1/passkeys/* - Gestion de passkeys",
            "/api/v1/auth/send-otp - Enviar OTP",
            "/api/v1/auth/verify-otp - Verificar OTP",
            "/api/v1/auth/change-password - Cambiar contrasena",
            "/api/v1/auth/check-password-expiry - Verificar expiracion",
            "/api/v1/auth/logout-all-sessions - Cerrar todas las sesiones",
            "/api/v1/auth/password-policy - Politica de contrasenas",
            "/api/v1/auth/forgot-password/send-otp - Enviar OTP para reset",
            "/api/v1/auth/forgot-password/verify-otp - Verificar OTP para reset",
            "/api/v1/auth/forgot-password/reset - Resetear contrasena con OTP",
            "/api/v1/auth/2fa/enable - Activar 2FA",
            "/api/v1/auth/2fa/verify-enable - Verificar y activar 2FA",
            "/api/v1/auth/2fa/status - Estado 2FA",
            "/api/v1/auth/2fa/disable - Desactivar 2FA",
            "/api/v1/auth/2fa/verify-login - Verificar 2FA en login",
            "/api/v1/backup/cloud - Gestion de backups en la nube"
        ],
        "autenticacion": {
            "metodos": [
                "Email/Password (Supabase)",
                "Passkeys (WebAuthn)",
                "OTP por Email",
                "TOTP 2FA (Google Authenticator)"
            ],
            "jwt_algoritmos": ["HS256", "ES256"],
            "seguridad_avanzada": [
                "Historial de contrasenas",
                "Expiracion de contrasenas",
                "Prevencion de reutilizacion",
                "Cierre de sesiones remotas",
                "Eventos de seguridad",
                "Rate limiting",
                "Recuperacion por OTP"
            ]
        },
        "backup": {
            "metodos": [
                "Local backup (JSON download)",
                "Cloud backup (Supabase storage)"
            ],
            "seguridad": "Row Level Security - Solo el usuario puede acceder a sus backups"
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
    logger.info(f"Version: 2.4.0")
    logger.info(f"Entorno: {settings.environment}")
    logger.info(f"Supabase URL: {settings.supabase_url}")
    logger.info(f"Frontend CORS: {len(origins)} origenes permitidos")
    logger.info("")
    logger.info("Funcionalidades activas:")
    logger.info("   ✅ Passkeys (WebAuthn)")
    logger.info("   ✅ OTP por Email")
    logger.info("   ✅ 2FA (TOTP - Google Authenticator)")
    logger.info("   ✅ CRUD de Notas")
    logger.info("   ✅ Backup en la Nube")
    logger.info("   ✅ Historial de contrasenas")
    logger.info("   ✅ Expiracion de contrasenas")
    logger.info("   ✅ Prevencion de reutilizacion")
    logger.info("   ✅ Cierre de sesiones remotas")
    logger.info("   ✅ Eventos de seguridad")
    logger.info("   ✅ Recuperacion de contrasena por OTP")
    logger.info("")
    logger.info("Endpoints principales:")
    logger.info("   - /health - Health check")
    logger.info("   - /info - Informacion de la API")
    logger.info("   - /docs - Documentacion Swagger")
    logger.info("   - /api/v1/auth/change-password - Cambiar contrasena")
    logger.info("   - /api/v1/auth/password-policy - Politica de contrasenas")
    logger.info("   - /api/v1/auth/forgot-password/* - Recuperacion por OTP")
    logger.info("=" * 60)
    
    # Log adicional de CORS para verificar
    logger.info("📋 ORIGENES CORS PERMITIDOS:")
    for origin in origins:
        logger.info(f"   ✅ {origin}")

@app.on_event("shutdown")
async def shutdown_event():
    """Evento ejecutado al detener la aplicacion."""
    logger.info("Aplicacion detenida")
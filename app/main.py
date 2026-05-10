from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
import sys
import os

# Agregar el directorio raíz al path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import settings
from app.routes import notes_router, passkeys_router, auth_router  # ✅ auth_router agregado

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Crear la aplicación FastAPI
app = FastAPI(
    title="QuickNote API",
    description="API para la aplicación de notas QuickNote con autenticación biométrica y OTP",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ============================================
# CONFIGURACIÓN DE CORS
# ============================================

logger.info("Configurando CORS...")

origins = [
    # Desarrollo local
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:5175",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
    "http://127.0.0.1:3000",
    # Producción
    "https://quicknote-web-app.vercel.app",
    "https://quicknote-web-app-git-main-josepablo1996s-projects.vercel.app",
    "https://quicknote-api-app-react.onrender.com",
]

logger.info(f"Origenes permitidos: {origins}")

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
    """Middleware para loguear todas las peticiones"""
    logger.info(f"{request.method} {request.url.path}")
    
    # Log de headers importantes
    auth_header = request.headers.get("Authorization")
    origin = request.headers.get("Origin")
    
    if auth_header:
        logger.info(f"Authorization header presente: {auth_header[:30]}...")
    else:
        logger.warning("No Authorization header found")
    
    if origin:
        logger.info(f"Origin: {origin}")
    
    # Procesar la petición
    response = await call_next(request)
    
    logger.info(f"Response status: {response.status_code}")
    
    return response

# ============================================
# EXCEPCIÓN GLOBAL
# ============================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Manejador global de excepciones"""
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

# Prefix /api/v1 para todos los routers
app.include_router(notes_router, prefix="/api/v1")
app.include_router(passkeys_router, prefix="/api/v1")
app.include_router(auth_router, prefix="/api/v1")  # ✅ NUEVO: Router de autenticación (OTP)

logger.info("Rutas incluidas correctamente")

# ============================================
# ENDPOINTS BÁSICOS
# ============================================

@app.get("/")
async def root():
    """Endpoint raíz"""
    return {
        "message": "QuickNote API",
        "version": "2.0.0",
        "status": "online",
        "docs": "/docs",
        "endpoints": {
            "health": "/health",
            "info": "/info",
            "notes": "/api/v1/notes",
            "passkeys": "/api/v1/passkeys",
            "auth": "/api/v1/auth"  # ✅ NUEVO
        }
    }

@app.get("/health")
async def health_check():
    """Endpoint de health check"""
    return {
        "status": "healthy",
        "service": "QuickNote API",
        "version": "2.0.0",
        "environment": settings.environment,
        "features": {
            "passkeys": True,
            "otp_auth": True,  # ✅ NUEVO
            "notes_crud": True,
            "supabase": True
        }
    }

@app.get("/info")
async def api_info():
    """Endpoint de información de la API"""
    return {
        "name": "QuickNote API",
        "version": "2.0.0",
        "description": "API para gestión de notas con autenticación biométrica y OTP",
        "environment": settings.environment,
        "cors_origins": len(origins),
        "endpoints_disponibles": [
            "/docs - Documentación Swagger",
            "/redoc - Documentación ReDoc",
            "/health - Health check",
            "/info - Información de la API",
            "/api/v1/notes/* - CRUD de notas",
            "/api/v1/passkeys/* - Gestión de passkeys",
            "/api/v1/auth/* - Autenticación (OTP)"  # ✅ NUEVO
        ],
        "autenticacion": {
            "metodos": [
                "Email/Password (Supabase)",
                "Passkeys (WebAuthn)",
                "OTP por Email"  # ✅ NUEVO
            ],
            "jwt_algoritmos": ["HS256", "ES256"]
        }
    }

# ============================================
# EVENTOS DE INICIO
# ============================================

@app.on_event("startup")
async def startup_event():
    """Evento ejecutado al iniciar la aplicación"""
    logger.info("=" * 60)
    logger.info("APLICACION INICIADA CORRECTAMENTE")
    logger.info(f"Entorno: {settings.environment}")
    logger.info(f"Supabase URL: {settings.supabase_url}")
    logger.info(f"JWT Secret configurado: {'SI' if settings.jwt_secret else 'NO'}")
    logger.info(f"JWT Secret (primeros 20): {settings.jwt_secret[:20] if settings.jwt_secret else 'N/A'}...")
    logger.info(f"Passkeys: Configurado y activo")
    logger.info(f"OTP Auth: Configurado y activo")  # ✅ NUEVO
    logger.info(f"CORS Origins: {len(origins)} origenes")
    logger.info("Endpoints disponibles:")
    logger.info("   - /health - Health check")
    logger.info("   - /info - Informacion de la API")
    logger.info("   - /docs - Documentacion Swagger")
    logger.info("   - /api/v1/notes/* - CRUD de notas")
    logger.info("   - /api/v1/passkeys/* - Gestion de passkeys")
    logger.info("   - /api/v1/auth/* - Autenticacion (OTP)")  # ✅ NUEVO
    logger.info("=" * 60)

@app.on_event("shutdown")
async def shutdown_event():
    """Evento ejecutado al detener la aplicación"""
    logger.info("Aplicación detenida")
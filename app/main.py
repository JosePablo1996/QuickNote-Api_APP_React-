# main.py - VERSIÓN MEJORADA CON PASSKEYS
from fastapi import FastAPI, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
import logging
import sys
import json
from typing import Dict, Any

# 🔧 CONFIGURACIÓN DE LOGGING
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
    ]
)

logger = logging.getLogger(__name__)
logger.info("=" * 60)
logger.info("🚀 Iniciando aplicación QuickNote API")
logger.info("=" * 60)

from app.routes import notes
from app.routes import passkeys  # ✅ NUEVO: Rutas de passkeys
from app.config import settings
from app.services.passkey_service import passkey_service  # ✅ NUEVO: Servicio de passkeys

app = FastAPI(
    title=settings.project_name,
    version=settings.version,
    description=settings.description,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ✅ CONFIGURACIÓN CORS MEJORADA
logger.info("🔧 Configurando CORS...")
logger.info(f"📋 Orígenes permitidos: {settings.get_allowed_origins()}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*", "Authorization", "Content-Type", "Accept", "Origin", "X-Requested-With"],
    expose_headers=["*"],
    max_age=600,
)

# ✅ MIDDLEWARE PARA DEPURACIÓN DE TOKENS Y PASSKEYS
@app.middleware("http")
async def log_requests(request: Request, call_next):
    # Log de la petición entrante
    logger.info(f"📥 {request.method} {request.url.path}")
    
    # Log de headers importantes
    auth_header = request.headers.get("authorization")
    if auth_header:
        logger.info(f"🔑 Authorization header presente: {auth_header[:30]}...")
    else:
        logger.warning("⚠️ No Authorization header found")
    
    origin = request.headers.get("origin")
    if origin:
        logger.info(f"🌐 Origin: {origin}")
    
    # ✅ Nuevo: Log para passkey requests
    if "/passkeys" in request.url.path:
        logger.info("🔐 Procesando solicitud de passkey")
    
    # Procesar la petición
    response = await call_next(request)
    
    # Log de la respuesta
    logger.info(f"📤 Response status: {response.status_code}")
    
    return response

# Incluir rutas
logger.info("🔄 Incluyendo rutas...")
app.include_router(notes.router, prefix="/api/v1")
app.include_router(passkeys.router, prefix="/api/v1")  # ✅ NUEVO: Rutas de passkeys
logger.info("✅ Rutas incluidas correctamente")

@app.get("/")
async def root():
    logger.info("📢 Endpoint root llamado")
    return {
        "message": "📝 Welcome to QuickNote API",
        "version": settings.version,
        "environment": settings.environment,
        "jwt_configured": bool(settings.jwt_secret),
        "passkey_enabled": True,  # ✅ NUEVO: Indicar que passkeys están disponibles
        "cors_origins": settings.get_allowed_origins(),
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "jwt_configured": bool(settings.jwt_secret),
        "passkey_endpoints": "/api/v1/passkeys/*",  # ✅ NUEVO: Ruta de passkeys en health check
        "services": {
            "supabase": bool(settings.supabase_url and settings.supabase_key),
            "jwt": bool(settings.jwt_secret),
            "passkey": True  # ✅ NUEVO: Servicio de passkey
        }
    }

@app.get("/info")  # ✅ NUEVO: Endpoint de información detallada
async def api_info():
    """Endpoint informativo con todos los servicios disponibles"""
    return {
        "api": {
            "name": settings.project_name,
            "version": settings.version,
            "description": settings.description,
            "environment": settings.environment
        },
        "authentication": {
            "methods": ["jwt", "passkey"],
            "jwt_config": bool(settings.jwt_secret),
            "passkey_enabled": True,
            "passkey_endpoints": {
                "register_start": "/api/v1/passkeys/register/start",
                "register_complete": "/api/v1/passkeys/register/complete",
                "login_start": "/api/v1/passkeys/login/start",
                "login_complete": "/api/v1/passkeys/login/complete",
                "list": "/api/v1/passkeys/list/{user_id}",
                "delete": "/api/v1/passkeys/{credential_id}"
            }
        },
        "endpoints": {
            "health": "/health",
            "info": "/info",
            "docs": "/docs",
            "redoc": "/redoc",
            "notes": "/api/v1/notes/*",
            "passkeys": "/api/v1/passkeys/*"
        },
        "cors": {
            "origins": settings.get_allowed_origins(),
            "count": len(settings.get_allowed_origins())
        }
    }

@app.on_event("startup")
async def startup_event():
    logger.info("=" * 60)
    logger.info("✅ APLICACIÓN INICIADA CORRECTAMENTE")
    logger.info(f"🌐 Entorno: {settings.environment}")
    logger.info(f"🔗 Supabase URL: {settings.supabase_url}")
    logger.info(f"🔑 JWT Secret configurado: {'✅ SI' if settings.jwt_secret else '❌ NO'}")
    logger.info(f"🔑 JWT Secret (primeros 20): {settings.jwt_secret[:20]}...")
    logger.info(f"🔐 Passkeys: Configurado y activo")  # ✅ NUEVO
    logger.info(f"📋 CORS Origins: {len(settings.get_allowed_origins())} orígenes")
    logger.info(f"📡 Endpoints disponibles:")
    logger.info(f"   - /health - Health check")
    logger.info(f"   - /info - Información de la API")
    logger.info(f"   - /docs - Documentación Swagger")
    logger.info(f"   - /api/v1/notes/* - CRUD de notas")
    logger.info(f"   - /api/v1/passkeys/* - Gestión de passkeys")
    logger.info("=" * 60)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
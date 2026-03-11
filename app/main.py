# main.py - VERSIÓN CORREGIDA CON LOGGING
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import logging
import sys

# 🔧 CONFIGURACIÓN DE LOGGING - IMPORTANTE PARA VER LOS LOGS EN RENDER
logging.basicConfig(
    level=logging.INFO,  # Cambiar a DEBUG para más detalles
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),  # Forzar salida a stdout
        logging.StreamHandler(sys.stderr),  # También a stderr por si acaso
    ]
)

# Configurar loggers específicos
logging.getLogger("app.services.supabase_client").setLevel(logging.INFO)
logging.getLogger("app.routes.notes").setLevel(logging.INFO)
logging.getLogger("app.config").setLevel(logging.INFO)
logging.getLogger("uvicorn").setLevel(logging.INFO)
logging.getLogger("uvicorn.access").setLevel(logging.INFO)

logger = logging.getLogger(__name__)
logger.info("=" * 60)
logger.info("🚀 Iniciando aplicación QuickNote API")
logger.info("=" * 60)

from app.routes import notes
from app.config import settings

app = FastAPI(
    title=settings.project_name,
    version=settings.version,
    description=settings.description,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ✅ CONFIGURACIÓN CORS
logger.info("🔧 Configurando CORS...")
logger.info(f"📋 Orígenes permitidos: {settings.get_allowed_origins()}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=600,
)

# ✅ MIDDLEWARE DE RESPALDO - SIEMPRE AÑADIR CABECERAS
@app.middleware("http")
async def add_cors_headers(request, call_next):
    logger.debug(f"📥 Request: {request.method} {request.url.path}")
    response = await call_next(request)
    origin = request.headers.get("origin")
    
    # Siempre añadir cabeceras para orígenes conocidos
    if origin and origin in settings.get_allowed_origins():
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "*"
        logger.debug(f"✅ CORS headers añadidos para origen: {origin}")
    
    return response

# ✅ RUTAS OPTIONS MANUALES - POR SI ACASO
@app.options("/{path:path}")
async def options_handler(path: str):
    logger.debug(f"📋 OPTIONS request para: {path}")
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "*",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Max-Age": "600",
        }
    )

# Incluir rutas - ✅ IMPORTANTE: usar el router correcto
logger.info("🔄 Incluyendo rutas...")
app.include_router(notes.router, prefix="/api/v1")
logger.info("✅ Rutas incluidas correctamente")

# Endpoint de prueba para verificar CORS
@app.get("/api/v1/notes-test")
async def get_notes_test(deleted: bool = False):
    """Endpoint temporal para pruebas"""
    logger.info(f"🔍 Test endpoint llamado con deleted={deleted}")
    return {"message": "API funcionando", "deleted": deleted, "notes": []}

@app.get("/")
async def root():
    logger.info("📢 Endpoint root llamado")
    return {
        "message": "📝 Welcome to QuickNote API",
        "version": settings.version,
        "environment": settings.environment,
        "cors_origins": settings.get_allowed_origins(),
    }

@app.get("/health")
async def health_check():
    logger.debug("🏥 Health check")
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
    }

@app.on_event("startup")
async def startup_event():
    logger.info("✅ Aplicación iniciada correctamente")
    logger.info(f"🌐 Entorno: {settings.environment}")
    logger.info(f"🔗 Supabase URL: {settings.supabase_url}")
    logger.info(f"🔑 JWT Secret configurado: {settings.jwt_secret[:20]}...")
    logger.info(f"📋 CORS Origins: {len(settings.get_allowed_origins())} orígenes")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("👋 Aplicación deteniéndose")

if __name__ == "__main__":
    import uvicorn
    logger.info("🚀 Iniciando servidor uvicorn...")
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
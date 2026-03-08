# main.py - VERSIÓN CORREGIDA
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime

from app.routes import notes_router
from app.config import settings

app = FastAPI(
    title=settings.project_name,
    version=settings.version,
    description=settings.description,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ✅ CONFIGURACIÓN CORS - VERSIÓN MÁS PERMISIVA PARA DIAGNÓSTICO
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:5175",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://127.0.0.1:3000",
        "https://quicknote-web-app.vercel.app",
        "https://quicknote-web-app-git-main-josepablo1996s-projects.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],  # ✅ Permitir TODOS los métodos
    allow_headers=["*"],  # ✅ Permitir TODOS los headers
    expose_headers=["*"],
    max_age=600,
)

# ✅ MIDDLEWARE DE RESPALDO - SIEMPRE AÑADIR CABECERAS
@app.middleware("http")
async def add_cors_headers(request, call_next):
    response = await call_next(request)
    origin = request.headers.get("origin")
    
    # Siempre añadir cabeceras para orígenes conocidos
    if origin and origin in [
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:5175",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://127.0.0.1:3000",
        "https://quicknote-web-app.vercel.app",
        "https://quicknote-web-app-git-main-josepablo1996s-projects.vercel.app",
    ]:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "*"
    
    return response

# ✅ RUTAS OPTIONS MANUALES - POR SI ACASO
@app.options("/{path:path}")
async def options_handler():
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

# Incluir rutas
app.include_router(notes_router, prefix="/api/v1")

# Endpoint de prueba para verificar CORS
@app.get("/api/v1/notes")
async def get_notes(deleted: bool = False):
    """Endpoint temporal para pruebas"""
    return {"message": "API funcionando", "deleted": deleted, "notes": []}

@app.get("/")
async def root():
    return {
        "message": "📝 Welcome to QuickNote API",
        "version": settings.version,
        "environment": settings.environment,
        "cors_origins": settings.get_allowed_origins(),
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
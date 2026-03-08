# main.py
from fastapi import FastAPI, Response  # ✅ Añadir Response
from fastapi import FastAPI
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

# ✅ CONFIGURACIÓN CORS COMPLETA
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "https://quicknote-web-app.vercel.app",
        "https://quicknote-web-app-git-main-josepablo1996s-projects.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],  # ✅ Incluir OPTIONS
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=600,  # Cache preflight requests for 10 minutes
)

# ✅ MIDDLEWARE PARA ASEGURAR CORS EN TODAS LAS RESPUESTAS
@app.middleware("http")
async def add_cors_headers(request, call_next):
    response = await call_next(request)
    
    # Añadir cabeceras CORS manualmente como respaldo
    origin = request.headers.get("origin")
    if origin in [
        "http://localhost:5173",
        "https://quicknote-web-app.vercel.app",
        "https://quicknote-web-app-git-main-josepablo1996s-projects.vercel.app",
    ]:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    
    return response

# ✅ RUTA ESPECÍFICA PARA MANEJAR OPTIONS EN /notes/
@app.options("/api/v1/notes/")
async def options_notes():
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Allow-Credentials": "true",
        }
    )

# ✅ RUTA ESPECÍFICA PARA MANEJAR OPTIONS EN /notes (sin slash)
@app.options("/api/v1/notes")
async def options_notes_no_slash():
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Allow-Credentials": "true",
        }
    )

app.include_router(notes_router, prefix="/api/v1")

@app.get("/")
async def root():
    return {
        "message": "📝 Welcome to QuickNote API",
        "version": settings.version,
        "environment": settings.environment,
        "documentation": {
            "swagger": "/docs",
            "redoc": "/redoc"
        },
        "endpoints": {
            "notes": "/api/v1/notes"
        }
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "database": "connected (simulado)"
    }

@app.get("/api/v1")
async def api_root():
    return {
        "message": "QuickNote API v1",
        "available_endpoints": {
            "GET /notes": "Listar todas las notas (usar /api/v1/notes/)",
            "GET /notes/{id}": "Obtener una nota específica",
            "POST /notes": "Crear una nueva nota",
            "PUT /notes/{id}": "Actualizar una nota existente",
            "DELETE /notes/{id}": "Eliminar una nota",
            "POST /notes/sync": "Sincronizar múltiples notas"
        }
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
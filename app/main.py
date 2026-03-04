from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime  # IMPORTANTE: esto faltaba

from app.routes import notes_router
from app.config import settings

app = FastAPI(
    title=settings.project_name,
    version=settings.version,
    description=settings.description,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
    """Endpoint para verificar que la API está funcionando correctamente"""
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
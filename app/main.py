# main.py
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

# ✅ USAR el método get_allowed_origins() de settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=600,
)

# ✅ MIDDLEWARE PARA CORS
@app.middleware("http")
async def add_cors_headers(request, call_next):
    response = await call_next(request)
    origin = request.headers.get("origin")
    
    # Usar la misma lista de orígenes
    if origin in settings.get_allowed_origins():
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    
    return response

# ✅ RUTA PARA NOTES CON PARÁMETRO deleted=true
@app.get("/api/v1/notes")
async def get_notes(deleted: bool = False):
    """
    Obtener notas, con opción de filtrar por eliminadas
    - deleted=false (default): solo notas activas
    - deleted=true: solo notas eliminadas
    """
    # Aquí iría la lógica para obtener notas de la base de datos
    # Por ahora es un placeholder
    return {"message": "Endpoint de notas - implementar después"}

# ✅ RUTA ESPECÍFICA PARA OPTIONS
@app.options("/api/v1/notes")
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

@app.options("/api/v1/notes/")
async def options_notes_slash():
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
        "documentation": { "swagger": "/docs", "redoc": "/redoc" },
        "endpoints": { "notes": "/api/v1/notes" }
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
            "GET /notes?deleted=true": "Obtener notas eliminadas",
            "GET /notes/": "Obtener todas las notas",
            "GET /notes/{id}": "Obtener una nota específica",
            "POST /notes": "Crear una nueva nota",
            "PUT /notes/{id}": "Actualizar una nota existente",
            "DELETE /notes/{id}": "Eliminar una nota",
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
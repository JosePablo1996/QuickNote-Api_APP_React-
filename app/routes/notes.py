from fastapi import APIRouter, HTTPException, Depends, Header
from typing import List, Optional
from uuid import UUID
from datetime import datetime
import jwt
from jwt import PyJWKClient, InvalidTokenError
import logging
import httpx

from app.models.note import NoteCreate, NoteUpdate, NoteInDB
from app.services.supabase_client import supabase_client
from app.config import settings

# Configurar logger
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/notes", tags=["notes"])

# Constantes
JWT_SECRET = settings.jwt_secret if hasattr(settings, 'jwt_secret') else "quicknote-super-secret-jwt-key-change-in-production"
SUPABASE_URL = settings.supabase_url if hasattr(settings, 'supabase_url') else ""
SUPABASE_JWKS_URL = f"{SUPABASE_URL}/auth/v1/jwks" if SUPABASE_URL else ""

# Cache del cliente JWKS
_jwks_client = None

def get_jwks_client():
    """Obtener cliente JWKS para verificar tokens de Supabase (ES256)"""
    global _jwks_client
    if _jwks_client is None and SUPABASE_JWKS_URL:
        _jwks_client = PyJWKClient(SUPABASE_JWKS_URL)
    return _jwks_client

def decode_token_hs256(token: str) -> dict:
    """
    Decodifica token JWT con algoritmo HS256.
    Usado para tokens generados por passkey/login tradicional.
    """
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            options={
                "verify_exp": True,
                "verify_aud": False
            }
        )
        logger.info("✅ Token HS256 decodificado correctamente")
        return payload
    except InvalidTokenError as e:
        logger.warning(f"⚠️ Token no es HS256: {str(e)}")
        raise

def decode_token_es256(token: str) -> dict:
    """
    Decodifica token JWT con algoritmo ES256.
    Usado para tokens generados por Supabase Auth.
    """
    try:
        jwks_client = get_jwks_client()
        if not jwks_client:
            raise ValueError("JWKS client no disponible (SUPABASE_URL no configurada)")
        
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["ES256"],
            audience="authenticated",
            options={
                "verify_exp": True,
                "verify_aud": False
            }
        )
        logger.info("✅ Token ES256 (Supabase) decodificado correctamente")
        return payload
    except Exception as e:
        logger.warning(f"⚠️ Token no es ES256: {str(e)}")
        raise

async def get_token(authorization: Optional[str] = Header(None)):
    """
    Extrae y valida el token JWT del header Authorization.
    Soporta tanto HS256 (passkey/login) como ES256 (Supabase).
    """
    if not authorization:
        logger.error("❌ Token no proporcionado en header")
        raise HTTPException(status_code=401, detail="Token no proporcionado")
    
    logger.info(f"📥 Header Authorization recibido: {authorization[:50]}...")
    
    if not authorization.startswith("Bearer "):
        logger.error(f"❌ Formato inválido: {authorization[:30]}...")
        raise HTTPException(status_code=401, detail="Formato de token inválido")
    
    token = authorization.replace("Bearer ", "")
    logger.info(f"🔑 Token extraído: {token[:50]}...")
    logger.info(f"🔑 Longitud del token: {len(token)} caracteres")
    
    # Determinar tipo de token por el encabezado
    try:
        header = jwt.get_unverified_header(token)
        alg = header.get("alg", "desconocido")
        logger.info(f"🔐 Algoritmo del token: {alg}")
    except Exception:
        alg = "desconocido"
    
    # Intentar decodificar con ambos algoritmos
    payload = None
    error_msg = ""
    
    # Primero intentar con HS256
    try:
        payload = decode_token_hs256(token)
    except Exception as e:
        error_msg += f"HS256: {str(e)}. "
    
    # Si falló HS256, intentar con ES256
    if payload is None:
        try:
            payload = decode_token_es256(token)
        except Exception as e:
            error_msg += f"ES256: {str(e)}"
    
    if payload is None:
        logger.error(f"❌ Token inválido ({alg}): {error_msg}")
        raise HTTPException(status_code=401, detail=f"Token inválido: {error_msg}")
    
    # Extraer user_id del payload (soporta ambos formatos)
    user_id = (
        payload.get("userId") or 
        payload.get("sub") or 
        payload.get("user_id")
    )
    email = payload.get("email") or payload.get("user_metadata", {}).get("email")
    
    logger.info(f"✅ Token decodificado correctamente")
    logger.info(f"👤 User ID: {user_id}")
    logger.info(f"📧 Email: {email}")
    
    if not user_id:
        logger.error("❌ El payload no contiene userId, sub ni user_id")
        logger.info(f"📦 Payload recibido: {payload}")
        raise HTTPException(status_code=401, detail="Token no contiene user_id")
    
    return {
        "token": token,
        "user_id": user_id,
        "email": email,
        "payload": payload
    }

@router.get("/", response_model=List[NoteInDB])
async def get_notes(
    deleted: bool = False,
    auth: dict = Depends(get_token)
):
    """Obtener todas las notas del usuario autenticado"""
    try:
        user_id = auth["user_id"]
        token = auth["token"]
        logger.info("=" * 50)
        logger.info(f"📥 GET /notes - Iniciando petición")
        logger.info(f"👤 Usuario: {user_id}")
        logger.info(f"🔍 Filtro deleted: {deleted}")
        logger.info(f"🔑 Token (primeros 50): {token[:50]}...")
        
        # Crear cliente con el token del usuario
        logger.info("🔄 Creando cliente con token...")
        user_client = supabase_client.with_token(token)
        logger.info("✅ Cliente con token creado exitosamente")
        
        # Construir query
        logger.info(f"🔍 Construyendo query para tabla 'notes'")
        query = user_client.table("notes")\
            .select("*")\
            .eq("user_id", str(user_id))
        
        if deleted:
            query = query.is_not_null("deleted_at")
            logger.info("📌 Filtrando: notas eliminadas (deleted_at NOT NULL)")
        else:
            query = query.is_null("deleted_at")
            logger.info("📌 Filtrando: notas activas (deleted_at IS NULL)")
        
        query = query.order("updated_at", desc=True)
        logger.info("📤 Ejecutando query en Supabase...")
        
        # ✅ CORREGIDO: select necesita .execute()
        result = query.execute()
        
        logger.info(f"✅ Query ejecutada exitosamente")
        logger.info(f"📊 Notas encontradas: {len(result) if result else 0}")
        logger.info("=" * 50)
        
        return result if result else []
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en get_notes: {str(e)}")
        logger.exception("📝 Stacktrace completo:")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{note_id}", response_model=NoteInDB)
async def get_note(
    note_id: UUID,
    auth: dict = Depends(get_token)
):
    """Obtener una nota por ID (solo si pertenece al usuario)"""
    try:
        user_id = auth["user_id"]
        token = auth["token"]
        logger.info("=" * 50)
        logger.info(f"🔍 GET /notes/{note_id}")
        logger.info(f"👤 Usuario: {user_id}")
        logger.info(f"🔑 Token: {token[:50]}...")
        
        # Crear cliente con el token del usuario
        logger.info("🔄 Creando cliente con token...")
        user_client = supabase_client.with_token(token)
        logger.info("✅ Cliente con token creado")
        
        logger.info(f"🔍 Buscando nota con ID: {note_id}")
        # ✅ CORREGIDO: select necesita .execute()
        result = user_client.table("notes")\
            .select("*")\
            .eq("id", str(note_id))\
            .eq("user_id", str(user_id))\
            .execute()
        
        if not result:
            logger.warning(f"⚠️ Nota {note_id} no encontrada para usuario {user_id}")
            raise HTTPException(status_code=404, detail="Nota no encontrada")
        
        logger.info(f"✅ Nota encontrada: {note_id}")
        logger.info("=" * 50)
        return result[0]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en get_note: {str(e)}")
        logger.exception("📝 Stacktrace completo:")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/", response_model=NoteInDB, status_code=201)
async def create_note(
    note: NoteCreate,
    auth: dict = Depends(get_token)
):
    """Crear una nueva nota para el usuario autenticado"""
    try:
        user_id = auth["user_id"]
        token = auth["token"]
        logger.info("=" * 50)
        logger.info(f"📝 POST /notes - Creando nueva nota")
        logger.info(f"👤 Usuario: {user_id}")
        logger.info(f"🔑 Token: {token[:50]}...")
        
        # Crear cliente con el token del usuario
        logger.info("🔄 Creando cliente con token...")
        user_client = supabase_client.with_token(token)
        logger.info("✅ Cliente con token creado")
        
        # Preparar datos de la nota
        note_data = note.model_dump(exclude_unset=True)
        note_data["user_id"] = str(user_id)
        note_data["created_at"] = datetime.now().isoformat()
        note_data["updated_at"] = datetime.now().isoformat()
        
        logger.info(f"📦 Datos a insertar:")
        logger.info(f"  - Título: {note_data.get('title')}")
        logger.info(f"  - Contenido: {note_data.get('content')[:50]}..." if note_data.get('content') else "  - Contenido: None")
        logger.info(f"  - Color: {note_data.get('color')}")
        logger.info(f"  - Favorito: {note_data.get('is_favorite')}")
        logger.info(f"  - Archivado: {note_data.get('is_archived')}")
        logger.info(f"  - Tags: {note_data.get('tags')}")
        logger.info(f"  - User ID: {note_data.get('user_id')}")
        
        logger.info("📤 Insertando en Supabase...")
        # ✅ CORREGIDO: insert() ya ejecuta automáticamente (sin .execute())
        result = user_client.table("notes").insert(note_data)
        
        if not result:
            logger.error("❌ Supabase no devolvió resultados después de insertar")
            raise HTTPException(status_code=500, detail="Error al crear nota: no se recibió respuesta")
        
        logger.info(f"✅ Nota creada exitosamente")
        logger.info(f"📌 ID de la nueva nota: {result[0]['id']}")
        logger.info("=" * 50)
        return result[0]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en create_note: {str(e)}")
        logger.exception("📝 Stacktrace completo:")
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/{note_id}", response_model=NoteInDB)
async def update_note(
    note_id: UUID,
    note: NoteUpdate,
    auth: dict = Depends(get_token)
):
    """Actualizar una nota existente (solo si pertenece al usuario)"""
    try:
        user_id = auth["user_id"]
        token = auth["token"]
        logger.info("=" * 50)
        logger.info(f"✏️ PUT /notes/{note_id} - Actualizando nota")
        logger.info(f"👤 Usuario: {user_id}")
        logger.info(f"🔑 Token: {token[:50]}...")
        
        # Crear cliente con el token del usuario
        logger.info("🔄 Creando cliente con token...")
        user_client = supabase_client.with_token(token)
        logger.info("✅ Cliente con token creado")
        
        # Verificar que la nota existe y pertenece al usuario
        logger.info(f"🔍 Verificando existencia de nota {note_id}")
        # ✅ CORREGIDO: select necesita .execute()
        existing = user_client.table("notes")\
            .select("id")\
            .eq("id", str(note_id))\
            .eq("user_id", str(user_id))\
            .execute()
        
        if not existing:
            logger.warning(f"⚠️ Nota {note_id} no encontrada para usuario {user_id}")
            raise HTTPException(status_code=404, detail="Nota no encontrada")
        
        logger.info(f"✅ Nota encontrada, procediendo con actualización")
        
        # Preparar datos de actualización
        update_data = note.model_dump(exclude_unset=True)
        update_data["updated_at"] = datetime.now().isoformat()
        
        logger.info(f"📦 Datos a actualizar: {update_data}")
        
        # Actualizar
        logger.info("📤 Enviando actualización a Supabase...")
        # ✅ CORREGIDO: update() necesita filtros + .execute()
        result = user_client.table("notes")\
            .update(update_data)\
            .eq("id", str(note_id))\
            .eq("user_id", str(user_id))\
            .execute()
        
        if not result:
            logger.error("❌ Supabase no devolvió resultados después de actualizar")
            raise HTTPException(status_code=500, detail="Error al actualizar nota")
        
        logger.info(f"✅ Nota {note_id} actualizada exitosamente")
        logger.info("=" * 50)
        return result[0]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en update_note: {str(e)}")
        logger.exception("📝 Stacktrace completo:")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{note_id}", status_code=204)
async def delete_note(
    note_id: UUID,
    auth: dict = Depends(get_token)
):
    """Eliminar una nota permanentemente (solo si pertenece al usuario)"""
    try:
        user_id = auth["user_id"]
        token = auth["token"]
        logger.info("=" * 50)
        logger.info(f"🗑️ DELETE /notes/{note_id} - Eliminando nota")
        logger.info(f"👤 Usuario: {user_id}")
        logger.info(f"🔑 Token: {token[:50]}...")
        
        # Crear cliente con el token del usuario
        logger.info("🔄 Creando cliente con token...")
        user_client = supabase_client.with_token(token)
        logger.info("✅ Cliente con token creado")
        
        # Verificar que la nota existe y pertenece al usuario
        logger.info(f"🔍 Verificando existencia de nota {note_id}")
        # ✅ CORREGIDO: select necesita .execute()
        existing = user_client.table("notes")\
            .select("id")\
            .eq("id", str(note_id))\
            .eq("user_id", str(user_id))\
            .execute()
        
        if not existing:
            logger.warning(f"⚠️ Nota {note_id} no encontrada para usuario {user_id}")
            raise HTTPException(status_code=404, detail="Nota no encontrada")
        
        logger.info(f"✅ Nota encontrada, procediendo con eliminación")
        
        # Eliminar
        logger.info("📤 Enviando solicitud de eliminación a Supabase...")
        # ✅ CORREGIDO: delete() necesita filtros + .execute()
        user_client.table("notes")\
            .delete()\
            .eq("id", str(note_id))\
            .eq("user_id", str(user_id))\
            .execute()
        
        logger.info(f"✅ Nota {note_id} eliminada permanentemente")
        logger.info("=" * 50)
        return None
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en delete_note: {str(e)}")
        logger.exception("📝 Stacktrace completo:")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/sync", response_model=List[NoteInDB])
async def sync_notes(
    notes: List[NoteCreate],
    auth: dict = Depends(get_token)
):
    """Sincronizar múltiples notas para el usuario autenticado"""
    try:
        user_id = auth["user_id"]
        token = auth["token"]
        logger.info("=" * 50)
        logger.info(f"🔄 POST /notes/sync - Sincronizando notas")
        logger.info(f"👤 Usuario: {user_id}")
        logger.info(f"📊 Notas a sincronizar: {len(notes)}")
        logger.info(f"🔑 Token: {token[:50]}...")
        
        # Crear cliente con el token del usuario
        logger.info("🔄 Creando cliente con token...")
        user_client = supabase_client.with_token(token)
        logger.info("✅ Cliente con token creado")
        
        synced_notes = []
        for i, note in enumerate(notes):
            logger.info(f"📝 Procesando nota {i+1} de {len(notes)}")
            note_data = note.model_dump(exclude_unset=True)
            note_data["user_id"] = str(user_id)
            note_data["updated_at"] = datetime.now().isoformat()
            note_data["created_at"] = datetime.now().isoformat()
            
            logger.info(f"  - Título: {note_data.get('title')}")
            
            # ✅ CORREGIDO: upsert() ya ejecuta automáticamente (sin .execute())
            result = user_client.table("notes").upsert(note_data)
            
            if result:
                synced_notes.extend(result)
                logger.info(f"  ✅ Nota sincronizada: {result[0]['id']}")
        
        logger.info(f"✅ Sincronización completada: {len(synced_notes)} notas procesadas")
        logger.info("=" * 50)
        return synced_notes
        
    except Exception as e:
        logger.error(f"❌ Error en sync_notes: {str(e)}")
        logger.exception("📝 Stacktrace completo:")
        raise HTTPException(status_code=500, detail=str(e))
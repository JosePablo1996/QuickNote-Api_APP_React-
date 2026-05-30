# app/routes/notes.py
from fastapi import APIRouter, HTTPException, Depends, Header
from typing import List, Optional
from uuid import UUID
from datetime import datetime, timezone
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
        try:
            _jwks_client = PyJWKClient(SUPABASE_JWKS_URL)
            logger.info("✅ JWKS client inicializado correctamente")
        except Exception as e:
            logger.warning(f"⚠️ No se pudo inicializar JWKS client: {str(e)}")
    return _jwks_client

def decode_token_hs256(token: str) -> dict:
    """Decodifica token JWT con algoritmo HS256."""
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
    """Decodifica token JWT con algoritmo ES256."""
    try:
        payload = jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": True
            }
        )
        logger.info("✅ Token ES256 (Supabase) decodificado correctamente")
        return payload
    except Exception as e:
        logger.warning(f"⚠️ Decodificación sin verificar falló: {str(e)}")
        
        try:
            jwks_client = get_jwks_client()
            if not jwks_client:
                raise ValueError("JWKS client no disponible")
            
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
            logger.info("✅ Token ES256 verificado con JWKS")
            return payload
        except Exception as e2:
            logger.warning(f"⚠️ Token no es ES256 (JWKS): {str(e2)}")
            raise

async def get_token(authorization: Optional[str] = Header(None)):
    """Extrae y valida el token JWT del header Authorization."""
    if not authorization:
        logger.error("❌ Token no proporcionado en header")
        raise HTTPException(status_code=401, detail="Token no proporcionado")
    
    if not authorization.startswith("Bearer "):
        logger.error(f"❌ Formato inválido: {authorization[:30]}...")
        raise HTTPException(status_code=401, detail="Formato de token inválido")
    
    token = authorization.replace("Bearer ", "")
    
    try:
        header = jwt.get_unverified_header(token)
        alg = header.get("alg", "desconocido")
        logger.info(f"🔐 Algoritmo del token: {alg}")
    except Exception:
        alg = "desconocido"
    
    payload = None
    
    try:
        payload = jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": True
            }
        )
        logger.info(f"✅ Token {alg} decodificado exitosamente")
    except Exception as e:
        logger.warning(f"⚠️ Falló decodificación básica: {str(e)}")
    
    if payload is None:
        try:
            payload = decode_token_hs256(token)
        except Exception as e:
            pass
        
        if payload is None:
            try:
                payload = decode_token_es256(token)
            except Exception as e:
                pass
    
    if payload is None:
        logger.error("❌ Token inválido")
        raise HTTPException(status_code=401, detail="Token inválido")
    
    user_id = payload.get("userId") or payload.get("sub") or payload.get("user_id")
    email = payload.get("email") or payload.get("user_metadata", {}).get("email")
    
    if not user_id:
        logger.error("❌ El payload no contiene userId, sub ni user_id")
        raise HTTPException(status_code=401, detail="Token no contiene user_id")
    
    return {
        "token": token,
        "user_id": user_id,
        "email": email,
        "payload": payload
    }


# ============================================
# GET NOTES - OBTENER NOTAS (ACTIVAS O ELIMINADAS)
# ============================================

@router.get("/", response_model=List[NoteInDB])
async def get_notes(
    deleted: bool = False,
    auth: dict = Depends(get_token)
):
    """Obtener todas las notas del usuario autenticado.
    
    - deleted=false: Notas activas (deleted_at IS NULL)
    - deleted=true: Notas en papelera (deleted_at IS NOT NULL)
    """
    try:
        user_id = auth["user_id"]
        token = auth["token"]
        logger.info("=" * 50)
        logger.info(f"📥 GET /notes - Iniciando petición")
        logger.info(f"👤 Usuario: {user_id}")
        logger.info(f"🔍 Filtro deleted: {deleted}")
        
        user_client = supabase_client.with_token(token)
        
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
        
        result = query.execute()
        
        logger.info(f"✅ Notas encontradas: {len(result) if result else 0}")
        logger.info("=" * 50)
        
        # Convertir resultados a NoteInDB (incluye deleted_at)
        notes = []
        for item in (result or []):
            notes.append(NoteInDB(
                id=item.get("id"),
                user_id=item.get("user_id"),
                title=item.get("title"),
                content=item.get("content", ""),
                color=item.get("color", "#FFFFFF"),
                is_favorite=item.get("is_favorite", False),
                is_archived=item.get("is_archived", False),
                tags=item.get("tags", []),
                created_at=datetime.fromisoformat(item.get("created_at").replace('Z', '+00:00')) if item.get("created_at") else datetime.now(),
                updated_at=datetime.fromisoformat(item.get("updated_at").replace('Z', '+00:00')) if item.get("updated_at") else datetime.now(),
                deleted_at=datetime.fromisoformat(item.get("deleted_at").replace('Z', '+00:00')) if item.get("deleted_at") else None
            ))
        
        return notes
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en get_notes: {str(e)}")
        logger.exception("📝 Stacktrace completo:")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# GET NOTE BY ID - OBTENER NOTA POR ID
# ============================================

@router.get("/{note_id}", response_model=NoteInDB)
async def get_note(
    note_id: UUID,
    auth: dict = Depends(get_token)
):
    """Obtener una nota por ID (solo si pertenece al usuario)"""
    try:
        user_id = auth["user_id"]
        token = auth["token"]
        
        user_client = supabase_client.with_token(token)
        
        result = user_client.table("notes")\
            .select("*")\
            .eq("id", str(note_id))\
            .eq("user_id", str(user_id))\
            .execute()
        
        if not result:
            raise HTTPException(status_code=404, detail="Nota no encontrada")
        
        item = result[0]
        
        return NoteInDB(
            id=item.get("id"),
            user_id=item.get("user_id"),
            title=item.get("title"),
            content=item.get("content", ""),
            color=item.get("color", "#FFFFFF"),
            is_favorite=item.get("is_favorite", False),
            is_archived=item.get("is_archived", False),
            tags=item.get("tags", []),
            created_at=datetime.fromisoformat(item.get("created_at").replace('Z', '+00:00')) if item.get("created_at") else datetime.now(),
            updated_at=datetime.fromisoformat(item.get("updated_at").replace('Z', '+00:00')) if item.get("updated_at") else datetime.now(),
            deleted_at=datetime.fromisoformat(item.get("deleted_at").replace('Z', '+00:00')) if item.get("deleted_at") else None
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en get_note: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# CREATE NOTE - CREAR NOTA
# ============================================

@router.post("/", response_model=NoteInDB, status_code=201)
async def create_note(
    note: NoteCreate,
    auth: dict = Depends(get_token)
):
    """Crear una nueva nota para el usuario autenticado"""
    try:
        user_id = auth["user_id"]
        token = auth["token"]
        
        user_client = supabase_client.with_token(token)
        
        note_data = note.model_dump(exclude_unset=True)
        note_data["user_id"] = str(user_id)
        note_data["created_at"] = datetime.now(timezone.utc).isoformat()
        note_data["updated_at"] = datetime.now(timezone.utc).isoformat()
        note_data["deleted_at"] = None  # Nueva nota no está eliminada
        
        result = user_client.table("notes").insert(note_data)
        
        if not result:
            raise HTTPException(status_code=500, detail="Error al crear nota")
        
        item = result[0]
        
        return NoteInDB(
            id=item.get("id"),
            user_id=item.get("user_id"),
            title=item.get("title"),
            content=item.get("content", ""),
            color=item.get("color", "#FFFFFF"),
            is_favorite=item.get("is_favorite", False),
            is_archived=item.get("is_archived", False),
            tags=item.get("tags", []),
            created_at=datetime.fromisoformat(item.get("created_at").replace('Z', '+00:00')) if item.get("created_at") else datetime.now(),
            updated_at=datetime.fromisoformat(item.get("updated_at").replace('Z', '+00:00')) if item.get("updated_at") else datetime.now(),
            deleted_at=None
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en create_note: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# UPDATE NOTE - ACTUALIZAR NOTA
# ============================================

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
        
        user_client = supabase_client.with_token(token)
        
        # Verificar que la nota existe
        existing = user_client.table("notes")\
            .select("id")\
            .eq("id", str(note_id))\
            .eq("user_id", str(user_id))\
            .execute()
        
        if not existing:
            raise HTTPException(status_code=404, detail="Nota no encontrada")
        
        # Preparar datos de actualización
        update_data = note.model_dump(exclude_unset=True)
        update_data["updated_at"] = datetime.now(timezone.utc).isoformat()
        
        # Actualizar
        result = user_client.table("notes")\
            .update(update_data)\
            .eq("id", str(note_id))\
            .eq("user_id", str(user_id))\
            .execute()
        
        if not result:
            raise HTTPException(status_code=500, detail="Error al actualizar nota")
        
        item = result[0]
        
        return NoteInDB(
            id=item.get("id"),
            user_id=item.get("user_id"),
            title=item.get("title"),
            content=item.get("content", ""),
            color=item.get("color", "#FFFFFF"),
            is_favorite=item.get("is_favorite", False),
            is_archived=item.get("is_archived", False),
            tags=item.get("tags", []),
            created_at=datetime.fromisoformat(item.get("created_at").replace('Z', '+00:00')) if item.get("created_at") else datetime.now(),
            updated_at=datetime.fromisoformat(item.get("updated_at").replace('Z', '+00:00')) if item.get("updated_at") else datetime.now(),
            deleted_at=datetime.fromisoformat(item.get("deleted_at").replace('Z', '+00:00')) if item.get("deleted_at") else None
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en update_note: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# SOFT DELETE - MOVER NOTA A PAPELERA
# ============================================

@router.delete("/{note_id}", status_code=200)
async def soft_delete_note(
    note_id: UUID,
    auth: dict = Depends(get_token)
):
    """
    Soft delete - Mover nota a la papelera.
    ✅ CORREGIDO: No elimina permanentemente, solo marca deleted_at
    """
    try:
        user_id = auth["user_id"]
        token = auth["token"]
        logger.info("=" * 50)
        logger.info(f"🗑️ SOFT DELETE - Moviendo nota a papelera: {note_id}")
        logger.info(f"👤 Usuario: {user_id}")
        
        user_client = supabase_client.with_token(token)
        
        # Verificar que la nota existe
        existing = user_client.table("notes")\
            .select("id, deleted_at")\
            .eq("id", str(note_id))\
            .eq("user_id", str(user_id))\
            .execute()
        
        if not existing:
            logger.warning(f"⚠️ Nota {note_id} no encontrada")
            raise HTTPException(status_code=404, detail="Nota no encontrada")
        
        # Soft delete: actualizar deleted_at
        now_iso = datetime.now(timezone.utc).isoformat()
        result = user_client.table("notes")\
            .update({"deleted_at": now_iso, "updated_at": now_iso})\
            .eq("id", str(note_id))\
            .eq("user_id", str(user_id))\
            .execute()
        
        logger.info(f"✅ Nota {note_id} movida a papelera")
        logger.info("=" * 50)
        
        return {
            "success": True,
            "message": "Nota movida a la papelera",
            "deleted_at": now_iso
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en soft_delete_note: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# RESTORE NOTE - RESTAURAR NOTA DESDE PAPELERA
# ============================================

@router.post("/{note_id}/restore", status_code=200)
async def restore_note(
    note_id: UUID,
    auth: dict = Depends(get_token)
):
    """
    Restaurar nota desde la papelera.
    ✅ Limpia el campo deleted_at para que la nota vuelva a estar activa
    """
    try:
        user_id = auth["user_id"]
        token = auth["token"]
        logger.info("=" * 50)
        logger.info(f"🔄 RESTAURANDO nota desde papelera: {note_id}")
        logger.info(f"👤 Usuario: {user_id}")
        
        user_client = supabase_client.with_token(token)
        
        # Verificar que la nota existe y está eliminada
        existing = user_client.table("notes")\
            .select("id, deleted_at")\
            .eq("id", str(note_id))\
            .eq("user_id", str(user_id))\
            .is_not_null("deleted_at")\
            .execute()
        
        if not existing:
            logger.warning(f"⚠️ Nota {note_id} no encontrada o no está en papelera")
            raise HTTPException(status_code=404, detail="Nota no encontrada o no está en la papelera")
        
        # Restaurar: limpiar deleted_at
        now_iso = datetime.now(timezone.utc).isoformat()
        result = user_client.table("notes")\
            .update({"deleted_at": None, "updated_at": now_iso})\
            .eq("id", str(note_id))\
            .eq("user_id", str(user_id))\
            .execute()
        
        logger.info(f"✅ Nota {note_id} restaurada exitosamente")
        logger.info("=" * 50)
        
        return {
            "success": True,
            "message": "Nota restaurada correctamente"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en restore_note: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# PERMANENTLY DELETE - ELIMINAR NOTA PERMANENTEMENTE
# ============================================

@router.delete("/{note_id}/permanent", status_code=200)
async def permanently_delete_note(
    note_id: UUID,
    auth: dict = Depends(get_token)
):
    """
    Eliminar nota permanentemente (sin posibilidad de recuperar).
    ⚠️ Esta acción NO se puede deshacer
    """
    try:
        user_id = auth["user_id"]
        token = auth["token"]
        logger.info("=" * 50)
        logger.info(f"🗑️ ELIMINANDO PERMANENTEMENTE nota: {note_id}")
        logger.info(f"👤 Usuario: {user_id}")
        logger.info(f"⚠️ Esta acción NO se puede deshacer")
        
        user_client = supabase_client.with_token(token)
        
        # Verificar que la nota existe
        existing = user_client.table("notes")\
            .select("id")\
            .eq("id", str(note_id))\
            .eq("user_id", str(user_id))\
            .execute()
        
        if not existing:
            logger.warning(f"⚠️ Nota {note_id} no encontrada")
            raise HTTPException(status_code=404, detail="Nota no encontrada")
        
        # Eliminación permanente
        user_client.table("notes")\
            .delete()\
            .eq("id", str(note_id))\
            .eq("user_id", str(user_id))\
            .execute()
        
        logger.info(f"✅ Nota {note_id} eliminada permanentemente")
        logger.info("=" * 50)
        
        return {
            "success": True,
            "message": "Nota eliminada permanentemente"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en permanently_delete_note: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# EMPTY TRASH - VACIAR PAPELERA COMPLETA
# ============================================

@router.delete("/trash/empty", status_code=200)
async def empty_trash(
    auth: dict = Depends(get_token)
):
    """
    Vaciar toda la papelera.
    ✅ Elimina permanentemente TODAS las notas que están en la papelera
    ⚠️ Esta acción NO se puede deshacer
    """
    try:
        user_id = auth["user_id"]
        token = auth["token"]
        logger.info("=" * 50)
        logger.info(f"🗑️ VACIANDO PAPELERA COMPLETA para usuario: {user_id}")
        logger.info(f"⚠️ Esta acción eliminará permanentemente todas las notas en papelera")
        
        user_client = supabase_client.with_token(token)
        
        # Obtener todas las notas eliminadas del usuario (para contar)
        deleted_notes = user_client.table("notes")\
            .select("id")\
            .eq("user_id", str(user_id))\
            .is_not_null("deleted_at")\
            .execute()
        
        count = len(deleted_notes) if deleted_notes else 0
        
        if count == 0:
            logger.info("📭 La papelera ya está vacía")
            return {
                "success": True,
                "message": "La papelera ya está vacía",
                "deleted_count": 0
            }
        
        # Eliminar permanentemente todas las notas con deleted_at != NULL
        user_client.table("notes")\
            .delete()\
            .eq("user_id", str(user_id))\
            .is_not_null("deleted_at")\
            .execute()
        
        logger.info(f"✅ Papelera vaciada: {count} notas eliminadas permanentemente")
        logger.info("=" * 50)
        
        return {
            "success": True,
            "message": f"Papelera vaciada. {count} notas eliminadas permanentemente",
            "deleted_count": count
        }
        
    except Exception as e:
        logger.error(f"❌ Error en empty_trash: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# DELETE MULTIPLE NOTES - ELIMINAR MÚLTIPLES NOTAS (SOFT DELETE)
# ============================================

@router.post("/batch/soft-delete", status_code=200)
async def batch_soft_delete(
    note_ids: List[str],
    auth: dict = Depends(get_token)
):
    """
    Eliminar múltiples notas (mover a papelera) en lote.
    """
    try:
        user_id = auth["user_id"]
        token = auth["token"]
        
        user_client = supabase_client.with_token(token)
        now_iso = datetime.now(timezone.utc).isoformat()
        
        success_count = 0
        failed_ids = []
        
        for note_id in note_ids:
            try:
                result = user_client.table("notes")\
                    .update({"deleted_at": now_iso, "updated_at": now_iso})\
                    .eq("id", note_id)\
                    .eq("user_id", str(user_id))\
                    .execute()
                
                if result:
                    success_count += 1
                else:
                    failed_ids.append(note_id)
            except Exception as e:
                logger.error(f"Error eliminando nota {note_id}: {str(e)}")
                failed_ids.append(note_id)
        
        return {
            "success": True,
            "message": f"{success_count} notas movidas a la papelera",
            "success_count": success_count,
            "failed_count": len(failed_ids),
            "failed_ids": failed_ids if failed_ids else None
        }
        
    except Exception as e:
        logger.error(f"❌ Error en batch_soft_delete: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# PERMANENTLY DELETE MULTIPLE - ELIMINAR MÚLTIPLES NOTAS PERMANENTEMENTE
# ============================================

@router.post("/batch/permanent-delete", status_code=200)
async def batch_permanent_delete(
    note_ids: List[str],
    auth: dict = Depends(get_token)
):
    """
    Eliminar múltiples notas permanentemente (sin posibilidad de recuperar).
    ⚠️ Esta acción NO se puede deshacer
    """
    try:
        user_id = auth["user_id"]
        token = auth["token"]
        
        user_client = supabase_client.with_token(token)
        
        success_count = 0
        failed_ids = []
        
        for note_id in note_ids:
            try:
                result = user_client.table("notes")\
                    .delete()\
                    .eq("id", note_id)\
                    .eq("user_id", str(user_id))\
                    .execute()
                
                if result:
                    success_count += 1
                else:
                    failed_ids.append(note_id)
            except Exception as e:
                logger.error(f"Error eliminando permanentemente nota {note_id}: {str(e)}")
                failed_ids.append(note_id)
        
        return {
            "success": True,
            "message": f"{success_count} notas eliminadas permanentemente",
            "success_count": success_count,
            "failed_count": len(failed_ids),
            "failed_ids": failed_ids if failed_ids else None
        }
        
    except Exception as e:
        logger.error(f"❌ Error en batch_permanent_delete: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# SYNC NOTES - SINCRONIZAR NOTAS
# ============================================

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
        
        user_client = supabase_client.with_token(token)
        
        synced_notes = []
        for i, note in enumerate(notes):
            note_data = note.model_dump(exclude_unset=True)
            note_data["user_id"] = str(user_id)
            note_data["updated_at"] = datetime.now(timezone.utc).isoformat()
            note_data["created_at"] = datetime.now(timezone.utc).isoformat()
            note_data["deleted_at"] = None
            
            result = user_client.table("notes").upsert(note_data)
            
            if result:
                synced_notes.extend(result)
        
        logger.info(f"✅ Sincronización completada: {len(synced_notes)} notas procesadas")
        logger.info("=" * 50)
        
        # Convertir resultados a NoteInDB
        notes_response = []
        for item in synced_notes:
            notes_response.append(NoteInDB(
                id=item.get("id"),
                user_id=item.get("user_id"),
                title=item.get("title"),
                content=item.get("content", ""),
                color=item.get("color", "#FFFFFF"),
                is_favorite=item.get("is_favorite", False),
                is_archived=item.get("is_archived", False),
                tags=item.get("tags", []),
                created_at=datetime.fromisoformat(item.get("created_at").replace('Z', '+00:00')) if item.get("created_at") else datetime.now(),
                updated_at=datetime.fromisoformat(item.get("updated_at").replace('Z', '+00:00')) if item.get("updated_at") else datetime.now(),
                deleted_at=datetime.fromisoformat(item.get("deleted_at").replace('Z', '+00:00')) if item.get("deleted_at") else None
            ))
        
        return notes_response
        
    except Exception as e:
        logger.error(f"❌ Error en sync_notes: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
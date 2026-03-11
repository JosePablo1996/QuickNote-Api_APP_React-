from fastapi import APIRouter, HTTPException, Depends, Header
from typing import List, Optional
from uuid import UUID
from datetime import datetime
import jwt

from app.models.note import NoteCreate, NoteUpdate, NoteInDB
from app.services.supabase_client import supabase_client  # ✅ Importar el cliente base (sin token)
from app.config import settings

router = APIRouter(prefix="/notes", tags=["notes"])

# Constantes
JWT_SECRET = settings.jwt_secret if hasattr(settings, 'jwt_secret') else "quicknote-super-secret-jwt-key-change-in-production"

# Función para obtener el token del header
async def get_token(authorization: Optional[str] = Header(None)):
    """Extrae y valida el token JWT del header Authorization"""
    if not authorization:
        raise HTTPException(status_code=401, detail="Token no proporcionado")
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Formato de token inválido")
    
    token = authorization.replace("Bearer ", "")
    
    try:
        # Decodificar el token para obtener el user_id
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return {
            "token": token,
            "user_id": payload.get("userId"),
            "email": payload.get("email")
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Token inválido: {str(e)}")

@router.get("/", response_model=List[NoteInDB])
async def get_notes(
    deleted: bool = False,
    auth: dict = Depends(get_token)
):
    """Obtener todas las notas del usuario autenticado"""
    try:
        user_id = auth["user_id"]
        token = auth["token"]
        print(f"📥 GET /notes - Usuario: {user_id}, deleted: {deleted}")
        
        # ✅ Crear cliente con el token del usuario
        user_client = supabase_client.with_token(token)
        
        query = user_client.table("notes")\
            .select("*")\
            .eq("user_id", str(user_id))
        
        if deleted:
            query = query.not_.is_("deleted_at", "null")
        else:
            query = query.is_("deleted_at", "null")
        
        result = query.order("updated_at", desc=True).execute()
        
        if not result:
            return []
        
        print(f"✅ {len(result)} notas encontradas")
        return result
        
    except Exception as e:
        print(f"❌ Error en get_notes: {str(e)}")
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
        print(f"🔍 GET /notes/{note_id} - Usuario: {user_id}")
        
        # ✅ Crear cliente con el token del usuario
        user_client = supabase_client.with_token(token)
        
        result = user_client.table("notes")\
            .select("*")\
            .eq("id", str(note_id))\
            .eq("user_id", str(user_id))\
            .execute()
        
        if not result:
            raise HTTPException(status_code=404, detail="Nota no encontrada")
        
        return result[0]
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error en get_note: {str(e)}")
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
        print(f"📝 POST /notes - Usuario: {user_id}")
        
        # ✅ Crear cliente con el token del usuario
        user_client = supabase_client.with_token(token)
        
        # Preparar datos de la nota
        note_data = note.model_dump(exclude_unset=True)
        note_data["user_id"] = str(user_id)
        note_data["created_at"] = datetime.now().isoformat()
        note_data["updated_at"] = datetime.now().isoformat()
        
        print(f"📦 Datos a insertar: {note_data}")
        
        result = user_client.table("notes")\
            .insert(note_data)\
            .execute()
        
        if not result:
            raise HTTPException(status_code=500, detail="Error al crear nota")
        
        print(f"✅ Nota creada: {result[0]['id']}")
        return result[0]
        
    except Exception as e:
        print(f"❌ Error en create_note: {str(e)}")
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
        print(f"✏️ PUT /notes/{note_id} - Usuario: {user_id}")
        
        # ✅ Crear cliente con el token del usuario
        user_client = supabase_client.with_token(token)
        
        # Verificar que la nota existe y pertenece al usuario
        existing = user_client.table("notes")\
            .select("id")\
            .eq("id", str(note_id))\
            .eq("user_id", str(user_id))\
            .execute()
        
        if not existing:
            raise HTTPException(status_code=404, detail="Nota no encontrada")
        
        # Actualizar
        update_data = note.model_dump(exclude_unset=True)
        update_data["updated_at"] = datetime.now().isoformat()
        
        result = user_client.table("notes")\
            .eq("id", str(note_id))\
            .eq("user_id", str(user_id))\
            .update(update_data)\
            .execute()
        
        print(f"✅ Nota actualizada: {note_id}")
        return result[0]
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error en update_note: {str(e)}")
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
        print(f"🗑️ DELETE /notes/{note_id} - Usuario: {user_id}")
        
        # ✅ Crear cliente con el token del usuario
        user_client = supabase_client.with_token(token)
        
        # Verificar que la nota existe y pertenece al usuario
        existing = user_client.table("notes")\
            .select("id")\
            .eq("id", str(note_id))\
            .eq("user_id", str(user_id))\
            .execute()
        
        if not existing:
            raise HTTPException(status_code=404, detail="Nota no encontrada")
        
        # Eliminar
        user_client.table("notes")\
            .eq("id", str(note_id))\
            .eq("user_id", str(user_id))\
            .delete()\
            .execute()
        
        print(f"✅ Nota eliminada: {note_id}")
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error en delete_note: {str(e)}")
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
        print(f"🔄 POST /notes/sync - Usuario: {user_id}, {len(notes)} notas")
        
        # ✅ Crear cliente con el token del usuario
        user_client = supabase_client.with_token(token)
        
        synced_notes = []
        for note in notes:
            note_data = note.model_dump(exclude_unset=True)
            note_data["user_id"] = str(user_id)
            note_data["updated_at"] = datetime.now().isoformat()
            note_data["created_at"] = datetime.now().isoformat()
            
            result = user_client.table("notes")\
                .upsert(note_data, on_conflict="id")\
                .execute()
            
            if result:
                synced_notes.extend(result)
        
        print(f"✅ {len(synced_notes)} notas sincronizadas")
        return synced_notes
        
    except Exception as e:
        print(f"❌ Error en sync_notes: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
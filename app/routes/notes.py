from fastapi import APIRouter, HTTPException
from typing import List
from uuid import UUID
from datetime import datetime

from app.models.note import NoteCreate, NoteUpdate, NoteInDB
from app.services.supabase_client import supabase_client

router = APIRouter(prefix="/notes", tags=["notes"])

@router.get("/", response_model=List[NoteInDB])
async def get_notes():
    """Obtener todas las notas"""
    try:
        result = supabase_client.table("notes")\
            .select("*")\
            .order("updated_at", desc=True)\
            .execute()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{note_id}", response_model=NoteInDB)
async def get_note(note_id: UUID):
    """Obtener una nota por ID"""
    try:
        result = supabase_client.table("notes")\
            .select("*")\
            .eq("id", str(note_id))\
            .execute()
        
        if not result:
            raise HTTPException(status_code=404, detail="Nota no encontrada")
        
        return result[0]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/", response_model=NoteInDB, status_code=201)
async def create_note(note: NoteCreate):
    """Crear una nueva nota"""
    try:
        note_data = note.model_dump(exclude_unset=True)
        note_data["updated_at"] = datetime.now().isoformat()
        note_data["created_at"] = datetime.now().isoformat()
        
        result = supabase_client.table("notes")\
            .insert(note_data)
        
        return result[0]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/{note_id}", response_model=NoteInDB)
async def update_note(note_id: UUID, note: NoteUpdate):
    """Actualizar una nota existente"""
    try:
        # Verificar si existe
        existing = supabase_client.table("notes")\
            .select("*")\
            .eq("id", str(note_id))\
            .execute()
        
        if not existing:
            raise HTTPException(status_code=404, detail="Nota no encontrada")
        
        # Actualizar
        update_data = note.model_dump(exclude_unset=True)
        update_data["updated_at"] = datetime.now().isoformat()
        
        result = supabase_client.table("notes")\
            .eq("id", str(note_id))\
            .update(update_data)
        
        return result[0]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{note_id}", status_code=204)
async def delete_note(note_id: UUID):
    """Eliminar una nota"""
    try:
        result = supabase_client.table("notes")\
            .eq("id", str(note_id))\
            .delete()
        
        if not result:
            raise HTTPException(status_code=404, detail="Nota no encontrada")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/sync", response_model=List[NoteInDB])
async def sync_notes(notes: List[NoteCreate]):
    """Sincronizar múltiples notas"""
    try:
        synced_notes = []
        for note in notes:
            note_data = note.model_dump(exclude_unset=True)
            note_data["updated_at"] = datetime.now().isoformat()
            note_data["created_at"] = datetime.now().isoformat()
            
            result = supabase_client.table("notes")\
                .upsert(note_data, on_conflict="id")
            
            synced_notes.extend(result)
        
        return synced_notes
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
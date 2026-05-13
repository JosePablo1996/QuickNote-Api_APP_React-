# app/models/backup.py
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List, Any, Dict
from uuid import UUID, uuid4

class CloudBackupBase(BaseModel):
    """Base para backup en la nube"""
    file_name: str = Field(..., max_length=255)
    file_size: int = Field(..., ge=0)
    note_count: int = Field(..., ge=0)
    notes_data: Dict[str, Any] = Field(..., description="JSON con todas las notas")
    
class CloudBackupCreate(CloudBackupBase):
    """Crear un backup en la nube"""
    user_id: UUID
    pass

class CloudBackupInDB(CloudBackupBase):
    """Backup en base de datos"""
    id: UUID = Field(default_factory=uuid4)
    user_id: UUID
    created_at: datetime = Field(default_factory=datetime.now)
    
    class Config:
        from_attributes = True

class CloudBackupMetadata(BaseModel):
    """Metadatos del backup para listar (sin datos de notas)"""
    id: UUID
    user_id: UUID
    file_name: str
    file_size: int
    note_count: int
    created_at: datetime
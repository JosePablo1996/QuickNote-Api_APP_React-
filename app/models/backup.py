# app/models/backup.py
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, Any, Dict
from uuid import UUID, uuid4


class CloudBackupBase(BaseModel):
    """Base para backup en la nube"""
    file_name: str = Field(..., max_length=255, description="Nombre del archivo de backup")
    file_size: int = Field(..., ge=0, description="Tamaño del archivo en bytes")
    note_count: int = Field(..., ge=0, description="Número de notas incluidas en el backup")
    notes_data: Dict[str, Any] = Field(..., description="JSON con todas las notas")


class CloudBackupCreate(CloudBackupBase):
    """Crear un backup en la nube"""
    user_id: Optional[UUID] = Field(None, description="ID del usuario (se asigna automáticamente)")


class CloudBackupInDB(CloudBackupBase):
    """Backup en base de datos (respuesta completa)"""
    id: UUID = Field(default_factory=uuid4, description="ID único del backup")
    user_id: UUID = Field(..., description="ID del usuario propietario")
    created_at: datetime = Field(default_factory=datetime.now, description="Fecha de creación")
    
    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: lambda v: str(v)
        }


class CloudBackupMetadata(BaseModel):
    """Metadatos del backup para listar (sin datos de notas, más ligero)"""
    id: UUID = Field(..., description="ID único del backup")
    user_id: UUID = Field(..., description="ID del usuario propietario")
    file_name: str = Field(..., description="Nombre del archivo de backup")
    file_size: int = Field(..., description="Tamaño del archivo en bytes")
    note_count: int = Field(..., description="Número de notas incluidas")
    created_at: datetime = Field(..., description="Fecha de creación")
    
    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: lambda v: str(v)
        }
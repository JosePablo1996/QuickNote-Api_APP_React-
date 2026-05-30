# models/note.py - Versión corregida con deleted_at para soft delete
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List
from uuid import UUID, uuid4


class NoteBase(BaseModel):
    """Base para notas - campos comunes"""
    title: str = Field(..., min_length=1, max_length=200, description="Título de la nota")
    content: Optional[str] = Field(default="", description="Contenido de la nota")
    color: str = Field(default="#FFFFFF", description="Color de fondo de la nota")
    is_favorite: bool = Field(default=False, description="Marcada como favorita")
    is_archived: bool = Field(default=False, description="Nota archivada")
    tags: List[str] = Field(default_factory=list, description="Etiquetas de la nota")


class NoteCreate(NoteBase):
    """Modelo para crear una nueva nota"""
    user_id: Optional[UUID] = Field(None, description="ID del usuario (se asigna automáticamente)")


class NoteUpdate(BaseModel):
    """Modelo para actualizar una nota (todos los campos son opcionales)"""
    title: Optional[str] = Field(None, min_length=1, max_length=200, description="Título de la nota")
    content: Optional[str] = Field(None, description="Contenido de la nota")
    color: Optional[str] = Field(None, description="Color de fondo de la nota")
    is_favorite: Optional[bool] = Field(None, description="Marcada como favorita")
    is_archived: Optional[bool] = Field(None, description="Nota archivada")
    tags: Optional[List[str]] = Field(None, description="Etiquetas de la nota")


class NoteInDB(NoteBase):
    """Modelo para nota en base de datos (respuesta completa)"""
    id: UUID = Field(default_factory=uuid4, description="ID único de la nota")
    user_id: Optional[UUID] = Field(None, description="ID del usuario propietario")
    created_at: datetime = Field(default_factory=datetime.now, description="Fecha de creación")
    updated_at: datetime = Field(default_factory=datetime.now, description="Fecha de última actualización")
    deleted_at: Optional[datetime] = Field(default=None, description="Fecha de eliminación (soft delete)")

    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: lambda v: str(v)
        }


class NoteResponse(NoteInDB):
    """Alias para NoteInDB (consistencia con otros modelos)"""
    pass


class NoteSoftDeleteResponse(BaseModel):
    """Respuesta para soft delete"""
    success: bool = Field(..., description="Indica si la operación fue exitosa")
    message: str = Field(..., description="Mensaje informativo")
    deleted_at: Optional[str] = Field(None, description="Fecha de eliminación")


class NoteRestoreResponse(BaseModel):
    """Respuesta para restaurar nota"""
    success: bool = Field(..., description="Indica si la operación fue exitosa")
    message: str = Field(..., description="Mensaje informativo")


class BatchDeleteResponse(BaseModel):
    """Respuesta para operaciones por lote"""
    success: bool = Field(..., description="Indica si la operación fue exitosa")
    message: str = Field(..., description="Mensaje informativo")
    success_count: int = Field(..., description="Número de operaciones exitosas")
    failed_count: int = Field(..., description="Número de operaciones fallidas")
    failed_ids: Optional[List[str]] = Field(None, description="IDs que fallaron")


class EmptyTrashResponse(BaseModel):
    """Respuesta para vaciar papelera"""
    success: bool = Field(..., description="Indica si la operación fue exitosa")
    message: str = Field(..., description="Mensaje informativo")
    deleted_count: int = Field(0, description="Número de notas eliminadas permanentemente")
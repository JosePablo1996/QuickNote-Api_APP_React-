from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional
from uuid import UUID

class NoteBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    content: Optional[str] = ""
    color: str = "#FFFFFF"
    is_favorite: bool = False
    is_archived: bool = False

class NoteCreate(NoteBase):
    user_id: Optional[UUID] = None

class NoteUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=200)
    content: Optional[str] = None
    color: Optional[str] = None
    is_favorite: Optional[bool] = None
    is_archived: Optional[bool] = None

class NoteInDB(NoteBase):
    id: UUID
    user_id: Optional[UUID]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
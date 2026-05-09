# app/models/passkey.py
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List
from uuid import UUID

class PasskeyCredential(BaseModel):
    """Modelo para credenciales de passkey"""
    id: str  # Credential ID en base64
    public_key: str  # Public key en formato apropiado
    sign_count: int = 0
    transports: Optional[List[str]] = None
    device_name: Optional[str] = "Dispositivo sin nombre"
    created_at: datetime = Field(default_factory=datetime.now)
    last_used_at: Optional[datetime] = None

class PasskeyCredentialDB(PasskeyCredential):
    """Modelo para credenciales en base de datos"""
    user_id: UUID
    credential_id: str  # ID único generado por Supabase

class WebAuthnRegistrationStart(BaseModel):
    """Inicio de registro WebAuthn"""
    email: str

class WebAuthnRegistrationComplete(BaseModel):
    """Completar registro WebAuthn"""
    email: str
    credential: dict  # Respuesta de navigator.credentials.create()
    device_name: Optional[str] = "Mi dispositivo"

class WebAuthnLoginStart(BaseModel):
    """Inicio de login WebAuthn"""
    email: Optional[str] = None

class WebAuthnLoginComplete(BaseModel):
    """Completar login WebAuthn"""
    email: Optional[str] = None
    credential: dict  # Respuesta de navigator.credentials.get()

class Challenge(BaseModel):
    """Challenge para WebAuthn"""
    challenge: str
    timeout: int = 60000  # 1 minuto
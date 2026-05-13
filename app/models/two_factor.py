# app/models/two_factor.py
from pydantic import BaseModel, Field
from typing import Optional

class TwoFactorEnableResponse(BaseModel):
    """Respuesta al solicitar activación de 2FA"""
    secret: str = Field(..., description="Secreto TOTP en base32")
    qr_code: str = Field(..., description="QR code en formato base64 (data:image/png;base64,...)")
    manual_key: str = Field(..., description="Clave manual para ingresar si no se puede escanear QR")
    message: str = Field(default="Escanea el código QR con Google Authenticator")

class TwoFactorVerifyRequest(BaseModel):
    """Solicitud para verificar código TOTP"""
    code: str = Field(..., min_length=6, max_length=6, description="Código de 6 dígitos")
    secret: str = Field(..., description="Secreto TOTP temporal (solo para enable)")
    password: Optional[str] = Field(default=None, description="Contraseña actual para confirmar")

class TwoFactorVerifyResponse(BaseModel):
    """Respuesta de verificación 2FA"""
    success: bool
    message: str
    backup_codes: Optional[list[str]] = Field(default=None, description="Códigos de respaldo (solo al activar)")

class TwoFactorLoginVerifyRequest(BaseModel):
    """Solicitud para verificar 2FA durante login"""
    code: str = Field(..., min_length=6, max_length=6)
    temp_token: str = Field(..., description="Token temporal obtenido después de email/password")

class TwoFactorStatusResponse(BaseModel):
    """Estado actual del 2FA del usuario"""
    enabled: bool
    method: Optional[str] = Field(default="totp", description="Método 2FA (totp)")
    created_at: Optional[str] = None
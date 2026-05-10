from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr
import secrets
import logging
from datetime import datetime, timedelta, timezone
import jwt
from app.config import settings
from app.services.email_service import send_otp_email

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# Almacenamiento temporal de OTPs (en producción usar Redis)
otp_store = {}

class SendOtpRequest(BaseModel):
    email: EmailStr

class VerifyOtpRequest(BaseModel):
    email: EmailStr
    code: str

@router.post("/send-otp")
async def send_otp(request: SendOtpRequest):
    """Envía un código OTP al email del usuario"""
    try:
        email = request.email.lower()
        
        # Generar código de 6 dígitos
        code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
        
        # Guardar código con expiración de 10 minutos
        otp_store[email] = {
            "code": code,
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10),
            "attempts": 0
        }
        
        # ✅ CORREGIDO: Llamar a la función de envío de email
        logger.info(f"📧 Enviando OTP para {email}...")
        email_sent = await send_otp_email(email, code)
        
        if not email_sent:
            logger.warning(f"⚠️  No se pudo enviar el email a {email}, pero el código OTP es válido")
            # No lanzamos error para no bloquear el flujo en desarrollo
        
        logger.info(f"📧 OTP para {email}: {code}")
        
        return {
            "message": "Código enviado exitosamente",
            "expires_in": 600,  # 10 minutos en segundos
            "success": True
        }
        
    except Exception as e:
        logger.error(f"Error enviando OTP: {str(e)}")
        raise HTTPException(status_code=500, detail="Error al enviar el código")

@router.post("/verify-otp")
async def verify_otp(request: VerifyOtpRequest):
    """Verifica el código OTP y devuelve un token JWT"""
    try:
        email = request.email.lower()
        code = request.code
        
        # Verificar que existe un OTP para este email
        if email not in otp_store:
            raise HTTPException(status_code=400, detail="No se ha solicitado un código para este email")
        
        otp_data = otp_store[email]
        
        # Verificar expiración
        if datetime.now(timezone.utc) > otp_data["expires_at"]:
            del otp_store[email]
            raise HTTPException(status_code=400, detail="El código ha expirado")
        
        # Verificar intentos
        if otp_data["attempts"] >= 3:
            del otp_store[email]
            raise HTTPException(status_code=400, detail="Demasiados intentos. Solicita un nuevo código")
        
        # Verificar código
        if code != otp_data["code"]:
            otp_data["attempts"] += 1
            raise HTTPException(status_code=400, detail="Código inválido")
        
        # Código válido - limpiar store
        del otp_store[email]
        
        # Generar token JWT (usando el email como identificador)
        # Buscar usuario en Supabase
        from app.routes.passkeys import supabase_query
        users = supabase_query("profiles", "GET", params={"email": email})
        
        if not users:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        user = users[0]
        
        # Generar token
        now = datetime.now(timezone.utc)
        token_data = {
            "sub": str(user["id"]),
            "userId": str(user["id"]),
            "email": user["email"],
            "aud": "authenticated",
            "role": "authenticated",
            "user_metadata": {
                "full_name": user.get("full_name", "")
            },
            "iat": now,
            "exp": now + timedelta(days=7)
        }
        
        token = jwt.encode(token_data, settings.jwt_secret, algorithm="HS256")
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": user["id"],
                "email": user["email"],
                "name": user.get("full_name", user.get("email", "").split("@")[0])
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error verificando OTP: {str(e)}")
        raise HTTPException(status_code=500, detail="Error al verificar el código")
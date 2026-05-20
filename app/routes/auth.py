# app/routes/auth.py
from fastapi import APIRouter, HTTPException, Depends, Header, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
import secrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List
import jwt
import httpx
from app.config import settings
from app.services.email_service import EmailService
from app.services.two_factor_service import TwoFactorService
from app.services.password_service import password_service
from app.services.security_service import security_service, SecurityEventType
from app.services.supabase_client import supabase_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# Esquema de seguridad Bearer
security = HTTPBearer()

# Almacenamiento temporal de OTPs para login normal
otp_store = {}

# Almacenamiento temporal para reset de contrasena con OTP
reset_otp_store = {}

# Instancias de servicios
two_factor_service = TwoFactorService()
email_service = EmailService()


# ============================================
# MODELOS
# ============================================

class SendOtpRequest(BaseModel):
    email: EmailStr


class VerifyOtpRequest(BaseModel):
    email: EmailStr
    code: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    success: bool = True
    requires_2fa: bool = False
    temp_token: Optional[str] = None
    message: Optional[str] = None
    user_id: Optional[str] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: Optional[int] = None
    user: Optional[dict] = None


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)


class PasswordChangeResponse(BaseModel):
    success: bool
    message: str
    requires_relogin: bool = True


class PasswordExpiryResponse(BaseModel):
    success: bool
    is_expired: bool
    days_remaining: Optional[int] = None
    requires_change: bool


class PasswordPolicyResponse(BaseModel):
    max_age_days: int
    prevent_reuse_count: int
    min_length: int
    require_uppercase: bool
    require_lowercase: bool
    require_numbers: bool
    require_special_chars: bool


class LogoutAllSessionsResponse(BaseModel):
    success: bool
    message: str


class TwoFactorVerifyEnableRequest(BaseModel):
    code: str
    secret: str


class TwoFactorLoginVerifyRequest(BaseModel):
    code: str
    temp_token: str


class TwoFactorBackupVerifyRequest(BaseModel):
    code: str
    temp_token: str


# ============================================
# MODELOS PARA RESET DE CONTRASENA CON OTP
# ============================================

class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ForgotPasswordVerifyRequest(BaseModel):
    email: EmailStr
    code: str


class ForgotPasswordResetRequest(BaseModel):
    email: EmailStr
    code: str
    new_password: str = Field(..., min_length=8)


class ForgotPasswordResponse(BaseModel):
    success: bool
    message: str
    email_sent: bool = False
    expires_in: Optional[int] = None


class ForgotPasswordVerifyResponse(BaseModel):
    success: bool
    message: str
    temp_token: Optional[str] = None
    expires_in: int = 300


class ForgotPasswordResetResponse(BaseModel):
    success: bool
    message: str
    requires_relogin: bool = True


# ============================================
# FUNCIONES AUXILIARES
# ============================================

async def get_user_by_id(user_id: str) -> Optional[dict]:
    """Obtiene usuario por ID usando service role"""
    try:
        headers = {
            "apikey": settings.supabase_key,
            "Authorization": f"Bearer {settings.supabase_service_role_key}"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{settings.supabase_url}/auth/v1/admin/users/{user_id}",
                headers=headers
            )
            
            if response.status_code == 200:
                return response.json()
            logger.warning(f"Usuario {user_id} no encontrado en Supabase Auth")
            return None
    except Exception as e:
        logger.error(f"Error obteniendo usuario: {e}")
        return None


async def update_user_metadata(user_id: str, metadata: dict) -> bool:
    """Actualiza metadata del usuario en la tabla profiles"""
    return await supabase_client.update_user_metadata(user_id, metadata)


async def is_password_expired(user_id: str) -> tuple[bool, Optional[int]]:
    """Verifica si la contrasena ha expirado"""
    try:
        user = await get_user_by_id(user_id)
        if not user:
            return False, None
        
        user_metadata = user.get("user_metadata", {})
        password_expires_at = user_metadata.get("password_expires_at")
        
        if not password_expires_at:
            return False, None
        
        expires_at = datetime.fromisoformat(password_expires_at.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        
        if expires_at < now:
            return True, 0
        
        days_remaining = (expires_at - now).days
        return False, days_remaining
    except Exception as e:
        logger.error(f"Error verificando expiracion: {e}")
        return False, None


# ============================================
# FUNCION DE AUTENTICACION (get_current_user)
# ============================================

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    authorization: Optional[str] = Header(None),
    request: Request = None
) -> dict:
    """
    Obtiene el usuario actual a partir del token JWT.
    Verifica session_version para forzar cierre de sesion.
    """
    try:
        token = credentials.credentials if credentials else None
        
        if not token and authorization:
            if authorization.startswith("Bearer "):
                token = authorization[7:]
        
        if not token:
            raise HTTPException(
                status_code=401,
                detail="Token de autenticacion no proporcionado"
            )
        
        original_token = token
        
        token_header = jwt.get_unverified_header(token)
        token_alg = token_header.get("alg", "unknown")
        logger.debug(f"Token recibido: alg={token_alg}")
        
        try:
            payload = jwt.decode(
                token,
                options={"verify_signature": False, "verify_exp": True}
            )
        except jwt.InvalidTokenError as e:
            logger.error(f"Token invalido: {e}")
            raise HTTPException(status_code=401, detail="Token invalido o expirado")
        
        user_id = payload.get("sub") or payload.get("userId") or payload.get("user_id")
        user_email = payload.get("email") or payload.get("user_metadata", {}).get("email")
        
        if not user_id:
            raise HTTPException(
                status_code=401,
                detail="Token no contiene informacion de usuario"
            )
        
        # Verificar session_version
        user_metadata = await supabase_client.get_user_metadata(user_id)
        if user_metadata:
            session_version = user_metadata.get("session_version")
            if session_version:
                token_iat = payload.get("iat")
                if token_iat:
                    if float(session_version) > float(token_iat):
                        logger.warning(f"Sesion expirada para usuario {user_id}")
                        raise HTTPException(
                            status_code=401,
                            detail={
                                "code": "SESSION_EXPIRED",
                                "message": "Tu sesion ha sido cerrada. Por favor, inicia sesion nuevamente.",
                                "requires_relogin": True
                            }
                        )
        
        # Verificar expiracion de contrasena
        is_expired, days_remaining = await is_password_expired(user_id)
        
        if is_expired:
            logger.warning(f"Contrasena expirada para usuario {user_id}")
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "PASSWORD_EXPIRED",
                    "message": "Tu contrasena ha expirado. Debes cambiarla para continuar.",
                    "requires_password_change": True
                }
            )
        
        return {
            "user_id": user_id,
            "sub": user_id,
            "email": user_email,
            "payload": payload,
            "token": original_token
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en get_current_user: {e}")
        raise HTTPException(
            status_code=401,
            detail="Error al validar autenticacion"
        )


# ============================================
# ENDPOINT: CAMBIAR CONTRASENA (CON requires_relogin)
# ============================================

@router.post("/change-password", response_model=PasswordChangeResponse)
async def change_password(
    request_data: PasswordChangeRequest,
    current_user: dict = Depends(get_current_user),
    req: Request = None
):
    """Cambia la contrasena del usuario y fuerza cierre de sesion."""
    user_id = current_user["user_id"]
    
    try:
        policy = await supabase_client.get_password_policy()
        
        is_valid, errors = password_service.validate_strength(request_data.new_password, policy)
        if not is_valid:
            raise HTTPException(status_code=400, detail={"errors": errors, "message": "La contrasena no cumple los requisitos"})
        
        if request_data.new_password == request_data.current_password:
            raise HTTPException(status_code=400, detail="La nueva contrasena debe ser diferente a la actual")
        
        user = await get_user_by_id(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        async with httpx.AsyncClient() as client:
            auth_response = await client.post(
                f"{settings.supabase_url}/auth/v1/token?grant_type=password",
                headers={"apikey": settings.supabase_key, "Content-Type": "application/json"},
                json={"email": user.get("email"), "password": request_data.current_password}
            )
            
            if auth_response.status_code != 200:
                raise HTTPException(status_code=401, detail="Contrasena actual incorrecta")
        
        new_password_hash = password_service.hash_for_history(request_data.new_password)
        can_reuse = await supabase_client.check_password_reuse(user_id, new_password_hash, policy.get("prevent_reuse_count", 5))
        
        if not can_reuse:
            raise HTTPException(
                status_code=400,
                detail=f"No puedes usar una contrasena que hayas utilizado en las ultimas {policy.get('prevent_reuse_count', 5)} veces"
            )
        
        headers = {
            "apikey": settings.supabase_key,
            "Authorization": f"Bearer {settings.supabase_service_role_key}",
            "Content-Type": "application/json"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.put(
                f"{settings.supabase_url}/auth/v1/admin/users/{user_id}",
                headers=headers,
                json={"password": request_data.new_password}
            )
            
            if response.status_code != 200:
                logger.error(f"Error actualizando password en Supabase: {response.status_code} - {response.text}")
                raise HTTPException(status_code=500, detail="Error al actualizar la contrasena")
        
        max_age_days = policy.get("max_age_days", 90)
        expires_at = (datetime.now(timezone.utc) + timedelta(days=max_age_days)).isoformat()
        
        new_session_version = datetime.now(timezone.utc).timestamp()
        
        await update_user_metadata(user_id, {
            "password_changed_at": datetime.now(timezone.utc).isoformat(),
            "password_expires_at": expires_at,
            "session_version": new_session_version,
            "last_password_change": datetime.now(timezone.utc).isoformat()
        })
        
        await supabase_client.record_password_history(user_id, new_password_hash)
        await supabase_client.cleanup_old_password_history(user_id, 20)
        
        # Invalidar todas las sesiones
        await supabase_client.invalidate_all_sessions(user_id)
        
        # Registrar evento de seguridad
        await security_service.log_security_event(
            user_id=user_id,
            event_type=SecurityEventType.PASSWORD_CHANGED,
            ip_address=req.client.host if req else None,
            details={"reason": "password_changed", "force_logout": True, "session_version": new_session_version}
        )
        
        # Enviar email de confirmacion
        user_email = current_user.get("email") or user.get("email")
        if user_email:
            user_name = user.get("user_metadata", {}).get("full_name", "Usuario")
            await email_service.send_password_change_confirmation(user_email, user_name, req.client.host if req else None)
        
        logger.info(f"Contrasena cambiada exitosamente para usuario {user_id} - session_version actualizada a {new_session_version}")
        
        return PasswordChangeResponse(
            success=True,
            message="Contrasena actualizada correctamente. Debes iniciar sesion nuevamente.",
            requires_relogin=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en change_password: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error al cambiar contrasena: {str(e)}")


# ============================================
# ENDPOINTS DE RECUPERACION DE CONTRASENA (CON requires_relogin)
# ============================================

@router.post("/forgot-password/send-otp", response_model=ForgotPasswordResponse)
async def forgot_password_send_otp(request: ForgotPasswordRequest, req: Request = None):
    """Paso 1 y 2: Envia un codigo OTP al email del usuario para resetear contrasena."""
    try:
        email = request.email.lower()
        
        from app.routes.passkeys import supabase_query
        users = supabase_query("profiles", "GET", params={"email": email})
        
        if not users:
            logger.info(f"Solicitud de reset para email no registrado: {email}")
            return ForgotPasswordResponse(
                success=True,
                message="Si el email existe en nuestro sistema, recibiras un codigo de verificacion.",
                email_sent=False
            )
        
        code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
        
        user = users[0]
        user_name = user.get("full_name", user.get("username", "Usuario"))
        
        reset_otp_store[email] = {
            "code": code,
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10),
            "attempts": 0,
            "user_id": user.get("id"),
            "user_name": user_name
        }
        
        email_sent = await email_service.send_password_reset_otp(email, code)
        
        if email_sent:
            logger.info(f"OTP de reset enviado a {email}")
        else:
            logger.warning(f"No se pudo enviar OTP de reset a {email}")
        
        return ForgotPasswordResponse(
            success=True,
            message="Si el email existe en nuestro sistema, recibiras un codigo de verificacion.",
            email_sent=email_sent,
            expires_in=600
        )
        
    except Exception as e:
        logger.error(f"Error en forgot_password_send_otp: {e}")
        raise HTTPException(status_code=500, detail="Error al enviar el codigo")


@router.post("/forgot-password/verify-otp", response_model=ForgotPasswordVerifyResponse)
async def forgot_password_verify_otp(request: ForgotPasswordVerifyRequest, req: Request = None):
    """Paso 3: Verifica el codigo OTP para resetear contrasena."""
    try:
        email = request.email.lower()
        code = request.code
        
        if email not in reset_otp_store:
            raise HTTPException(status_code=400, detail="No se ha solicitado un codigo para este email")
        
        otp_data = reset_otp_store[email]
        
        if datetime.now(timezone.utc) > otp_data["expires_at"]:
            del reset_otp_store[email]
            raise HTTPException(status_code=400, detail="El codigo ha expirado. Solicita uno nuevo")
        
        if otp_data["attempts"] >= 3:
            del reset_otp_store[email]
            raise HTTPException(status_code=400, detail="Demasiados intentos. Solicita un nuevo codigo")
        
        if code != otp_data["code"]:
            otp_data["attempts"] += 1
            raise HTTPException(status_code=400, detail="Codigo invalido")
        
        temp_token = secrets.token_urlsafe(32)
        
        reset_otp_store[email]["verified"] = True
        reset_otp_store[email]["temp_token"] = temp_token
        
        logger.info(f"OTP de reset verificado para {email}")
        
        return ForgotPasswordVerifyResponse(
            success=True,
            message="Codigo verificado correctamente",
            temp_token=temp_token,
            expires_in=300
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en forgot_password_verify_otp: {e}")
        raise HTTPException(status_code=500, detail="Error al verificar el codigo")


@router.post("/forgot-password/reset", response_model=ForgotPasswordResetResponse)
async def forgot_password_reset(request: ForgotPasswordResetRequest, req: Request = None):
    """
    Paso 4: Resetea la contrasena usando el codigo OTP verificado.
    ✅ Requiere relogin obligatorio
    ✅ CORREGIDO: Mejor manejo de errores y logs detallados
    """
    try:
        email = request.email.lower()
        code = request.code
        new_password = request.new_password
        
        logger.info(f"🔐 [Reset] Intentando resetear contrasena para: {email}")
        logger.info(f"🔐 [Reset] Codigo recibido: {code}")
        
        # 1. Verificar que existe solicitud
        if email not in reset_otp_store:
            logger.error(f"❌ [Reset] No hay solicitud para {email}")
            raise HTTPException(status_code=400, detail="Solicitud invalida. Reinicia el proceso")
        
        otp_data = reset_otp_store[email]
        logger.info(f"🔐 [Reset] Datos OTP encontrados: verified={otp_data.get('verified')}, user_id={otp_data.get('user_id')}")
        
        # 2. Verificar que el OTP fue verificado
        if not otp_data.get("verified"):
            logger.error(f"❌ [Reset] OTP no verificado para {email}")
            raise HTTPException(status_code=400, detail="Debes verificar el codigo primero")
        
        # 3. Verificar que el codigo coincide
        if code != otp_data.get("code"):
            logger.error(f"❌ [Reset] Codigo no coincide para {email}")
            raise HTTPException(status_code=400, detail="Token invalido")
        
        # 4. Validar fortaleza de la nueva contraseña
        policy = await supabase_client.get_password_policy()
        is_valid, errors = password_service.validate_strength(new_password, policy)
        if not is_valid:
            logger.error(f"❌ [Reset] Contrasena no cumple requisitos: {errors}")
            raise HTTPException(status_code=400, detail={"errors": errors, "message": "La contrasena no cumple los requisitos"})
        
        user_id = otp_data.get("user_id")
        if not user_id:
            logger.error(f"❌ [Reset] No se encontró user_id para {email}")
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        logger.info(f"🔐 [Reset] User ID obtenido: {user_id}")
        
        # 5. Verificar que el usuario existe en la tabla profiles
        try:
            profile_result = supabase_client.table("profiles").select("id, email").eq("id", user_id).execute()
            if not profile_result or len(profile_result) == 0:
                logger.error(f"❌ [Reset] Usuario no encontrado en profiles: {user_id}")
                raise HTTPException(status_code=404, detail="Usuario no encontrado en el sistema")
            logger.info(f"✅ [Reset] Usuario encontrado en profiles: {profile_result[0].get('email')}")
        except Exception as e:
            logger.error(f"❌ [Reset] Error verificando perfil: {e}")
            raise HTTPException(status_code=500, detail="Error al verificar el usuario")
        
        # 6. Actualizar contraseña en Supabase Auth
        headers = {
            "apikey": settings.supabase_key,
            "Authorization": f"Bearer {settings.supabase_service_role_key}",
            "Content-Type": "application/json"
        }
        
        logger.info(f"🔄 [Reset] Actualizando contraseña en Supabase Auth para user: {user_id}")
        
        async with httpx.AsyncClient() as client:
            response = await client.put(
                f"{settings.supabase_url}/auth/v1/admin/users/{user_id}",
                headers=headers,
                json={"password": new_password}
            )
            
            if response.status_code != 200:
                error_detail = response.text
                logger.error(f"❌ [Reset] Error en Supabase Auth: {response.status_code} - {error_detail}")
                raise HTTPException(
                    status_code=500, 
                    detail=f"Error al actualizar la contrasena en el servidor de autenticación"
                )
            
            logger.info(f"✅ [Reset] Contraseña actualizada en Supabase Auth")
        
        # 7. Calcular fecha de expiración
        max_age_days = policy.get("max_age_days", 90)
        expires_at = (datetime.now(timezone.utc) + timedelta(days=max_age_days)).isoformat()
        new_session_version = datetime.now(timezone.utc).timestamp()
        
        # 8. Actualizar metadata del usuario en profiles
        logger.info(f"🔄 [Reset] Actualizando metadata en profiles para user: {user_id}")
        
        try:
            update_result = supabase_client.table("profiles").update({
                "password_changed_at": datetime.now(timezone.utc).isoformat(),
                "password_expires_at": expires_at,
                "password_reset_via_otp": True,
                "session_version": new_session_version,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }).eq("id", user_id).execute()
            
            if update_result:
                logger.info(f"✅ [Reset] Metadata actualizada en profiles")
            else:
                logger.warning(f"⚠️ [Reset] No se pudo actualizar metadata (resultado vacío)")
        except Exception as e:
            logger.warning(f"⚠️ [Reset] Error actualizando metadata (no crítico): {e}")
        
        # 9. Registrar en historial de contraseñas
        new_password_hash = password_service.hash_for_history(new_password)
        await supabase_client.record_password_history(user_id, new_password_hash)
        await supabase_client.cleanup_old_password_history(user_id, 20)
        
        # 10. Invalidar todas las sesiones
        await supabase_client.invalidate_all_sessions(user_id)
        logger.info(f"✅ [Reset] Sesiones invalidadas")
        
        # 11. Registrar evento de seguridad
        await security_service.log_security_event(
            user_id=user_id,
            event_type="PASSWORD_RESET_VIA_OTP",
            ip_address=req.client.host if req else None,
            details={"session_version": new_session_version}
        )
        
        # 12. Enviar email de confirmación
        user_email = email
        user_name = otp_data.get("user_name", "Usuario")
        await email_service.send_password_change_confirmation(user_email, user_name, req.client.host if req else None)
        
        # 13. Limpiar el store
        del reset_otp_store[email]
        
        logger.info(f"✅✅✅ [Reset] CONTRASEÑA RESETEADA EXITOSAMENTE para usuario {user_id}")
        
        return ForgotPasswordResetResponse(
            success=True,
            message="Contraseña actualizada correctamente. Debes iniciar sesión con tu nueva contraseña.",
            requires_relogin=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌❌❌ [Reset] Error FATAL en forgot_password_reset: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500, 
            detail=f"Error al actualizar la contraseña: {str(e)}"
        )


# ============================================
# ENDPOINT: VERIFICAR EXPIRACION DE CONTRASENA
# ============================================

@router.get("/check-password-expiry", response_model=PasswordExpiryResponse)
async def check_password_expiry(current_user: dict = Depends(get_current_user)):
    """Verifica si la contrasena del usuario ha expirado."""
    user_id = current_user["user_id"]
    
    try:
        is_expired, days_remaining = await is_password_expired(user_id)
        
        return PasswordExpiryResponse(
            success=True,
            is_expired=is_expired,
            days_remaining=days_remaining,
            requires_change=is_expired or (days_remaining is not None and days_remaining <= 7)
        )
    except Exception as e:
        logger.error(f"Error en check_password_expiry: {e}")
        return PasswordExpiryResponse(
            success=False,
            is_expired=False,
            days_remaining=None,
            requires_change=False
        )


# ============================================
# ENDPOINT: CERRAR TODAS LAS SESIONES
# ============================================

@router.post("/logout-all-sessions", response_model=LogoutAllSessionsResponse)
async def logout_all_sessions(
    current_user: dict = Depends(get_current_user),
    req: Request = None
):
    """Cierra todas las sesiones activas del usuario."""
    user_id = current_user["user_id"]
    
    try:
        new_session_version = datetime.now(timezone.utc).timestamp()
        await update_user_metadata(user_id, {"session_version": new_session_version})
        
        count = await supabase_client.invalidate_all_sessions(user_id)
        
        await security_service.log_security_event(
            user_id=user_id,
            event_type=SecurityEventType.LOGOUT_ALL_SESSIONS,
            ip_address=req.client.host if req else None,
            details={"session_version": new_session_version}
        )
        
        return LogoutAllSessionsResponse(
            success=True,
            message=f"Se han cerrado {count} sesiones activas"
        )
    except Exception as e:
        logger.error(f"Error en logout_all_sessions: {e}")
        raise HTTPException(status_code=500, detail="Error al cerrar sesiones")


# ============================================
# ENDPOINT: OBTENER POLITICA DE CONTRASENAS
# ============================================

@router.get("/password-policy", response_model=PasswordPolicyResponse)
async def get_password_policy_endpoint():
    """Obtiene la politica actual de contrasenas."""
    try:
        policy = await supabase_client.get_password_policy()
        return PasswordPolicyResponse(**policy)
    except Exception as e:
        logger.error(f"Error obteniendo politica: {e}")
        return PasswordPolicyResponse(
            max_age_days=90,
            prevent_reuse_count=5,
            min_length=8,
            require_uppercase=True,
            require_lowercase=True,
            require_numbers=True,
            require_special_chars=True
        )


# ============================================
# ENDPOINTS OTP PARA LOGIN NORMAL
# ============================================

@router.post("/send-otp")
async def send_otp(request: SendOtpRequest, req: Request = None):
    """Envía un código OTP al email del usuario para login."""
    try:
        email = request.email.lower()
        
        code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
        
        otp_store[email] = {
            "code": code,
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10),
            "attempts": 0
        }
        
        logger.info(f"Enviando OTP para {email}...")
        email_sent = await email_service.send_otp_email(email, code)
        
        if not email_sent:
            logger.warning(f"No se pudo enviar el email a {email}")
        
        logger.info(f"OTP para {email}: {code}")
        
        return {
            "message": "Codigo enviado exitosamente",
            "expires_in": 600,
            "success": True
        }
        
    except Exception as e:
        logger.error(f"Error enviando OTP: {str(e)}")
        raise HTTPException(status_code=500, detail="Error al enviar el codigo")


@router.post("/verify-otp")
async def verify_otp(request: VerifyOtpRequest, req: Request = None):
    """Verifica el codigo OTP y devuelve un token JWT."""
    try:
        email = request.email.lower()
        code = request.code
        
        if email not in otp_store:
            raise HTTPException(status_code=400, detail="No se ha solicitado un codigo para este email")
        
        otp_data = otp_store[email]
        
        if datetime.now(timezone.utc) > otp_data["expires_at"]:
            del otp_store[email]
            raise HTTPException(status_code=400, detail="El codigo ha expirado")
        
        if otp_data["attempts"] >= 3:
            del otp_store[email]
            raise HTTPException(status_code=400, detail="Demasiados intentos. Solicita un nuevo codigo")
        
        if code != otp_data["code"]:
            otp_data["attempts"] += 1
            raise HTTPException(status_code=400, detail="Codigo invalido")
        
        del otp_store[email]
        
        from app.routes.passkeys import supabase_query
        users = supabase_query("profiles", "GET", params={"email": email})
        
        if not users:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        user = users[0]
        
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
        raise HTTPException(status_code=500, detail="Error al verificar el codigo")


# ============================================
# ENDPOINT DE LOGIN
# ============================================

@router.post("/login", response_model=LoginResponse)
async def login(credentials: LoginRequest, req: Request = None):
    """Inicia sesion usando Supabase Auth."""
    logger.info(f"Intentando login para: {credentials.email}")
    
    try:
        async with httpx.AsyncClient() as client:
            auth_response = await client.post(
                f"{settings.supabase_url}/auth/v1/token?grant_type=password",
                headers={
                    "apikey": settings.supabase_key,
                    "Content-Type": "application/json"
                },
                json={
                    "email": credentials.email,
                    "password": credentials.password,
                    "gotrue_meta_security": {}
                }
            )
            
            if auth_response.status_code != 200:
                error_data = {}
                try:
                    error_data = auth_response.json()
                except:
                    pass
                
                error_msg = error_data.get("error_description", error_data.get("error", "Credenciales incorrectas"))
                
                if "Invalid login credentials" in str(error_msg).lower():
                    raise HTTPException(status_code=401, detail="Email o contrasena incorrectos")
                elif "Email not confirmed" in str(error_msg):
                    raise HTTPException(status_code=401, detail="Por favor verifica tu email antes de iniciar sesion")
                else:
                    raise HTTPException(status_code=401, detail=f"Error de autenticacion: {error_msg}")
            
            auth_data = auth_response.json()
            user = auth_data.get("user", {})
            user_id = user.get("id")
            access_token = auth_data.get("access_token")
            refresh_token = auth_data.get("refresh_token")
            expires_in = auth_data.get("expires_in")
            
            if not user_id:
                raise HTTPException(status_code=401, detail="No se pudo obtener informacion del usuario")
            
            is_expired, _ = await is_password_expired(user_id)
            
            if is_expired:
                logger.warning(f"Intento de login con contrasena expirada: {credentials.email}")
                raise HTTPException(
                    status_code=403,
                    detail={
                        "code": "PASSWORD_EXPIRED",
                        "message": "Tu contrasena ha expirado. Debes cambiarla para continuar.",
                        "requires_password_change": True
                    }
                )
            
            user_metadata = user.get("user_metadata", {}) or {}
            
            requires_2fa = False
            try:
                requires_2fa = two_factor_service.is_2fa_enabled(user_id)
            except Exception as e:
                logger.warning(f"Error verificando 2FA: {e}")
            
            if requires_2fa:
                logger.info(f"Usuario {credentials.email} requiere 2FA")
                return LoginResponse(
                    success=True,
                    requires_2fa=True,
                    temp_token=user_id,
                    message="Se requiere codigo de verificacion 2FA",
                    user_id=user_id,
                    user={
                        "id": user_id,
                        "email": credentials.email,
                        "username": user_metadata.get("username") or credentials.email.split("@")[0],
                        "full_name": user_metadata.get("full_name"),
                        "avatar": user_metadata.get("avatar")
                    }
                )
            
            user_data = {
                "id": user_id,
                "email": credentials.email,
                "username": user_metadata.get("username") or credentials.email.split("@")[0],
                "full_name": user_metadata.get("full_name"),
                "avatar": user_metadata.get("avatar"),
                "email_verified": True
            }
            
            return LoginResponse(
                success=True,
                requires_2fa=False,
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in=expires_in,
                user=user_data
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en login: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error al iniciar sesion: {str(e)}")


# ============================================
# ENDPOINTS 2FA (MANTENIDOS)
# ============================================

@router.post("/2fa/enable")
async def enable_2fa(current_user: dict = Depends(get_current_user)):
    """Inicia la activacion de 2FA."""
    try:
        user_id = current_user["user_id"]
        user_email = current_user.get("email", "")
        
        if not user_email:
            from app.routes.passkeys import supabase_query
            users = supabase_query("profiles", "GET", params={"id": user_id})
            if users:
                user_email = users[0].get("email", "")
        
        if not user_email:
            raise HTTPException(status_code=400, detail="No se pudo determinar el email del usuario")
        
        if two_factor_service.is_2fa_enabled(user_id):
            raise HTTPException(status_code=400, detail="2FA ya esta activado")
        
        secret, qr_code, manual_key = two_factor_service.generate_secret(user_email)
        
        return {
            "secret": secret,
            "qr_code": qr_code,
            "manual_key": manual_key,
            "message": "Escanea el codigo QR con Google Authenticator"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en enable_2fa: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error al iniciar 2FA: {str(e)}")


@router.post("/2fa/verify-enable")
async def verify_enable_2fa(
    request: TwoFactorVerifyEnableRequest,
    current_user: dict = Depends(get_current_user)
):
    """Verifica y activa 2FA."""
    try:
        user_id = current_user["user_id"]
        code = request.code
        secret = request.secret
        
        if not code or len(code) != 6:
            raise HTTPException(status_code=400, detail="El codigo debe tener 6 digitos")
        
        is_valid = two_factor_service.verify_code(secret, code)
        
        if not is_valid:
            raise HTTPException(status_code=400, detail="Codigo invalido o expirado")
        
        backup_codes = two_factor_service.generate_backup_codes(8)
        success = two_factor_service.enable_2fa(user_id, secret, backup_codes)
        
        if not success:
            raise HTTPException(status_code=500, detail="Error al guardar la configuracion 2FA")
        
        logger.info(f"2FA activado para usuario {user_id}")
        
        return {
            "success": True,
            "message": "2FA activado correctamente",
            "backup_codes": backup_codes
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en verify_enable_2fa: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error al verificar codigo: {str(e)}")


@router.get("/2fa/status")
async def get_2fa_status(current_user: dict = Depends(get_current_user)):
    """Obtiene el estado del 2FA."""
    try:
        user_id = current_user["user_id"]
        status = two_factor_service.get_2fa_status(user_id)
        return status
    except Exception as e:
        logger.error(f"Error en get_2fa_status: {str(e)}")
        return {"enabled": False, "method": None, "created_at": None}


@router.post("/2fa/disable")
async def disable_2fa(current_user: dict = Depends(get_current_user)):
    """Desactiva 2FA."""
    try:
        user_id = current_user["user_id"]
        success = two_factor_service.disable_2fa(user_id)
        
        if not success:
            raise HTTPException(status_code=500, detail="Error al desactivar 2FA")
        
        return {"success": True, "message": "2FA desactivado correctamente"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en disable_2fa: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error al desactivar 2FA: {str(e)}")


@router.post("/2fa/verify-login")
async def verify_2fa_login(request: TwoFactorLoginVerifyRequest, req: Request = None):
    """Verifica codigo 2FA durante el login."""
    try:
        code = request.code
        temp_token = request.temp_token
        
        if not code or len(code) != 6:
            raise HTTPException(status_code=400, detail="El codigo debe tener 6 digitos")
        
        user_id = temp_token
        
        secret = two_factor_service.get_user_2fa_secret(user_id)
        is_valid = False
        
        if secret:
            is_valid = two_factor_service.verify_code(secret, code)
        
        if not is_valid:
            is_valid = two_factor_service.verify_backup_code(user_id, code)
        
        if not is_valid:
            raise HTTPException(status_code=401, detail="Codigo 2FA invalido o expirado")
        
        from app.routes.passkeys import supabase_query
        users = supabase_query("profiles", "GET", params={"id": user_id})
        
        if not users:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        user = users[0]
        user_email = user.get("email", "")
        
        now = datetime.now(timezone.utc)
        token_data = {
            "sub": str(user_id),
            "userId": str(user_id),
            "email": user_email,
            "aud": "authenticated",
            "role": "authenticated",
            "two_factor_verified": True,
            "iat": now,
            "exp": now + timedelta(days=7)
        }
        
        jwt_token = jwt.encode(token_data, settings.jwt_secret, algorithm="HS256")
        
        logger.info(f"Login con 2FA exitoso para: {user_email}")
        
        return {
            "success": True,
            "token": jwt_token,
            "access_token": jwt_token,
            "token_type": "bearer",
            "expires_in": 604800,
            "user": {
                "id": user_id,
                "email": user_email,
                "username": user.get("username", ""),
                "full_name": user.get("full_name", "")
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en verify_2fa_login: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error al verificar 2FA: {str(e)}")


@router.post("/2fa/verify-backup")
async def verify_2fa_backup(request: TwoFactorBackupVerifyRequest, req: Request = None):
    """Verifica codigo de respaldo durante login."""
    try:
        code = request.code
        temp_token = request.temp_token
        
        user_id = temp_token
        is_valid = two_factor_service.verify_backup_code(user_id, code)
        
        if not is_valid:
            raise HTTPException(status_code=401, detail="Codigo de respaldo invalido")
        
        from app.routes.passkeys import supabase_query
        users = supabase_query("profiles", "GET", params={"id": user_id})
        
        if not users:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        user = users[0]
        user_email = user.get("email", "")
        
        now = datetime.now(timezone.utc)
        final_token = jwt.encode({
            "sub": user_id,
            "userId": user_id,
            "email": user_email,
            "aud": "authenticated",
            "role": "authenticated",
            "iat": now,
            "exp": now + timedelta(days=7)
        }, settings.jwt_secret, algorithm="HS256")
        
        return {
            "success": True,
            "token": final_token,
            "access_token": final_token,
            "user": {
                "id": user_id,
                "email": user_email,
                "username": user.get("username", ""),
                "full_name": user.get("full_name", "")
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en verify_2fa_backup: {str(e)}")
        raise HTTPException(status_code=500, detail="Error al verificar codigo de respaldo")
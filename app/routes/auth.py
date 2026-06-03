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


async def get_user_profile(user_id: str) -> Optional[dict]:
    """Obtiene el perfil del usuario desde la tabla profiles"""
    try:
        client = supabase_client.with_service_role()
        result = client.table("profiles").select("*").eq("id", user_id).execute()
        
        if result and len(result) > 0:
            return result[0]
        return None
    except Exception as e:
        logger.error(f"Error obteniendo perfil de usuario: {e}")
        return None


async def update_user_metadata(user_id: str, metadata: dict) -> bool:
    """Actualiza metadata del usuario en la tabla profiles"""
    return await supabase_client.update_user_metadata(user_id, metadata)


async def is_password_expired(user_id: str) -> tuple[bool, Optional[int]]:
    """Verifica si la contrasena ha expirado"""
    try:
        profile = await get_user_profile(user_id)
        if not profile:
            return False, None
        
        password_expires_at = profile.get("password_expires_at")
        
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


async def check_user_2fa_enabled(user_id: str) -> bool:
    """Verifica si el usuario tiene 2FA activado"""
    try:
        from app.services.two_factor_service import supabase as tf_supabase
        
        result = tf_supabase.table('two_factor_settings')\
            .select('enabled')\
            .eq('user_id', user_id)\
            .eq('enabled', True)\
            .execute()
        
        return result.data and len(result.data) > 0
    except Exception as e:
        logger.warning(f"Error verificando 2FA para usuario {user_id}: {e}")
        return False


# ============================================
# ✅ FUNCIÓN MEJORADA PARA OBTENER URL DEL AVATAR
# ============================================

def _get_avatar_url(user_id: str, existing_url: Optional[str] = None) -> str:
    """
    Obtiene la URL correcta del avatar.
    Si la URL guardada no es válida o es placeholder, busca el archivo real.
    """
    supabase_url = settings.supabase_url
    bucket = "avatars"
    
    if existing_url and existing_url.startswith(supabase_url) and not existing_url.endswith('/avatar.jpg'):
        if any(ext in existing_url for ext in ['.jpg', '.png', '.webp', '.jpeg']):
            return existing_url
    
    return f"{supabase_url}/storage/v1/object/public/{bucket}/{user_id}/avatar-1780098249267.jpg"


def _get_banner_url(user_id: str, existing_url: Optional[str] = None) -> str:
    """
    Obtiene la URL correcta del banner.
    """
    supabase_url = settings.supabase_url
    bucket = "banners"
    
    banner_name = "1775032503-263cd994-d213-4303-98a7-c103a2314333.webp"
    
    if existing_url and existing_url.startswith(supabase_url):
        return existing_url
    
    return f"{supabase_url}/storage/v1/object/public/{bucket}/{user_id}/{banner_name}"


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
        try:
            is_expired, _ = await is_password_expired(user_id)
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
        except Exception as e:
            logger.warning(f"Error verificando expiracion de contrasena: {e}")
        
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
# ENDPOINT DE LOGIN (CORREGIDO CON ROL)
# ============================================

@router.post("/login", response_model=LoginResponse)
async def login(credentials: LoginRequest, req: Request = None):
    """Inicia sesion usando Supabase Auth."""
    logger.info("=" * 50)
    logger.info(f"🔐 Intentando login para: {credentials.email}")
    
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
                    "password": credentials.password
                }
            )
            
            logger.info(f"📡 Supabase Auth response status: {auth_response.status_code}")
            
            if auth_response.status_code != 200:
                error_text = auth_response.text
                logger.warning(f"❌ Auth falló: {auth_response.status_code} - {error_text}")
                
                try:
                    error_data = auth_response.json()
                    error_msg = error_data.get("error_description", error_data.get("error", "Credenciales incorrectas"))
                except:
                    error_msg = "Credenciales incorrectas"
                
                if "Invalid login credentials" in str(error_msg).lower():
                    raise HTTPException(status_code=401, detail="Email o contraseña incorrectos")
                elif "Email not confirmed" in str(error_msg):
                    raise HTTPException(status_code=401, detail="Por favor verifica tu email antes de iniciar sesión")
                else:
                    raise HTTPException(status_code=401, detail=error_msg)
            
            auth_data = auth_response.json()
            user = auth_data.get("user", {})
            user_id = user.get("id")
            access_token = auth_data.get("access_token")
            refresh_token = auth_data.get("refresh_token")
            expires_in = auth_data.get("expires_in")
            
            if not user_id:
                logger.error("❌ No se pudo obtener user_id de la respuesta")
                raise HTTPException(status_code=401, detail="No se pudo obtener información del usuario")
            
            user_metadata = user.get("user_metadata")
            if user_metadata is None:
                user_metadata = {}
            
            logger.info(f"✅ Usuario autenticado: {user_id}")
            logger.info(f"📧 Email: {credentials.email}")
            
            # Verificar expiración de contraseña
            try:
                is_expired, _ = await is_password_expired(user_id)
                if is_expired:
                    logger.warning(f"⚠️ Intento de login con contraseña expirada: {credentials.email}")
                    raise HTTPException(
                        status_code=403,
                        detail={
                            "code": "PASSWORD_EXPIRED",
                            "message": "Tu contraseña ha expirado. Debes cambiarla para continuar.",
                            "requires_password_change": True
                        }
                    )
            except HTTPException:
                raise
            except Exception as e:
                logger.warning(f"⚠️ No se pudo verificar expiración: {e}")
            
            # Verificar 2FA
            requires_2fa = False
            try:
                requires_2fa = await check_user_2fa_enabled(user_id)
                logger.info(f"🔐 2FA activado: {requires_2fa}")
            except Exception as e:
                logger.warning(f"⚠️ Error verificando 2FA: {e}")
                requires_2fa = False
            
            # Obtener perfil completo del usuario desde la tabla profiles
            user_profile = await get_user_profile(user_id)
            
            # ✅ Obtener rol del usuario
            user_role = user_profile.get("role", "user") if user_profile else "user"
            
            # ✅ OBTENER URLs CORRECTAS
            avatar_url = _get_avatar_url(user_id, user_profile.get("avatar_url") if user_profile else None)
            banner_url = _get_banner_url(user_id, user_profile.get("banner_url") if user_profile else None)
            
            if requires_2fa:
                logger.info(f"🔐 Usuario {credentials.email} requiere 2FA")
                
                return LoginResponse(
                    success=True,
                    requires_2fa=True,
                    temp_token=user_id,
                    message="Se requiere código de verificación 2FA",
                    user_id=user_id,
                    user={
                        "id": user_id,
                        "email": credentials.email,
                        "username": user_metadata.get("username") or (user_profile.get("username") if user_profile else None) or credentials.email.split("@")[0],
                        "full_name": user_metadata.get("full_name") or (user_profile.get("full_name") if user_profile else None),
                        "avatar": avatar_url,
                        "banner": banner_url,
                        "role": user_role,  # ✅ AGREGADO: Campo role
                    }
                )
            
            # ✅ DATOS DE USUARIO CON ROL
            user_data = {
                "id": user_id,
                "email": credentials.email,
                "username": user_metadata.get("username") or (user_profile.get("username") if user_profile else None) or credentials.email.split("@")[0],
                "full_name": user_metadata.get("full_name") or (user_profile.get("full_name") if user_profile else None),
                "avatar": avatar_url,
                "banner": banner_url,
                "email_verified": user.get("email_confirmed_at") is not None,
                "role": user_role,  # ✅ AGREGADO: Campo role
            }
            
            logger.info(f"🎉 Login exitoso para: {credentials.email}")
            logger.info(f"👤 Datos usuario: {user_data}")
            logger.info(f"📸 Avatar URL: {avatar_url}")
            logger.info(f"🖼️ Banner URL: {banner_url}")
            logger.info(f"👑 Rol: {user_role}")
            
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
        logger.error(f"❌ Error inesperado en login: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error al iniciar sesión: {str(e)}")


# ============================================
# ENDPOINTS DE RECUPERACION DE CONTRASENA
# ============================================

@router.post("/forgot-password/send-otp", response_model=ForgotPasswordResponse)
async def forgot_password_send_otp(request: ForgotPasswordRequest, req: Request = None):
    """Envia un codigo OTP al email del usuario para resetear contrasena."""
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
    """Verifica el codigo OTP para resetear contrasena."""
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
    """Resetea la contrasena usando el codigo OTP verificado."""
    try:
        email = request.email.lower()
        code = request.code
        new_password = request.new_password
        
        logger.info(f"🔐 [Reset] Intentando resetear contrasena para: {email}")
        
        if email not in reset_otp_store:
            logger.error(f"❌ [Reset] No hay solicitud para {email}")
            raise HTTPException(status_code=400, detail="Solicitud invalida. Reinicia el proceso")
        
        otp_data = reset_otp_store[email]
        
        if not otp_data.get("verified"):
            logger.error(f"❌ [Reset] OTP no verificado para {email}")
            raise HTTPException(status_code=400, detail="Debes verificar el codigo primero")
        
        if code != otp_data.get("code"):
            logger.error(f"❌ [Reset] Codigo no coincide para {email}")
            raise HTTPException(status_code=400, detail="Token invalido")
        
        policy = await supabase_client.get_password_policy()
        is_valid, errors = password_service.validate_strength(new_password, policy)
        if not is_valid:
            logger.error(f"❌ [Reset] Contrasena no cumple requisitos: {errors}")
            raise HTTPException(status_code=400, detail={"errors": errors, "message": "La contrasena no cumple los requisitos"})
        
        user_id = otp_data.get("user_id")
        if not user_id:
            logger.error(f"❌ [Reset] No se encontró user_id para {email}")
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        headers = {
            "apikey": settings.supabase_key,
            "Authorization": f"Bearer {settings.supabase_service_role_key}",
            "Content-Type": "application/json"
        }
        
        async with httpx.AsyncClient() as http_client:
            response = await http_client.put(
                f"{settings.supabase_url}/auth/v1/admin/users/{user_id}",
                headers=headers,
                json={"password": new_password}
            )
            
            if response.status_code != 200:
                error_detail = response.text
                logger.error(f"❌ [Reset] Error en Supabase Auth: {response.status_code} - {error_detail}")
                
                if response.status_code == 403:
                    raise HTTPException(
                        status_code=500, 
                        detail="Error de permisos en el servidor de autenticación. Contacta al administrador."
                    )
                else:
                    raise HTTPException(
                        status_code=500, 
                        detail="Error al actualizar la contrasena en el servidor de autenticación"
                    )
            
            logger.info(f"✅ [Reset] Contraseña actualizada en Supabase Auth")
        
        max_age_days = policy.get("max_age_days", 90)
        expires_at = (datetime.now(timezone.utc) + timedelta(days=max_age_days)).isoformat()
        new_session_version = datetime.now(timezone.utc).timestamp()
        
        await update_user_metadata(user_id, {
            "password_changed_at": datetime.now(timezone.utc).isoformat(),
            "password_expires_at": expires_at,
            "password_reset_via_otp": True,
            "session_version": new_session_version,
            "updated_at": datetime.now(timezone.utc).isoformat()
        })
        
        new_password_hash = password_service.hash_for_history(new_password)
        await supabase_client.record_password_history(user_id, new_password_hash)
        await supabase_client.cleanup_old_password_history(user_id, 20)
        
        await supabase_client.invalidate_all_sessions(user_id)
        
        await security_service.log_security_event(
            user_id=user_id,
            event_type="PASSWORD_RESET_VIA_OTP",
            ip_address=req.client.host if req else None,
            details={"session_version": new_session_version}
        )
        
        user_email = email
        user_name = otp_data.get("user_name", "Usuario")
        await email_service.send_password_change_confirmation(user_email, user_name, req.client.host if req else None)
        
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


# ============================================
# ✅ ENDPOINT VERIFY OTP - CORREGIDO CON ROL
# ============================================

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
        user_id = user["id"]
        
        # ✅ Obtener rol del usuario
        user_role = user.get("role", "user")
        
        # ✅ OBTENER URLs CORRECTAS
        avatar_url = _get_avatar_url(user_id, user.get("avatar_url"))
        banner_url = _get_banner_url(user_id, user.get("banner_url"))
        
        logger.info(f"📸 OTP - Avatar URL: {avatar_url}")
        logger.info(f"🖼️ OTP - Banner URL: {banner_url}")
        logger.info(f"👑 OTP - Rol: {user_role}")
        
        now = datetime.now(timezone.utc)
        token_data = {
            "sub": str(user["id"]),
            "userId": str(user["id"]),
            "email": user["email"],
            "aud": "authenticated",
            "role": "authenticated",
            "user_metadata": {
                "full_name": user.get("full_name", ""),
                "username": user.get("username", ""),
                "avatar": avatar_url,
                "banner": banner_url,
                "role": user_role,  # ✅ AGREGADO: Campo role en metadata
            },
            "iat": now,
            "exp": now + timedelta(days=7)
        }
        
        token = jwt.encode(token_data, settings.jwt_secret, algorithm="HS256")
        
        # ✅ RESPUESTA CON URLs CORRECTAS Y ROL
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": user["id"],
                "email": user["email"],
                "name": user.get("full_name", user.get("username", user.get("email", "").split("@")[0])),
                "username": user.get("username", user.get("email", "").split("@")[0]),
                "full_name": user.get("full_name", ""),
                "avatar": avatar_url,
                "banner": banner_url,
                "role": user_role,  # ✅ AGREGADO: Campo role
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error verificando OTP: {str(e)}")
        raise HTTPException(status_code=500, detail="Error al verificar el codigo")


# ============================================
# ENDPOINTS 2FA (COMPLETOS CON ROL)
# ============================================

@router.post("/2fa/enable")
async def enable_2fa(current_user: dict = Depends(get_current_user)):
    """Inicia la activacion de 2FA."""
    try:
        user_id = current_user["user_id"]
        user_email = current_user.get("email", "")
        
        if not user_email:
            profile = await get_user_profile(user_id)
            if profile:
                user_email = profile.get("email", "")
        
        if not user_email:
            raise HTTPException(status_code=400, detail="No se pudo determinar el email del usuario")
        
        if await check_user_2fa_enabled(user_id):
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
        
        is_valid = False
        verification_method = "unknown"
        
        secret = two_factor_service.get_user_2fa_secret(user_id)
        
        if secret:
            is_valid = two_factor_service.verify_code(secret, code)
            verification_method = "totp"
            
            if is_valid:
                logger.info(f"✅ Código TOTP válido")
            else:
                logger.warning(f"⚠️ Código TOTP inválido")
        
        if not is_valid:
            is_valid = two_factor_service.verify_backup_code(user_id, code)
            verification_method = "backup"
            
            if is_valid:
                logger.info(f"✅ Código de respaldo válido")
            else:
                logger.warning(f"⚠️ Código de respaldo inválido")
        
        if not is_valid:
            raise HTTPException(status_code=401, detail="Codigo 2FA invalido o expirado")
        
        user_profile = await get_user_profile(user_id)
        
        if not user_profile:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        user_email = user_profile.get("email", "")
        user_username = user_profile.get("username", "")
        user_full_name = user_profile.get("full_name", "")
        user_avatar = user_profile.get("avatar_url")
        user_banner = user_profile.get("banner_url")
        user_role = user_profile.get("role", "user")  # ✅ Obtener rol
        
        # ✅ OBTENER URLs CORRECTAS
        avatar_url = _get_avatar_url(user_id, user_avatar)
        banner_url = _get_banner_url(user_id, user_banner)
        
        now = datetime.now(timezone.utc)
        token_data = {
            "sub": str(user_id),
            "userId": str(user_id),
            "email": user_email,
            "aud": "authenticated",
            "role": "authenticated",
            "two_factor_verified": True,
            "verification_method": verification_method,
            "user_metadata": {
                "full_name": user_full_name,
                "username": user_username,
                "avatar": avatar_url,
                "banner": banner_url,
                "role": user_role,  # ✅ AGREGADO: Campo role en metadata
            },
            "iat": now,
            "exp": now + timedelta(days=7)
        }
        
        jwt_token = jwt.encode(token_data, settings.jwt_secret, algorithm="HS256")
        
        logger.info(f"🎉 Login con 2FA exitoso para: {user_email}")
        logger.info(f"👑 Rol: {user_role}")
        
        return {
            "success": True,
            "message": "Código 2FA verificado correctamente. ¡Bienvenido!",
            "token": jwt_token,
            "access_token": jwt_token,
            "token_type": "bearer",
            "expires_in": 604800,
            "verification_method": verification_method,
            "user": {
                "id": user_id,
                "email": user_email,
                "username": user_username or user_email.split("@")[0],
                "full_name": user_full_name or user_username or user_email.split("@")[0],
                "avatar": avatar_url,
                "banner": banner_url,
                "email_verified": True,
                "two_factor_verified": True,
                "role": user_role,  # ✅ AGREGADO: Campo role
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en verify_2fa_login: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error al verificar 2FA: {str(e)}")


@router.post("/2fa/verify-backup")
async def verify_2fa_backup(request: TwoFactorBackupVerifyRequest, req: Request = None):
    """Verifica codigo de respaldo durante login."""
    try:
        code = request.code
        temp_token = request.temp_token
        
        if not code or not temp_token:
            raise HTTPException(
                status_code=400,
                detail="Código y token temporal son requeridos"
            )
        
        user_id = temp_token
        
        is_valid = two_factor_service.verify_backup_code(user_id, code)
        
        if not is_valid:
            raise HTTPException(status_code=401, detail="Código de respaldo inválido o ya utilizado")
        
        user_profile = await get_user_profile(user_id)
        
        if not user_profile:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        user_email = user_profile.get("email", "")
        user_banner = user_profile.get("banner_url")
        user_role = user_profile.get("role", "user")  # ✅ Obtener rol
        
        # ✅ OBTENER URL CORRECTA DEL BANNER
        banner_url = _get_banner_url(user_id, user_banner)
        
        now = datetime.now(timezone.utc)
        final_token = jwt.encode({
            "sub": str(user_id),
            "userId": str(user_id),
            "email": user_email,
            "aud": "authenticated",
            "role": "authenticated",
            "two_factor_verified": True,
            "verification_method": "backup",
            "user_metadata": {
                "banner": banner_url,
                "role": user_role,  # ✅ AGREGADO: Campo role en metadata
            },
            "iat": now,
            "exp": now + timedelta(days=7)
        }, settings.jwt_secret, algorithm="HS256")
        
        return {
            "success": True,
            "message": "Código de respaldo verificado correctamente",
            "token": final_token,
            "access_token": final_token,
            "token_type": "bearer",
            "expires_in": 604800,
            "user": {
                "id": user_id,
                "email": user_email,
                "username": user_profile.get("username", ""),
                "full_name": user_profile.get("full_name", ""),
                "banner": banner_url,
                "role": user_role,  # ✅ AGREGADO: Campo role
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en verify_2fa_backup: {str(e)}")
        raise HTTPException(status_code=500, detail="Error al verificar código de respaldo")
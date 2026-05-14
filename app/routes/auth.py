# app/routes/auth.py
from fastapi import APIRouter, HTTPException, Depends, Header, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
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

# Almacenamiento temporal de OTPs
otp_store = {}

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
    new_password: str


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
            return None
    except Exception as e:
        logger.error(f"Error obteniendo usuario: {e}")
        return None


async def update_user_metadata(user_id: str, metadata: dict) -> bool:
    """Actualiza metadata del usuario"""
    try:
        headers = {
            "apikey": settings.supabase_key,
            "Authorization": f"Bearer {settings.supabase_service_role_key}",
            "Content-Type": "application/json"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.put(
                f"{settings.supabase_url}/auth/v1/admin/users/{user_id}",
                headers=headers,
                json={"user_metadata": metadata}
            )
            return response.status_code == 200
    except Exception as e:
        logger.error(f"Error actualizando metadata: {e}")
        return False


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
    Verifica expiracion de contrasena.
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
        
        # Verificar expiracion de contrasena
        is_expired, days_remaining = await is_password_expired(user_id)
        
        if is_expired:
            logger.warning(f"Contrasena expirada para usuario {user_id}")
            await security_service.log_security_event(
                user_id=user_id,
                event_type=SecurityEventType.PASSWORD_EXPIRED,
                ip_address=request.client.host if request else None,
                details={"token_alg": token_alg}
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "PASSWORD_EXPIRED",
                    "message": "Tu contrasena ha expirado. Debes cambiarla para continuar.",
                    "requires_password_change": True
                }
            )
        
        # Notificar si esta por expirar
        if days_remaining is not None and days_remaining <= 7 and days_remaining > 0:
            logger.info(f"Contrasena por expirar en {days_remaining} dias para {user_id}")
        
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
# ENDPOINT: CAMBIAR CONTRASENA
# ============================================

@router.post("/change-password", response_model=PasswordChangeResponse)
async def change_password(
    request_data: PasswordChangeRequest,
    current_user: dict = Depends(get_current_user),
    req: Request = None
):
    """Cambia la contrasena del usuario con validaciones de seguridad."""
    user_id = current_user["user_id"]
    
    try:
        # Obtener politica de contrasenas
        policy = await supabase_client.get_password_policy()
        
        # Validar nueva contrasena
        is_valid, errors = password_service.validate_strength(request_data.new_password, policy)
        if not is_valid:
            raise HTTPException(status_code=400, detail={"errors": errors, "message": "La contrasena no cumple los requisitos"})
        
        # Verificar que la nueva sea diferente a la actual
        if request_data.new_password == request_data.current_password:
            raise HTTPException(status_code=400, detail="La nueva contrasena debe ser diferente a la actual")
        
        # Obtener usuario actual
        user = await get_user_by_id(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        # Autenticar con contrasena actual
        async with httpx.AsyncClient() as client:
            auth_response = await client.post(
                f"{settings.supabase_url}/auth/v1/token?grant_type=password",
                headers={"apikey": settings.supabase_key, "Content-Type": "application/json"},
                json={"email": user.get("email"), "password": request_data.current_password}
            )
            
            if auth_response.status_code != 200:
                # Registrar intento fallido
                await security_service.record_failed_login(user.get("email"), req.client.host if req else "unknown")
                raise HTTPException(status_code=401, detail="Contrasena actual incorrecta")
        
        # Verificar historial de contrasenas
        new_password_hash = password_service.hash_for_history(request_data.new_password)
        can_reuse = await supabase_client.check_password_reuse(user_id, new_password_hash, policy.get("prevent_reuse_count", 5))
        
        if not can_reuse:
            await security_service.log_security_event(
                user_id=user_id,
                event_type=SecurityEventType.PASSWORD_REUSE_ATTEMPT,
                ip_address=req.client.host if req else None
            )
            raise HTTPException(
                status_code=400,
                detail=f"No puedes usar una contrasena que hayas utilizado en las ultimas {policy.get('prevent_reuse_count', 5)} veces"
            )
        
        # Actualizar contrasena en Supabase
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
                raise HTTPException(status_code=500, detail="Error al actualizar la contrasena")
        
        # Calcular fecha de expiracion
        max_age_days = policy.get("max_age_days", 90)
        expires_at = (datetime.now(timezone.utc) + timedelta(days=max_age_days)).isoformat()
        
        # Actualizar metadata
        await update_user_metadata(user_id, {
            "password_changed_at": datetime.now(timezone.utc).isoformat(),
            "password_expires_at": expires_at
        })
        
        # Registrar en historial
        await supabase_client.record_password_history(user_id, new_password_hash)
        
        # Limpiar historial antiguo
        await supabase_client.cleanup_old_password_history(user_id, 20)
        
        # Invalidar todas las sesiones
        await supabase_client.invalidate_all_sessions(user_id)
        
        # Registrar evento de seguridad
        await security_service.log_security_event(
            user_id=user_id,
            event_type=SecurityEventType.PASSWORD_CHANGED,
            ip_address=req.client.host if req else None
        )
        
        # Enviar email de confirmacion
        user_email = current_user.get("email") or user.get("email")
        if user_email:
            user_name = user.get("user_metadata", {}).get("full_name", "Usuario")
            await email_service.send_password_change_confirmation(user_email, user_name, req.client.host if req else None)
        
        logger.info(f"Contrasena cambiada exitosamente para usuario {user_id}")
        
        return PasswordChangeResponse(
            success=True,
            message="Contrasena actualizada correctamente. Seras redirigido al inicio de sesion.",
            requires_relogin=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en change_password: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error al cambiar contrasena: {str(e)}")


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
        count = await supabase_client.invalidate_all_sessions(user_id)
        
        await security_service.log_security_event(
            user_id=user_id,
            event_type=SecurityEventType.LOGOUT_ALL_SESSIONS,
            ip_address=req.client.host if req else None
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
# ENDPOINTS OTP
# ============================================

@router.post("/send-otp")
async def send_otp(request: SendOtpRequest, req: Request = None):
    """Envía un código OTP al email del usuario."""
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
    """Verifica el código OTP y devuelve un token JWT."""
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
        
        # Buscar usuario en Supabase
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
# ENDPOINT DE LOGIN (MODIFICADO)
# ============================================

@router.post("/login", response_model=LoginResponse)
async def login(credentials: LoginRequest, req: Request = None):
    """Inicia sesion usando Supabase Auth con verificacion de expiracion."""
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
                await security_service.record_failed_login(credentials.email, req.client.host if req else "unknown")
                
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
            
            # Resetear intentos fallidos en login exitoso
            await security_service.reset_failed_logins(credentials.email, req.client.host if req else "unknown")
            
            auth_data = auth_response.json()
            user = auth_data.get("user", {})
            user_id = user.get("id")
            access_token = auth_data.get("access_token")
            refresh_token = auth_data.get("refresh_token")
            expires_in = auth_data.get("expires_in")
            
            if not user_id:
                raise HTTPException(status_code=401, detail="No se pudo obtener informacion del usuario")
            
            # Verificar expiracion de contrasena
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
            
            # Registrar evento de login exitoso
            await security_service.log_security_event(
                user_id=user_id,
                event_type=SecurityEventType.LOGIN_SUCCESS,
                ip_address=req.client.host if req else None
            )
            
            logger.info(f"Usuario autenticado: {credentials.email} (ID: {user_id})")
            
            # Verificar 2FA
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
        
        await security_service.log_security_event(
            user_id=user_id,
            event_type=SecurityEventType.TWO_FACTOR_ENABLED
        )
        
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
        
        await security_service.log_security_event(
            user_id=user_id,
            event_type=SecurityEventType.TWO_FACTOR_DISABLED
        )
        
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
            await security_service.log_security_event(
                user_id=user_id,
                event_type=SecurityEventType.TWO_FACTOR_FAILED,
                ip_address=req.client.host if req else None
            )
            raise HTTPException(status_code=401, detail="Codigo 2FA invalido o expirado")
        
        await security_service.log_security_event(
            user_id=user_id,
            event_type=SecurityEventType.TWO_FACTOR_VERIFIED,
            ip_address=req.client.host if req else None
        )
        
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
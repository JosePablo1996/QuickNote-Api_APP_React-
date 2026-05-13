# app/routes/auth.py
from fastapi import APIRouter, HTTPException, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
import secrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
import httpx
from app.config import settings
from app.services.email_service import send_otp_email
from app.services.two_factor_service import TwoFactorService
from app.services.supabase_client import supabase_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# Esquema de seguridad Bearer
security = HTTPBearer()

# Almacenamiento temporal de OTPs (en producción usar Redis)
otp_store = {}

# Instancia del servicio 2FA
two_factor_service = TwoFactorService()

# ============================================
# MODELOS
# ============================================

class SendOtpRequest(BaseModel):
    email: EmailStr

class VerifyOtpRequest(BaseModel):
    email: EmailStr
    code: str

# Modelo para login
class LoginRequest(BaseModel):
    email: EmailStr
    password: str

# Modelo para respuesta de login CON temp_token
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

# Modelos 2FA
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
# FUNCIÓN DE AUTENTICACIÓN (get_current_user)
# ============================================

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    authorization: Optional[str] = Header(None)
) -> dict:
    """
    Obtiene el usuario actual a partir del token JWT.
    Soporta:
    - Tokens HS256 (generados por nuestro backend)
    - Tokens ES256 (generados por Supabase Auth)
    
    ✅ CORREGIDO: Ahora devuelve el token original para usar en clientes Supabase
    """
    try:
        token = credentials.credentials if credentials else None
        
        if not token and authorization:
            if authorization.startswith("Bearer "):
                token = authorization[7:]
        
        if not token:
            raise HTTPException(
                status_code=401,
                detail="Token de autenticación no proporcionado"
            )
        
        # Guardar el token original para usarlo en las consultas a Supabase
        original_token = token
        
        token_header = jwt.get_unverified_header(token)
        token_alg = token_header.get("alg", "unknown")
        logger.info(f"🔑 Token recibido: alg={token_alg}, primeros 30: {token[:30]}...")
        
        # Decodificar sin verificar firma primero
        try:
            payload = jwt.decode(
                token,
                options={"verify_signature": False, "verify_exp": True}
            )
            logger.info(f"✅ Token {token_alg} decodificado: sub={payload.get('sub')}")
        except jwt.InvalidTokenError as e:
            logger.error(f"❌ Token inválido: {e}")
            raise HTTPException(status_code=401, detail="Token inválido o expirado")
        
        user_id = payload.get("sub") or payload.get("userId") or payload.get("user_id")
        user_email = payload.get("email") or payload.get("user_metadata", {}).get("email")
        
        if not user_id:
            raise HTTPException(
                status_code=401,
                detail="Token no contiene información de usuario"
            )
        
        # ✅ CRÍTICO: Devolver el token ORIGINAL para usarlo en Supabase
        return {
            "user_id": user_id,
            "sub": user_id,
            "email": user_email,
            "payload": payload,
            "token": original_token  # ✅ Token original para autenticación en Supabase
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en get_current_user: {e}")
        raise HTTPException(
            status_code=401,
            detail="Error al validar autenticación"
        )


# ============================================
# ENDPOINT DE LOGIN CON SOPORTE 2FA
# ============================================

@router.post("/login", response_model=LoginResponse)
async def login(credentials: LoginRequest):
    """
    Inicia sesión usando Supabase Auth.
    Soporta autenticación normal y 2FA.
    
    Flujo:
    1. Si el usuario NO tiene 2FA -> Retorna access_token directamente
    2. Si el usuario TIENE 2FA -> Retorna temp_token (user_id) para verificar después
    """
    logger.info(f"📝 Intentando login para: {credentials.email}")
    
    try:
        # PASO 1: Autenticar con Supabase Auth usando REST API
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
            
            logger.info(f"📡 Respuesta Supabase Auth: {auth_response.status_code}")
            
            if auth_response.status_code != 200:
                error_data = {}
                try:
                    error_data = auth_response.json()
                except:
                    pass
                
                error_msg = error_data.get("error_description", error_data.get("error", "Credenciales incorrectas"))
                logger.error(f"❌ Error autenticación: {error_msg}")
                
                if "Invalid login credentials" in str(error_msg).lower() or "invalid" in str(error_msg).lower():
                    raise HTTPException(
                        status_code=401,
                        detail="Email o contraseña incorrectos"
                    )
                elif "Email not confirmed" in str(error_msg):
                    raise HTTPException(
                        status_code=401,
                        detail="Por favor verifica tu email antes de iniciar sesión. Revisa tu bandeja de entrada."
                    )
                else:
                    raise HTTPException(
                        status_code=401,
                        detail=f"Error de autenticación: {error_msg}"
                    )
            
            auth_data = auth_response.json()
            logger.info(f"📦 Respuesta auth: user_id presente: {'✅' if auth_data.get('user') else '❌'}")
            
            user = auth_data.get("user", {})
            user_id = user.get("id")
            access_token = auth_data.get("access_token")
            refresh_token = auth_data.get("refresh_token")
            expires_in = auth_data.get("expires_in")
            
            if not user_id:
                raise HTTPException(
                    status_code=401,
                    detail="No se pudo obtener información del usuario"
                )
            
            # Obtener metadata del usuario
            user_metadata = user.get("user_metadata", {}) or {}
            
            logger.info(f"✅ Usuario autenticado: {credentials.email} (ID: {user_id})")
            logger.info(f"   Email confirmado: {'✅' if user.get('email_confirmed_at') else '❌'}")
            
            # Verificar email confirmado
            if not user.get("email_confirmed_at"):
                logger.warning(f"⚠️ Intento de login con email no verificado: {credentials.email}")
                raise HTTPException(
                    status_code=401,
                    detail="Por favor verifica tu email antes de iniciar sesión. Revisa tu bandeja de entrada."
                )
            
            # PASO 2: Verificar si el usuario tiene 2FA activado
            requires_2fa = False
            
            try:
                requires_2fa = two_factor_service.is_2fa_enabled(user_id)
                logger.info(f"🔍 2FA status para {credentials.email}: {'✅ Activado' if requires_2fa else '❌ Desactivado'}")
            except Exception as e:
                logger.warning(f"⚠️ Error verificando 2FA: {e}")
                requires_2fa = False
            
            # PASO 3: Si requiere 2FA, devolver temp_token (user_id)
            if requires_2fa:
                logger.info(f"🔐 Usuario {credentials.email} requiere 2FA - Generando temp_token")
                
                return LoginResponse(
                    success=True,
                    requires_2fa=True,
                    temp_token=user_id,
                    message="Se requiere código de verificación 2FA",
                    user_id=user_id,
                    user={
                        "id": user_id,
                        "email": credentials.email,
                        "username": user_metadata.get("username") or credentials.email.split("@")[0],
                        "full_name": user_metadata.get("full_name"),
                        "avatar": user_metadata.get("avatar")
                    }
                )
            
            # PASO 4: Login exitoso sin 2FA - Devolver tokens
            logger.info(f"✅ Login exitoso para: {credentials.email} (sin 2FA)")
            
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
        error_msg = str(e)
        logger.error(f"❌ Error en login: {error_msg}")
        logger.exception("Stacktrace completo:")
        
        raise HTTPException(
            status_code=500,
            detail=f"Error al iniciar sesión: {error_msg}"
        )


# ============================================
# ENDPOINTS OTP
# ============================================

@router.post("/send-otp")
async def send_otp(request: SendOtpRequest):
    """Envía un código OTP al email del usuario"""
    try:
        email = request.email.lower()
        
        code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
        
        otp_store[email] = {
            "code": code,
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10),
            "attempts": 0
        }
        
        logger.info(f"📧 Enviando OTP para {email}...")
        email_sent = await send_otp_email(email, code)
        
        if not email_sent:
            logger.warning(f"⚠️ No se pudo enviar el email a {email}")
        
        logger.info(f"📧 OTP para {email}: {code}")
        
        return {
            "message": "Código enviado exitosamente",
            "expires_in": 600,
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
        
        if email not in otp_store:
            raise HTTPException(status_code=400, detail="No se ha solicitado un código para este email")
        
        otp_data = otp_store[email]
        
        if datetime.now(timezone.utc) > otp_data["expires_at"]:
            del otp_store[email]
            raise HTTPException(status_code=400, detail="El código ha expirado")
        
        if otp_data["attempts"] >= 3:
            del otp_store[email]
            raise HTTPException(status_code=400, detail="Demasiados intentos. Solicita un nuevo código")
        
        if code != otp_data["code"]:
            otp_data["attempts"] += 1
            raise HTTPException(status_code=400, detail="Código inválido")
        
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
        raise HTTPException(status_code=500, detail="Error al verificar el código")


# ============================================
# ENDPOINTS 2FA (TWO-FACTOR AUTHENTICATION)
# ============================================

@router.post("/2fa/enable")
async def enable_2fa(current_user: dict = Depends(get_current_user)):
    """
    Paso 1: Inicia la activación de 2FA.
    Genera secreto TOTP, QR code y clave manual.
    """
    try:
        user_id = current_user["user_id"]
        user_email = current_user.get("email", "")
        
        if not user_email:
            user_email = current_user.get("payload", {}).get("email", "")
        
        if not user_email:
            from app.routes.passkeys import supabase_query
            users = supabase_query("profiles", "GET", params={"id": user_id})
            if users:
                user_email = users[0].get("email", "")
        
        if not user_email:
            raise HTTPException(status_code=400, detail="No se pudo determinar el email del usuario")
        
        logger.info(f"🔐 Iniciando activación 2FA para: {user_email}")
        
        if two_factor_service.is_2fa_enabled(user_id):
            raise HTTPException(status_code=400, detail="2FA ya está activado para este usuario")
        
        secret, qr_code, manual_key = two_factor_service.generate_secret(user_email)
        
        logger.info(f"✅ QR code generado exitosamente para {user_email}")
        
        return {
            "secret": secret,
            "qr_code": qr_code,
            "manual_key": manual_key,
            "message": "Escanea el código QR con Google Authenticator"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en enable_2fa: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error al iniciar 2FA: {str(e)}")


@router.post("/2fa/verify-enable")
async def verify_enable_2fa(
    request: TwoFactorVerifyEnableRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Paso 2: Verifica el código TOTP y activa 2FA.
    """
    try:
        user_id = current_user["user_id"]
        code = request.code
        secret = request.secret
        
        logger.info(f"🔍 Verificando código 2FA para usuario {user_id}")
        
        if not code or len(code) != 6:
            raise HTTPException(status_code=400, detail="El código debe tener 6 dígitos")
        
        if not secret:
            raise HTTPException(status_code=400, detail="Secreto no proporcionado")
        
        is_valid = two_factor_service.verify_code(secret, code)
        
        if not is_valid:
            logger.warning(f"⚠️ Código 2FA inválido para usuario {user_id}")
            raise HTTPException(status_code=400, detail="Código inválido o expirado")
        
        backup_codes = two_factor_service.generate_backup_codes(8)
        logger.info(f"📝 {len(backup_codes)} códigos de respaldo generados")
        
        success = two_factor_service.enable_2fa(
            user_id=user_id,
            secret=secret,
            backup_codes=backup_codes
        )
        
        if not success:
            raise HTTPException(status_code=500, detail="Error al guardar la configuración 2FA")
        
        logger.info(f"🎉 2FA activado exitosamente para usuario {user_id}")
        
        return {
            "success": True,
            "message": "2FA activado correctamente",
            "backup_codes": backup_codes
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en verify_enable_2fa: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error al verificar código: {str(e)}")


@router.get("/2fa/status")
async def get_2fa_status(current_user: dict = Depends(get_current_user)):
    """Obtiene el estado actual del 2FA del usuario"""
    try:
        user_id = current_user["user_id"]
        status = two_factor_service.get_2fa_status(user_id)
        return status
    except Exception as e:
        logger.error(f"❌ Error en get_2fa_status: {str(e)}")
        return {"enabled": False, "method": None, "created_at": None}


@router.post("/2fa/disable")
async def disable_2fa(current_user: dict = Depends(get_current_user)):
    """Desactiva 2FA para el usuario actual"""
    try:
        user_id = current_user["user_id"]
        success = two_factor_service.disable_2fa(user_id)
        
        if not success:
            raise HTTPException(status_code=500, detail="Error al desactivar 2FA")
        
        return {"success": True, "message": "2FA desactivado correctamente"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en disable_2fa: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error al desactivar 2FA: {str(e)}")


@router.post("/2fa/verify-login")
async def verify_2fa_login(request: TwoFactorLoginVerifyRequest):
    """
    Verifica código 2FA durante el login.
    Acepta temp_token como user_id y devuelve JWT si el código es válido.
    """
    try:
        code = request.code
        temp_token = request.temp_token
        
        logger.info(f"🔐 Verificando código 2FA para login")
        logger.info(f"   temp_token (user_id): {temp_token}")
        logger.info(f"   código: {code}")
        
        if not code or len(code) != 6:
            raise HTTPException(status_code=400, detail="El código debe tener 6 dígitos")
        
        if not temp_token:
            raise HTTPException(status_code=400, detail="Token temporal no proporcionado")
        
        user_id = temp_token
        
        # Intentar verificar con TOTP
        secret = two_factor_service.get_user_2fa_secret(user_id)
        is_valid = False
        
        if secret:
            logger.info(f"🔍 Verificando código TOTP para usuario {user_id}")
            is_valid = two_factor_service.verify_code(secret, code)
        else:
            logger.info(f"🔍 No se encontró secreto TOTP, intentando código de respaldo...")
            is_valid = two_factor_service.verify_backup_code(user_id, code)
        
        if not is_valid:
            logger.warning(f"⚠️ Código 2FA inválido para usuario {user_id}")
            raise HTTPException(status_code=401, detail="Código 2FA inválido o expirado")
        
        # Código válido - Obtener datos del usuario
        from app.routes.passkeys import supabase_query
        
        users = supabase_query("profiles", "GET", params={"id": user_id})
        
        if not users:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        user = users[0]
        user_email = user.get("email", "")
        
        logger.info(f"✅ Código 2FA válido para: {user_email}")
        
        # Generar token JWT final
        now = datetime.now(timezone.utc)
        token_data = {
            "sub": str(user_id),
            "userId": str(user_id),
            "email": user_email,
            "aud": "authenticated",
            "role": "authenticated",
            "two_factor_verified": True,
            "user_metadata": {
                "full_name": user.get("full_name", ""),
                "username": user.get("username", "")
            },
            "iat": now,
            "exp": now + timedelta(days=7)
        }
        
        jwt_token = jwt.encode(token_data, settings.jwt_secret, algorithm="HS256")
        
        logger.info(f"✅ Login con 2FA exitoso para: {user_email}")
        
        return {
            "success": True,
            "message": "Código 2FA verificado correctamente",
            "token": jwt_token,
            "access_token": jwt_token,
            "refresh_token": jwt_token,
            "token_type": "bearer",
            "expires_in": 604800,
            "user": {
                "id": user_id,
                "email": user_email,
                "username": user.get("username", ""),
                "full_name": user.get("full_name", ""),
                "avatar": user.get("avatar")
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
async def verify_2fa_backup(request: TwoFactorBackupVerifyRequest):
    """Verifica código de respaldo 2FA durante el login"""
    try:
        code = request.code
        temp_token = request.temp_token
        
        user_id = temp_token
        
        is_valid = two_factor_service.verify_backup_code(user_id, code)
        
        if not is_valid:
            raise HTTPException(status_code=401, detail="Código de respaldo inválido")
        
        # Obtener datos del usuario
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
            "message": "Código de respaldo verificado",
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
        logger.error(f"❌ Error en verify_2fa_backup: {str(e)}")
        raise HTTPException(status_code=500, detail="Error al verificar código de respaldo")
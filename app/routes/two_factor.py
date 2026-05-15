# app/routes/two_factor.py
from fastapi import APIRouter, HTTPException, Depends, status
from app.models.two_factor import (
    TwoFactorEnableResponse,
    TwoFactorVerifyRequest,
    TwoFactorVerifyResponse,
    TwoFactorLoginVerifyRequest,
    TwoFactorStatusResponse
)
from app.services.two_factor_service import TwoFactorService
from app.routes.auth import get_current_user
import logging
import jwt
from datetime import datetime, timedelta, timezone
from app.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/auth/2fa", tags=["2FA"])

# ✅ Instancia del servicio 2FA (sin pasar supabase_client porque ya lo maneja internamente)
two_factor_service = TwoFactorService()

# ============================================
# FUNCIÓN AUXILIAR PARA OBTENER DATOS DE USUARIO
# ============================================

async def get_user_data(user_id: str) -> dict:
    """
    Obtiene los datos del usuario desde Supabase.
    Busca en la tabla 'profiles'.
    """
    try:
        from app.routes.passkeys import supabase_query
        
        users = supabase_query("profiles", "GET", params={"id": user_id})
        
        if users and len(users) > 0:
            return users[0]
        
        logger.warning(f"⚠️ Usuario no encontrado en profiles: {user_id}")
        return {}
        
    except Exception as e:
        logger.error(f"❌ Error obteniendo usuario {user_id}: {e}")
        return {}


# ============================================
# ENDPOINT: ACTIVAR 2FA (PASO 1 - GENERAR QR)
# ============================================

@router.post("/enable", response_model=TwoFactorEnableResponse)
async def enable_2fa(current_user: dict = Depends(get_current_user)):
    """
    Inicia el proceso de activación de 2FA.
    Genera un secreto TOTP y un QR code para Google Authenticator.
    """
    try:
        user_id = current_user.get("user_id") or current_user.get("sub")
        user_email = current_user.get("email")
        
        if not user_id or not user_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Información de usuario incompleta"
            )
        
        # Verificar si ya tiene 2FA activado
        is_enabled = two_factor_service.is_2fa_enabled(user_id)
        if is_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="2FA ya está activado. Desactívalo primero para reconfigurar."
            )
        
        # Generar secreto y QR
        secret, qr_code, manual_key = two_factor_service.generate_secret(user_email)
        
        logger.info(f"✅ QR code generado para {user_email}")
        
        return TwoFactorEnableResponse(
            secret=secret,
            qr_code=qr_code,
            manual_key=manual_key,
            message="Escanea el código QR con Google Authenticator. Luego verifica con el código de 6 dígitos."
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error enabling 2FA: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al iniciar la activación de 2FA"
        )


# ============================================
# ENDPOINT: VERIFICAR Y ACTIVAR 2FA (PASO 2)
# ============================================

@router.post("/verify-enable", response_model=TwoFactorVerifyResponse)
async def verify_enable_2fa(
    request: TwoFactorVerifyRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Verifica el código TOTP y activa 2FA para el usuario.
    """
    try:
        user_id = current_user.get("user_id") or current_user.get("sub")
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Información de usuario incompleta"
            )
        
        logger.info(f"🔍 Verificando código 2FA para activación - Usuario: {user_id}")
        
        # Validar código
        if not request.code or len(request.code) != 6:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="El código debe tener 6 dígitos"
            )
        
        if not request.secret:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Secreto no proporcionado"
            )
        
        # Verificar el código TOTP
        is_valid = two_factor_service.verify_code(request.secret, request.code)
        
        if not is_valid:
            logger.warning(f"⚠️ Código TOTP inválido para activación - Usuario: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Código inválido. Asegúrate de que Google Authenticator esté sincronizado."
            )
        
        # Generar códigos de respaldo
        backup_codes = two_factor_service.generate_backup_codes(8)
        logger.info(f"📝 {len(backup_codes)} códigos de respaldo generados")
        
        # Activar 2FA
        success = two_factor_service.enable_2fa(user_id, request.secret, backup_codes)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al guardar la configuración 2FA"
            )
        
        logger.info(f"🎉 2FA activado exitosamente para usuario {user_id}")
        
        return TwoFactorVerifyResponse(
            success=True,
            message="2FA activado correctamente. Guarda tus códigos de respaldo en un lugar seguro.",
            backup_codes=backup_codes
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error verifying 2FA enable: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al verificar y activar 2FA"
        )


# ============================================
# ✅ ENDPOINT CORREGIDO: VERIFICAR 2FA EN LOGIN
# ============================================

@router.post("/verify-login")
async def verify_2fa_login(request: TwoFactorLoginVerifyRequest):
    """
    ✅ IMPLEMENTADO CORRECTAMENTE:
    Verifica el código 2FA durante el inicio de sesión.
    Recibe temp_token (user_id) y código TOTP.
    Retorna JWT final si el código es válido.
    
    Flujo:
    1. Recibe temp_token (user_id del paso anterior) y código de 6 dígitos
    2. Busca el secreto TOTP del usuario en two_factor_settings
    3. Verifica el código TOTP (o código de respaldo)
    4. Si es válido, genera JWT final con two_factor_verified=True
    5. Retorna el token y datos del usuario
    """
    try:
        code = request.code
        temp_token = request.temp_token
        
        logger.info("=" * 50)
        logger.info("🔐 VERIFICANDO CÓDIGO 2FA PARA LOGIN")
        logger.info(f"   temp_token (user_id): {temp_token}")
        logger.info(f"   código: {code}")
        
        # Validaciones básicas
        if not code or len(code) != 6 or not code.isdigit():
            logger.warning(f"⚠️ Código inválido: '{code}'")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="El código debe tener 6 dígitos numéricos"
            )
        
        if not temp_token:
            logger.error("❌ temp_token no proporcionado")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token temporal no proporcionado. Vuelve a iniciar sesión."
            )
        
        user_id = temp_token
        logger.info(f"👤 Verificando 2FA para user_id: {user_id}")
        
        # ✅ PASO 1: Intentar verificar con TOTP
        is_valid = False
        verification_method = "unknown"
        
        # Obtener el secreto TOTP del usuario
        secret = two_factor_service.get_user_2fa_secret(user_id)
        
        if secret:
            logger.info(f"🔑 Secreto TOTP encontrado, verificando código...")
            is_valid = two_factor_service.verify_code(secret, code)
            verification_method = "totp"
            
            if is_valid:
                logger.info(f"✅ Código TOTP válido")
            else:
                logger.warning(f"⚠️ Código TOTP inválido")
        else:
            logger.info(f"🔍 No se encontró secreto TOTP, intentando código de respaldo...")
            
        # ✅ PASO 2: Si falló TOTP (o no hay secreto), intentar código de respaldo
        if not is_valid:
            is_valid = two_factor_service.verify_backup_code(user_id, code)
            verification_method = "backup"
            
            if is_valid:
                logger.info(f"✅ Código de respaldo válido")
            else:
                logger.warning(f"⚠️ Código de respaldo inválido")
        
        # ✅ PASO 3: Si ambos fallaron, rechazar
        if not is_valid:
            logger.error(f"❌ Código 2FA inválido para usuario {user_id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Código 2FA inválido o expirado. Intenta de nuevo."
            )
        
        # ✅ PASO 4: Código válido - Obtener datos del usuario
        logger.info(f"🔍 Obteniendo datos del usuario {user_id}...")
        user_data = await get_user_data(user_id)
        
        if not user_data:
            logger.error(f"❌ Usuario {user_id} no encontrado en profiles")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado. Contacta al soporte."
            )
        
        user_email = user_data.get("email", "")
        user_username = user_data.get("username", "")
        user_full_name = user_data.get("full_name", "")
        user_avatar = user_data.get("avatar")
        
        logger.info(f"✅ Usuario encontrado: {user_email}")
        logger.info(f"   username: {user_username}")
        logger.info(f"   full_name: {user_full_name}")
        logger.info(f"   avatar: {'Sí' if user_avatar else 'No'}")
        
        # ✅ PASO 5: Generar token JWT final (HS256)
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
                "username": user_username
            },
            "iat": now,
            "exp": now + timedelta(days=7)
        }
        
        jwt_token = jwt.encode(token_data, settings.jwt_secret, algorithm="HS256")
        
        logger.info(f"🎉 LOGIN CON 2FA EXITOSO para: {user_email}")
        logger.info(f"   Método de verificación: {verification_method}")
        logger.info(f"   Token generado: {jwt_token[:50]}...")
        logger.info("=" * 50)
        
        # ✅ PASO 6: Retornar respuesta exitosa
        return {
            "success": True,
            "message": "Código 2FA verificado correctamente. ¡Bienvenido!",
            "token": jwt_token,
            "access_token": jwt_token,
            "refresh_token": jwt_token,  # En producción, generar refresh token separado
            "token_type": "bearer",
            "expires_in": 604800,  # 7 días en segundos
            "verification_method": verification_method,
            "user": {
                "id": user_id,
                "email": user_email,
                "username": user_username or user_email.split("@")[0],
                "full_name": user_full_name or user_username or user_email.split("@")[0],
                "avatar": user_avatar,
                "email_verified": True,
                "two_factor_verified": True
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error inesperado en verify_2fa_login: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al verificar 2FA: {str(e)}"
        )


# ============================================
# ENDPOINT: VERIFICAR CÓDIGO DE RESPALDO
# ============================================

@router.post("/verify-backup")
async def verify_2fa_backup(request: TwoFactorLoginVerifyRequest):
    """
    Verifica código de respaldo 2FA durante el login.
    Similar a verify-login pero específico para códigos de respaldo.
    """
    try:
        code = request.code
        temp_token = request.temp_token
        
        logger.info(f"🔐 Verificando código de respaldo para user_id: {temp_token}")
        
        if not code or not temp_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Código y token temporal son requeridos"
            )
        
        user_id = temp_token
        
        # Verificar código de respaldo
        is_valid = two_factor_service.verify_backup_code(user_id, code)
        
        if not is_valid:
            logger.warning(f"⚠️ Código de respaldo inválido para usuario {user_id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Código de respaldo inválido o ya utilizado"
            )
        
        # Obtener datos del usuario
        user_data = await get_user_data(user_id)
        
        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado"
            )
        
        user_email = user_data.get("email", "")
        
        logger.info(f"✅ Código de respaldo válido para: {user_email}")
        
        # Generar JWT
        now = datetime.now(timezone.utc)
        final_token = jwt.encode({
            "sub": str(user_id),
            "userId": str(user_id),
            "email": user_email,
            "aud": "authenticated",
            "role": "authenticated",
            "two_factor_verified": True,
            "verification_method": "backup",
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
                "username": user_data.get("username", ""),
                "full_name": user_data.get("full_name", "")
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en verify_2fa_backup: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al verificar código de respaldo"
        )


# ============================================
# ENDPOINT: DESACTIVAR 2FA
# ============================================

@router.post("/disable")
async def disable_2fa(
    current_user: dict = Depends(get_current_user)
):
    """Desactiva 2FA para el usuario actual"""
    try:
        user_id = current_user.get("user_id") or current_user.get("sub")
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Información de usuario incompleta"
            )
        
        logger.info(f"🔐 Desactivando 2FA para usuario: {user_id}")
        
        success = two_factor_service.disable_2fa(user_id)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al desactivar 2FA"
            )
        
        logger.info(f"✅ 2FA desactivado para usuario: {user_id}")
        
        return {
            "success": True, 
            "message": "2FA desactivado correctamente"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error disabling 2FA: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al desactivar 2FA"
        )


# ============================================
# ENDPOINT: ESTADO DE 2FA
# ============================================

@router.get("/status", response_model=TwoFactorStatusResponse)
async def get_2fa_status(current_user: dict = Depends(get_current_user)):
    """Obtiene el estado actual del 2FA del usuario"""
    try:
        user_id = current_user.get("user_id") or current_user.get("sub")
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Información de usuario incompleta"
            )
        
        logger.info(f"🔍 Consultando estado 2FA para usuario: {user_id}")
        
        status_data = two_factor_service.get_2fa_status(user_id)
        
        logger.info(f"📊 Estado 2FA: {'✅ Activado' if status_data.get('enabled') else '❌ Desactivado'}")
        
        return TwoFactorStatusResponse(**status_data)
        
    except Exception as e:
        logger.error(f"❌ Error getting 2FA status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al obtener estado de 2FA"
        )
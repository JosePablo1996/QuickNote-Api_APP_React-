# app/routes/passkeys.py
from fastapi import APIRouter, HTTPException, Depends, Request
from typing import Dict, Any
import secrets
import logging
import jwt
from datetime import datetime, timedelta, timezone

from app.models.passkey import (
    WebAuthnRegistrationStart,
    WebAuthnRegistrationComplete,
    WebAuthnLoginStart,
    WebAuthnLoginComplete,
)
from app.services.passkey_service import passkey_service
from app.services.supabase_client import supabase_client
from app.config import settings

# ✅ Configurar logger
logger = logging.getLogger(__name__)

# En producción, usar Redis o una base de datos temporal
challenges_store = {}

router = APIRouter(prefix="/passkeys", tags=["passkeys"])

@router.post("/register/start")
async def start_register(request: WebAuthnRegistrationStart):
    """Iniciar registro de passkey"""
    try:
        email = request.email
        logger.info(f"📝 Iniciando registro de passkey para: {email}")
        
        # Verificar si el usuario existe
        result = supabase_client.table("users").select("*").eq("email", email).execute()
        
        if not result:
            logger.warning(f"⚠️ Usuario no encontrado: {email}")
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        user = result[0]
        user_id = user["id"]
        logger.info(f"✅ Usuario encontrado: {user_id}")
        
        # Generar challenge
        registration_options = passkey_service.generate_registration_challenge(
            email=email,
            user_id=user_id
        )
        
        # Guardar el challenge
        challenge_id = secrets.token_hex(32)
        challenges_store[challenge_id] = {
            "challenge": registration_options["challenge"],
            "email": email,
            "user_id": user_id,
            "type": "registration"
        }
        
        logger.info(f"✅ Challenge generado: {challenge_id[:16]}...")
        
        return {
            "challenge_id": challenge_id,
            "options": registration_options
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error iniciando registro: {str(e)}")
        raise HTTPException(status_code=500, detail="Error interno del servidor")

@router.post("/register/complete")
async def complete_register(request: WebAuthnRegistrationComplete):
    """Completar registro de passkey"""
    try:
        logger.info("📝 Completando registro de passkey")
        
        # Obtener el challenge guardado
        challenge_id = request.credential.get("challenge_id")
        if not challenge_id or challenge_id not in challenges_store:
            logger.warning(f"⚠️ Challenge no válido: {challenge_id}")
            raise HTTPException(status_code=400, detail="Challenge no válido")
        
        challenge_data = challenges_store.pop(challenge_id)
        logger.info(f"✅ Challenge encontrado para: {challenge_data['email']}")
        
        # Verificar el registro
        success, credential_data = passkey_service.verify_registration(
            credential=request.credential,
            challenge=challenge_data["challenge"]
        )
        
        if not success:
            logger.error("❌ Fallo en la verificación del registro")
            raise HTTPException(status_code=400, detail="Fallo en la verificación")
        
        logger.info("✅ Registro verificado correctamente")
        
        # Guardar la credencial en Supabase
        passkey_data = {
            "user_id": challenge_data["user_id"],
            "credential_id": credential_data["credential_id"],
            "public_key": credential_data["public_key"],
            "sign_count": credential_data["sign_count"],
            "device_name": request.device_name or "Mi dispositivo",
            "created_at": "now()",
            "last_used_at": "now()"
        }
        
        result = supabase_client.table("passkeys").insert(passkey_data).execute()
        
        if not result:
            logger.error("❌ Error guardando credencial en Supabase")
            raise HTTPException(status_code=500, detail="Error guardando credencial")
        
        logger.info(f"✅ Passkey registrada: {credential_data['credential_id'][:20]}...")
        
        return {
            "message": "Passkey registrada exitosamente",
            "credential_id": credential_data["credential_id"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error completando registro: {str(e)}")
        raise HTTPException(status_code=500, detail="Error interno del servidor")

@router.post("/login/start")
async def start_login(request: WebAuthnLoginStart):
    """Iniciar login con passkey"""
    try:
        email = request.email
        logger.info(f"🔐 Iniciando login con passkey para: {email}")
        
        # Generar challenge para login
        authentication_options = passkey_service.generate_login_challenge()
        
        # Guardar el challenge
        challenge_id = secrets.token_hex(32)
        challenges_store[challenge_id] = {
            "challenge": authentication_options["challenge"],
            "email": email,
            "type": "login"
        }
        
        logger.info(f"✅ Challenge de login generado: {challenge_id[:16]}...")
        
        return {
            "challenge_id": challenge_id,
            "options": authentication_options,
            "rpId": passkey_service.rp_id
        }
        
    except Exception as e:
        logger.error(f"❌ Error iniciando login: {str(e)}")
        raise HTTPException(status_code=500, detail="Error interno del servidor")

@router.post("/login/complete")
async def complete_login(request: WebAuthnLoginComplete):
    """Completar login con passkey"""
    try:
        logger.info("🔐 Completando login con passkey")
        
        # Obtener el challenge guardado
        challenge_id = request.credential.get("challenge_id")
        if not challenge_id or challenge_id not in challenges_store:
            logger.warning(f"⚠️ Challenge no válido: {challenge_id}")
            raise HTTPException(status_code=400, detail="Challenge no válido")
        
        challenge_data = challenges_store.pop(challenge_id)
        logger.info(f"✅ Challenge encontrado para: {challenge_data.get('email', 'desconocido')}")
        
        # Obtener la credencial del usuario de Supabase
        credential_id = request.credential.get("id")
        result = supabase_client.table("passkeys").select("*").eq("credential_id", credential_id).execute()
        
        if not result:
            logger.warning(f"⚠️ Passkey no encontrada: {credential_id}")
            raise HTTPException(status_code=404, detail="Passkey no encontrada")
        
        stored_credential = result[0]
        logger.info(f"✅ Passkey encontrada para usuario: {stored_credential['user_id']}")
        
        # Verificar el login
        success, new_sign_count = passkey_service.verify_login(
            credential=request.credential,
            challenge=challenge_data["challenge"],
            stored_credential=stored_credential
        )
        
        if not success:
            logger.error("❌ Fallo en la verificación del login")
            raise HTTPException(status_code=400, detail="Fallo en la verificación")
        
        logger.info("✅ Login verificado correctamente")
        
        # Actualizar sign_count y last_used_at
        supabase_client.table("passkeys").update({
            "sign_count": new_sign_count,
            "last_used_at": "now()"
        }).eq("id", stored_credential["id"]).execute()
        
        # Generar JWT para el usuario
        user_id = stored_credential["user_id"]
        user_result = supabase_client.table("users").select("*").eq("id", user_id).execute()
        
        if not user_result:
            logger.warning(f"⚠️ Usuario no encontrado: {user_id}")
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        user = user_result[0]
        logger.info(f"✅ Usuario encontrado: {user['email']}")
        
        # Generar token JWT
        token_data = {
            "sub": str(user["id"]),
            "userId": str(user["id"]),
            "email": user["email"],
            "exp": datetime.now(timezone.utc) + timedelta(days=7)
        }
        
        token = jwt.encode(token_data, settings.jwt_secret, algorithm="HS256")
        
        logger.info(f"✅ Token JWT generado para: {user['email']}")
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": user["id"],
                "email": user["email"],
                "name": user.get("name", "")
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error completando login: {str(e)}")
        raise HTTPException(status_code=500, detail="Error interno del servidor")

@router.get("/list/{user_id}")
async def list_passkeys(user_id: str):
    """Listar passkeys de un usuario"""
    try:
        logger.info(f"📋 Listando passkeys para usuario: {user_id}")
        
        result = supabase_client.table("passkeys").select("*").eq("user_id", user_id).execute()
        
        if not result:
            return {"passkeys": []}
        
        logger.info(f"✅ {len(result)} passkeys encontradas")
        
        return {
            "passkeys": [
                {
                    "id": pk["id"],
                    "credential_id": pk["credential_id"],
                    "device_name": pk.get("device_name", "Dispositivo"),
                    "created_at": pk["created_at"],
                    "last_used_at": pk.get("last_used_at")
                }
                for pk in result
            ]
        }
        
    except Exception as e:
        logger.error(f"❌ Error listando passkeys: {str(e)}")
        raise HTTPException(status_code=500, detail="Error interno del servidor")

@router.delete("/{credential_id}")
async def delete_passkey(credential_id: str, user_id: str):
    """Eliminar una passkey"""
    try:
        logger.info(f"🗑️ Eliminando passkey {credential_id} para usuario {user_id}")
        
        supabase_client.table("passkeys").delete().eq("id", credential_id).eq("user_id", user_id).execute()
        
        logger.info("✅ Passkey eliminada")
        return {"message": "Passkey eliminada exitosamente"}
        
    except Exception as e:
        logger.error(f"❌ Error eliminando passkey: {str(e)}")
        raise HTTPException(status_code=500, detail="Error interno del servidor")
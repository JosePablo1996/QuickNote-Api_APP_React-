# app/routes/passkeys.py
import json
import base64
import logging
import secrets
import jwt
import httpx
from datetime import datetime, timedelta, timezone
from typing import Dict, Any
from urllib.parse import quote, unquote

from fastapi import APIRouter, HTTPException

from app.models.passkey import (
    WebAuthnRegistrationStart,
    WebAuthnRegistrationComplete,
    WebAuthnLoginStart,
    WebAuthnLoginComplete,
)
from app.services.passkey_service import passkey_service
from app.config import settings

logger = logging.getLogger(__name__)

challenges_store = {}

router = APIRouter(prefix="/passkeys", tags=["passkeys"])

def base64url_to_base64(base64url: str) -> str:
    """Convierte base64url a base64 estándar"""
    base64_str = base64url.replace('-', '+').replace('_', '/')
    padding = 4 - len(base64_str) % 4
    if padding != 4:
        base64_str += '=' * padding
    return base64_str

def base64_to_base64url(base64_str: str) -> str:
    """Convierte base64 estándar a base64url"""
    base64url = base64_str.rstrip('=')
    base64url = base64url.replace('+', '-').replace('/', '_')
    return base64url

def supabase_query(table: str, method: str = "GET", data: Dict = None, params: Dict = None) -> list:
    """Hacer consultas directas a la REST API de Supabase"""
    base_url = f"{settings.supabase_url}/rest/v1/{table}"
    headers = {
        "apikey": settings.supabase_key,
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }
    
    try:
        if method == "GET":
            query_params = {}
            if params:
                for key, value in params.items():
                    query_params[key] = f"eq.{value}"
            response = httpx.get(base_url, headers=headers, params=query_params)
        elif method == "POST":
            response = httpx.post(base_url, headers=headers, json=data)
        elif method == "PATCH":
            query_params = {}
            if params:
                for key, value in params.items():
                    query_params[key] = f"eq.{value}"
            response = httpx.patch(base_url, headers=headers, json=data, params=query_params)
        elif method == "DELETE":
            query_params = {}
            if params:
                for key, value in params.items():
                    query_params[key] = f"eq.{value}"
            response = httpx.delete(base_url, headers=headers, params=query_params)
        else:
            return []
        
        if response.status_code >= 200 and response.status_code < 300:
            return response.json() if response.text else []
        else:
            logger.error(f"Supabase error: {response.status_code} - {response.text}")
            return []
    except Exception as e:
        logger.error(f"Error en supabase_query: {str(e)}")
        return []

@router.post("/register/start")
async def start_register(request: WebAuthnRegistrationStart):
    """Iniciar registro de passkey"""
    try:
        email = request.email
        logger.info(f"Iniciando registro de passkey para: {email}")
        
        users = supabase_query("profiles", "GET", params={"email": email})
        
        if not users:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        user = users[0]
        user_id = user["id"]
        
        registration_options = passkey_service.generate_registration_challenge(
            email=email,
            user_id=user_id
        )
        
        challenge_id = secrets.token_hex(32)
        challenges_store[challenge_id] = {
            "challenge": registration_options["challenge"],
            "email": email,
            "user_id": user_id,
            "type": "registration"
        }
        
        return {
            "challenge_id": challenge_id,
            "options": registration_options
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error iniciando registro: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

@router.post("/register/complete")
async def complete_register(request: WebAuthnRegistrationComplete):
    """
    Completar registro de passkey.
    ✅ OPCIÓN 3: Reemplaza automáticamente cualquier passkey anterior del usuario.
    """
    try:
        challenge_id = request.credential.get("challenge_id")
        if not challenge_id or challenge_id not in challenges_store:
            raise HTTPException(status_code=400, detail="Challenge no valido o expirado")
        
        challenge_data = challenges_store.pop(challenge_id)
        
        success, credential_data = passkey_service.verify_registration(
            credential=request.credential,
            challenge=challenge_data["challenge"]
        )
        
        if not success:
            raise HTTPException(status_code=400, detail="Fallo en la verificacion")
        
        user_id = challenge_data["user_id"]
        device_name = request.device_name or "Mi dispositivo"
        
        # ✅ OPCIÓN 3: Eliminar TODAS las passkeys anteriores de este usuario
        existing_passkeys = supabase_query("passkeys", "GET", params={"user_id": user_id})
        if existing_passkeys:
            logger.info(f"🗑️ Eliminando {len(existing_passkeys)} passkey(s) anterior(es) del usuario {user_id}")
            for pk in existing_passkeys:
                delete_result = supabase_query("passkeys", "DELETE", params={
                    "id": pk["id"],
                    "user_id": user_id
                })
                logger.info(f"  ✅ Passkey eliminada: {pk.get('device_name', 'Desconocido')} ({pk['credential_id'][:20]}...)")
        
        # Guardar la nueva passkey en formato base64url
        credential_id_base64url = credential_data["credential_id"]
        public_key_base64url = credential_data["public_key"]
        
        logger.info(f"📝 Registrando nueva passkey: {credential_id_base64url[:30]}...")
        logger.info(f"📱 Dispositivo: {device_name}")
        logger.info(f"🔑 Public key length: {len(public_key_base64url)} chars")
        
        passkey_data = {
            "user_id": user_id,
            "credential_id": credential_id_base64url,
            "public_key": public_key_base64url,
            "counter": credential_data["sign_count"],
            "device_name": device_name,
            "transports": credential_data.get("transports", ["internal", "hybrid"]),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_used": datetime.now(timezone.utc).isoformat(),
            "last_used_at": datetime.now(timezone.utc).isoformat()
        }
        
        result = supabase_query("passkeys", "POST", data=passkey_data)
        
        if not result:
            raise HTTPException(status_code=500, detail="Error guardando credencial")
        
        logger.info(f"✅ Passkey registrada exitosamente (anterior eliminada)")
        
        return {
            "message": "Passkey registrada exitosamente",
            "credential_id": credential_id_base64url
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error completando registro: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

@router.post("/login/start")
async def start_login(request: WebAuthnLoginStart):
    """Iniciar login con passkey"""
    try:
        email = request.email
        logger.info(f"Iniciando login con passkey para: {email or 'autodescubrimiento'}")
        
        if email:
            users = supabase_query("profiles", "GET", params={"email": email})
            if users:
                user_id = users[0]["id"]
                user_passkeys = supabase_query("passkeys", "GET", params={"user_id": user_id})
                
                if user_passkeys:
                    existing_creds = [
                        {"id": pk["credential_id"], "type": "public-key"}
                        for pk in user_passkeys
                    ]
                    authentication_options = passkey_service.generate_login_challenge(
                        existing_credentials=existing_creds
                    )
                else:
                    authentication_options = passkey_service.generate_login_challenge()
            else:
                authentication_options = passkey_service.generate_login_challenge()
        else:
            authentication_options = passkey_service.generate_login_challenge()
        
        challenge_id = secrets.token_hex(32)
        challenges_store[challenge_id] = {
            "challenge": authentication_options["challenge"],
            "email": email or "",
            "type": "login"
        }
        
        logger.info(f"Challenge de login generado: {challenge_id[:16]}...")
        
        return {
            "challenge_id": challenge_id,
            "options": authentication_options,
            "rpId": passkey_service.rp_id
        }
        
    except Exception as e:
        logger.error(f"Error iniciando login: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

@router.post("/login/complete")
async def complete_login(request: WebAuthnLoginComplete):
    """Completar login con passkey"""
    try:
        logger.info("Completando login con passkey")
        
        challenge_id = request.credential.get("challenge_id")
        if not challenge_id or challenge_id not in challenges_store:
            raise HTTPException(status_code=400, detail="Challenge no valido o expirado")
        
        challenge_data = challenges_store.pop(challenge_id)
        
        # Convertir credential_id de base64url a base64 estándar para buscar en BD
        credential_id_base64url = request.credential.get("id")
        credential_id_base64 = base64url_to_base64(credential_id_base64url)
        
        logger.info(f"Credential ID recibido (base64url): {credential_id_base64url[:30]}...")
        logger.info(f"Credential ID convertido (base64): {credential_id_base64[:30]}...")
        
        # Buscar con el credential_id convertido
        passkeys = supabase_query("passkeys", "GET", params={"credential_id": credential_id_base64})
        
        if not passkeys:
            # Intentar con el base64url original
            logger.warning(f"No encontrada con base64, intentando con base64url...")
            passkeys = supabase_query("passkeys", "GET", params={"credential_id": credential_id_base64url})
        
        if not passkeys:
            logger.error(f"Passkey no encontrada")
            raise HTTPException(
                status_code=404, 
                detail="Passkey no encontrada. Asegúrate de haber registrado tu dispositivo en Configuración > Seguridad."
            )
        
        stored_credential = passkeys[0]
        logger.info(f"✅ Passkey encontrada para usuario: {stored_credential.get('user_id')}")
        
        # Verificar la autenticación
        success, new_sign_count = passkey_service.verify_login(
            credential=request.credential,
            challenge=challenge_data["challenge"],
            stored_credential={
                "public_key": stored_credential.get("public_key", ""),
                "sign_count": stored_credential.get("counter", 0)
            }
        )
        
        if not success:
            raise HTTPException(status_code=400, detail="Fallo en la verificación biométrica")
        
        # Actualizar contador y última fecha de uso
        supabase_query("passkeys", "PATCH", data={
            "counter": new_sign_count,
            "last_used": datetime.now(timezone.utc).isoformat(),
            "last_used_at": datetime.now(timezone.utc).isoformat()
        }, params={"id": stored_credential["id"]})
        
        # Buscar usuario
        users = supabase_query("profiles", "GET", params={"id": stored_credential["user_id"]})
        
        if not users:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        user = users[0]
        logger.info(f"🎉 Login exitoso para: {user['email']}")
        
        # Generar token JWT HS256
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
        logger.error(f"Error completando login: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

@router.get("/list/{user_id}")
async def list_passkeys(user_id: str):
    """Listar passkeys de un usuario"""
    try:
        passkeys = supabase_query("passkeys", "GET", params={"user_id": user_id})
        
        return {
            "passkeys": [
                {
                    "id": pk["id"],
                    "credential_id": pk["credential_id"],
                    "device_name": pk.get("device_name", "Dispositivo"),
                    "created_at": pk["created_at"],
                    "last_used": pk.get("last_used"),
                    "last_used_at": pk.get("last_used_at")
                }
                for pk in passkeys
            ]
        }
        
    except Exception as e:
        logger.error(f"Error listando passkeys: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

@router.delete("/{credential_id}")
async def delete_passkey(credential_id: str, user_id: str):
    """Eliminar una passkey"""
    try:
        logger.info(f"Eliminando passkey {credential_id[:30]}... para usuario {user_id}")
        
        supabase_query("passkeys", "DELETE", params={
            "credential_id": credential_id,
            "user_id": user_id
        })
        
        return {"message": "Passkey eliminada exitosamente"}
        
    except Exception as e:
        logger.error(f"Error eliminando passkey: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")
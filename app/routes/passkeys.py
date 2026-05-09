# app/routes/passkeys.py
from fastapi import APIRouter, HTTPException, Depends, Request
from typing import Dict, Any
import secrets
import logging
import jwt
import httpx
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

# Configurar logger
logger = logging.getLogger(__name__)

# En produccion, usar Redis o una base de datos temporal
challenges_store = {}

router = APIRouter(prefix="/passkeys", tags=["passkeys"])

# Helper para hacer consultas directas a Supabase REST API
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
        
        # Buscar usuario en tabla profiles
        users = supabase_query("profiles", "GET", params={"email": email})
        
        if not users:
            logger.warning(f"Usuario no encontrado en profiles: {email}")
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        user = users[0]
        user_id = user["id"]
        logger.info(f"Usuario encontrado en profiles: {user_id}")
        
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
        
        logger.info(f"Challenge generado: {challenge_id[:16]}...")
        
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
    """Completar registro de passkey"""
    try:
        logger.info("Completando registro de passkey")
        
        challenge_id = request.credential.get("challenge_id")
        if not challenge_id or challenge_id not in challenges_store:
            raise HTTPException(status_code=400, detail="Challenge no valido")
        
        challenge_data = challenges_store.pop(challenge_id)
        
        success, credential_data = passkey_service.verify_registration(
            credential=request.credential,
            challenge=challenge_data["challenge"]
        )
        
        if not success:
            raise HTTPException(status_code=400, detail="Fallo en la verificacion")
        
        # Guardar passkey con los nombres de columna correctos
        passkey_data = {
            "user_id": challenge_data["user_id"],
            "credential_id": credential_data["credential_id"],
            "public_key": credential_data["public_key"],
            "counter": credential_data["sign_count"],  # counter en BD = sign_count del servicio
            "device_name": request.device_name or "Mi dispositivo",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_used": datetime.now(timezone.utc).isoformat(),
            "last_used_at": datetime.now(timezone.utc).isoformat()
        }
        
        result = supabase_query("passkeys", "POST", data=passkey_data)
        
        if not result:
            raise HTTPException(status_code=500, detail="Error guardando credencial")
        
        logger.info(f"Passkey registrada: {credential_data['credential_id'][:20]}...")
        
        return {
            "message": "Passkey registrada exitosamente",
            "credential_id": credential_data["credential_id"]
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
        logger.info(f"Iniciando login con passkey para: {email}")
        
        authentication_options = passkey_service.generate_login_challenge()
        
        challenge_id = secrets.token_hex(32)
        challenges_store[challenge_id] = {
            "challenge": authentication_options["challenge"],
            "email": email,
            "type": "login"
        }
        
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
            raise HTTPException(status_code=400, detail="Challenge no valido")
        
        challenge_data = challenges_store.pop(challenge_id)
        
        # Buscar passkey en tabla passkeys
        credential_id = request.credential.get("id")
        passkeys = supabase_query("passkeys", "GET", params={"credential_id": credential_id})
        
        if not passkeys:
            raise HTTPException(status_code=404, detail="Passkey no encontrada")
        
        stored_credential = passkeys[0]
        
        success, new_sign_count = passkey_service.verify_login(
            credential=request.credential,
            challenge=challenge_data["challenge"],
            stored_credential=stored_credential
        )
        
        if not success:
            raise HTTPException(status_code=400, detail="Fallo en la verificacion")
        
        # Actualizar contador (usar columna 'counter')
        supabase_query("passkeys", "PATCH", data={
            "counter": new_sign_count,
            "last_used": datetime.now(timezone.utc).isoformat()
        }, params={"id": stored_credential["id"]})
        
        # Buscar usuario en tabla profiles
        users = supabase_query("profiles", "GET", params={"id": stored_credential["user_id"]})
        
        if not users:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        user = users[0]
        
        # Generar token JWT
        token_data = {
            "sub": str(user["id"]),
            "userId": str(user["id"]),
            "email": user["email"],
            "exp": datetime.now(timezone.utc) + timedelta(days=7)
        }
        
        token = jwt.encode(token_data, settings.jwt_secret, algorithm="HS256")
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": user["id"],
                "email": user["email"],
                "name": user.get("full_name", "")
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
        logger.info(f"Listando passkeys para usuario: {user_id}")
        
        # Buscar passkeys en tabla passkeys
        passkeys = supabase_query("passkeys", "GET", params={"user_id": user_id})
        
        return {
            "passkeys": [
                {
                    "id": pk["id"],
                    "credential_id": pk["credential_id"],
                    "device_name": pk.get("device_name", "Dispositivo"),
                    "created_at": pk["created_at"],
                    "last_used": pk.get("last_used")
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
        logger.info(f"Eliminando passkey {credential_id}")
        
        # Eliminar de tabla passkeys
        supabase_query("passkeys", "DELETE", params={
            "id": credential_id,
            "user_id": user_id
        })
        
        return {"message": "Passkey eliminada exitosamente"}
        
    except Exception as e:
        logger.error(f"Error eliminando passkey: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")
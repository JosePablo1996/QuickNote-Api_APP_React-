# app/services/two_factor_service.py
import pyotp
import qrcode
import base64
from io import BytesIO
from typing import Optional, Tuple, List, Dict
import secrets
import hashlib
from datetime import datetime, timezone
import logging
import httpx
from app.config import settings

logger = logging.getLogger(__name__)

class TwoFactorService:
    """Servicio para manejar autenticación de dos factores (TOTP) usando REST API de Supabase"""
    
    def __init__(self):
        self.issuer_name = "QuickNote"
        self.supabase_url = settings.supabase_url
        self.supabase_service_key = settings.supabase_service_role_key
        
        logger.info(f"🔑 TwoFactorService inicializado")
        logger.info(f"   URL: {self.supabase_url}")
        logger.info(f"   Service Key: {'✅' if self.supabase_service_key else '❌'}")
    
    def _supabase_query(
        self, 
        table: str, 
        method: str = "GET", 
        data: Dict = None, 
        params: Dict = None
    ) -> List[Dict]:
        """
        Consultas a Supabase REST API.
        ✅ USA SIEMPRE SERVICE ROLE KEY para bypassear RLS.
        """
        base_url = f"{self.supabase_url}/rest/v1/{table}"
        
        # ✅ SIEMPRE usar service role key
        api_key = self.supabase_service_key
        
        headers = {
            "apikey": api_key,
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Prefer": "return=representation"
        }
        
        try:
            if method == "GET":
                query_params = {}
                if params:
                    for key, value in params.items():
                        if isinstance(value, bool):
                            query_params[key] = f"eq.{str(value).lower()}"
                        else:
                            query_params[key] = f"eq.{value}"
                
                logger.info(f"🔍 GET {table} params: {query_params}")
                response = httpx.get(base_url, headers=headers, params=query_params)
                
            elif method == "POST":
                logger.info(f"📝 POST {table}")
                response = httpx.post(base_url, headers=headers, json=data)
                
            elif method == "PATCH":
                query_params = {}
                if params:
                    for key, value in params.items():
                        if isinstance(value, bool):
                            query_params[key] = f"eq.{str(value).lower()}"
                        else:
                            query_params[key] = f"eq.{value}"
                
                logger.info(f"🔧 PATCH {table} params: {query_params}")
                response = httpx.patch(base_url, headers=headers, json=data, params=query_params)
                
            elif method == "DELETE":
                query_params = {}
                if params:
                    for key, value in params.items():
                        if isinstance(value, bool):
                            query_params[key] = f"eq.{str(value).lower()}"
                        else:
                            query_params[key] = f"eq.{value}"
                
                logger.info(f"🗑️ DELETE {table} params: {query_params}")
                response = httpx.delete(base_url, headers=headers, params=query_params)
                
            else:
                logger.error(f"Método no soportado: {method}")
                return []
            
            status = response.status_code
            result = response.json() if response.text else []
            
            if status >= 200 and status < 300:
                count = len(result) if isinstance(result, list) else 1
                logger.info(f"✅ {method} {table}: {count} resultados (status: {status})")
                return result if isinstance(result, list) else [result]
            else:
                logger.error(f"❌ Error {status}: {response.text[:300]}")
                return []
                
        except Exception as e:
            logger.error(f"❌ Error en _supabase_query: {str(e)}")
            import traceback
            traceback.print_exc()
            return []
    
    def generate_secret(self, user_email: str) -> Tuple[str, str, str]:
        """Genera secreto TOTP, QR y clave manual"""
        secret = pyotp.random_base32()
        
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user_email,
            issuer_name=self.issuer_name
        )
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()
        qr_data_uri = f"data:image/png;base64,{qr_base64}"
        
        logger.info(f"✅ Secreto TOTP generado para {user_email}")
        logger.info(f"   Secret: {secret[:10]}...")
        
        return secret, qr_data_uri, secret
    
    def verify_code(self, secret: str, code: str) -> bool:
        """Verifica código TOTP"""
        try:
            totp = pyotp.TOTP(secret)
            is_valid = totp.verify(code, valid_window=1)
            logger.info(f"🔍 Verificación TOTP: {'✅ Válido' if is_valid else '❌ Inválido'}")
            return is_valid
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            return False
    
    def generate_backup_codes(self, count: int = 8) -> List[str]:
        """Genera códigos de respaldo"""
        codes = []
        for _ in range(count):
            code = secrets.token_hex(4).upper()
            formatted = f"{code[:4]}-{code[4:]}"
            codes.append(formatted)
        logger.info(f"✅ {count} códigos generados")
        return codes
    
    def hash_backup_code(self, code: str) -> str:
        """Hashea código de respaldo"""
        return hashlib.sha256(code.encode()).hexdigest()
    
    def enable_2fa(self, user_id: str, secret: str, backup_codes: List[str]) -> bool:
        """Activa 2FA - Primero elimina, luego inserta"""
        try:
            hashed_codes = [self.hash_backup_code(code) for code in backup_codes]
            now = datetime.now(timezone.utc).isoformat()
            
            # ✅ PASO 1: Eliminar cualquier registro existente
            logger.info(f"🗑️ Eliminando registros anteriores para {user_id}")
            self._supabase_query(
                "two_factor_settings",
                "DELETE",
                params={"user_id": user_id}
            )
            
            # ✅ PASO 2: Insertar nuevo registro
            data = {
                "user_id": user_id,
                "method": "totp",
                "secret": secret,
                "backup_codes": hashed_codes,
                "enabled": True,
                "created_at": now,
                "updated_at": now
            }
            
            logger.info(f"📝 Insertando nuevo registro 2FA")
            result = self._supabase_query(
                "two_factor_settings",
                "POST",
                data=data
            )
            
            if not result or len(result) == 0:
                logger.error(f"❌ No se pudo insertar el registro")
                return False
            
            logger.info(f"✅ Registro insertado: id={result[0].get('id')}")
            
            # ✅ PASO 3: Verificar inmediatamente
            verify = self._supabase_query(
                "two_factor_settings",
                "GET",
                params={"user_id": user_id}
            )
            
            if verify and len(verify) > 0:
                record = verify[0]
                is_enabled = record.get("enabled", False)
                logger.info(f"🔍 Verificación: enabled={is_enabled}, id={record.get('id')}")
                
                if is_enabled == True:
                    logger.info(f"🎉 2FA ACTIVADO CORRECTAMENTE para {user_id}")
                    return True
            
            # Si falla la verificación, reintentar
            logger.warning(f"⚠️ Verificación falló, reintentando...")
            
            # Reintentar GET
            retry = self._supabase_query(
                "two_factor_settings",
                "GET",
                params={"user_id": user_id}
            )
            
            if retry and len(retry) > 0 and retry[0].get("enabled") == True:
                logger.info(f"🎉 2FA ACTIVADO (reintento exitoso)")
                return True
            
            logger.error(f"❌ No se pudo verificar después de varios intentos")
            return False
            
        except Exception as e:
            logger.error(f"❌ Error en enable_2fa: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def disable_2fa(self, user_id: str) -> bool:
        """Desactiva 2FA"""
        try:
            now = datetime.now(timezone.utc).isoformat()
            
            self._supabase_query(
                "two_factor_settings",
                "PATCH",
                data={
                    "enabled": False,
                    "secret": None,
                    "backup_codes": None,
                    "updated_at": now
                },
                params={"user_id": user_id}
            )
            
            logger.info(f"✅ 2FA deshabilitado para {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            return False
    
    def get_user_2fa_secret(self, user_id: str) -> Optional[str]:
        """Obtiene secreto TOTP"""
        try:
            result = self._supabase_query(
                "two_factor_settings",
                "GET",
                params={"user_id": user_id, "enabled": True}
            )
            
            if result and len(result) > 0:
                secret = result[0].get("secret")
                logger.info(f"✅ Secreto encontrado")
                return secret
            
            return None
            
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            return None
    
    def is_2fa_enabled(self, user_id: str) -> bool:
        """Verifica si 2FA está activado"""
        try:
            result = self._supabase_query(
                "two_factor_settings",
                "GET",
                params={"user_id": user_id, "enabled": True}
            )
            
            is_enabled = len(result) > 0 if result else False
            logger.info(f"🔍 2FA status: {'✅ Activado' if is_enabled else '❌ Desactivado'}")
            return is_enabled
            
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            return False
    
    def verify_backup_code(self, user_id: str, code: str) -> bool:
        """Verifica código de respaldo"""
        try:
            hashed_input = self.hash_backup_code(code)
            
            result = self._supabase_query(
                "two_factor_settings",
                "GET",
                params={"user_id": user_id, "enabled": True}
            )
            
            if result and len(result) > 0:
                backup_codes = result[0].get("backup_codes", [])
                
                if hashed_input in backup_codes:
                    backup_codes.remove(hashed_input)
                    
                    self._supabase_query(
                        "two_factor_settings",
                        "PATCH",
                        data={"backup_codes": backup_codes},
                        params={"user_id": user_id}
                    )
                    
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            return False
    
    def get_2fa_status(self, user_id: str) -> Dict:
        """Obtiene estado 2FA"""
        try:
            result = self._supabase_query(
                "two_factor_settings",
                "GET",
                params={"user_id": user_id}
            )
            
            if result and len(result) > 0:
                record = result[0]
                is_enabled = record.get("enabled", False)
                
                if is_enabled == True:
                    return {
                        "enabled": True,
                        "method": record.get("method", "totp"),
                        "created_at": record.get("created_at")
                    }
            
            return {"enabled": False, "method": None, "created_at": None}
            
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            return {"enabled": False, "method": None, "created_at": None}
# app/services/two_factor_service.py
import os
import pyotp
import qrcode
import io
import base64
import hashlib
import secrets
import logging
from typing import List, Dict, Optional
from datetime import datetime, timezone
from app.services.supabase_client import supabase_query

logger = logging.getLogger(__name__)

class TwoFactorService:
    def __init__(self):
        pass  # No necesitamos supabase_client, usamos supabase_query directamente

    def generate_secret(self, email: str) -> tuple:
        """Genera un secreto TOTP y un QR code"""
        try:
            # Generar secreto
            secret = pyotp.random_base32()
            logger.info(f"🔐 Secreto generado: {secret[:10]}...")
            
            # Crear URI para Google Authenticator
            issuer_name = "QuickNote"
            totp = pyotp.TOTP(secret)
            provisioning_uri = totp.provisioning_uri(name=email, issuer_name=issuer_name)
            
            # Generar QR code
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convertir a base64
            buffered = io.BytesIO()
            img.save(buffered, format="PNG")
            img_str = base64.b64encode(buffered.getvalue()).decode()
            qr_code = f"data:image/png;base64,{img_str}"
            
            # Generar clave manual formateada
            manual_key = f"{secret[0:4]} {secret[4:8]} {secret[8:12]} {secret[12:16]} {secret[16:20]} {secret[20:24]} {secret[24:28]} {secret[28:32]}"
            
            return secret, qr_code, manual_key
            
        except Exception as e:
            logger.error(f"❌ Error generando secreto: {e}")
            raise

    def verify_code(self, secret: str, code: str) -> bool:
        """Verifica un código TOTP"""
        try:
            totp = pyotp.TOTP(secret)
            is_valid = totp.verify(code)
            logger.info(f"🔐 Verificando código TOTP: {'✅ Válido' if is_valid else '❌ Inválido'}")
            return is_valid
        except Exception as e:
            logger.error(f"❌ Error verificando código: {e}")
            return False

    def generate_backup_codes(self, num_codes: int = 8) -> List[str]:
        """Genera códigos de respaldo únicos"""
        backup_codes = []
        for _ in range(num_codes):
            # Generar código aleatorio de 10 caracteres alfanuméricos
            code = secrets.token_hex(5).upper()  # 10 caracteres hex
            # Agregar guión en medio para legibilidad
            formatted_code = f"{code[:5]}-{code[5:]}"
            # Hashear el código para almacenar
            hashed_code = hashlib.sha256(formatted_code.encode()).hexdigest()
            backup_codes.append(hashed_code)
        return backup_codes

    def get_user_2fa_secret(self, user_id: str) -> Optional[str]:
        """Obtiene el secreto TOTP del usuario (solo si está habilitado)"""
        try:
            logger.info(f"🔍 Buscando secreto 2FA para usuario: {user_id}")
            
            # CORRECCIÓN: Usar supabase_query directamente
            result = supabase_query(
                "two_factor_settings",
                "GET",
                params={"user_id": user_id, "enabled": "eq.true"},
                select="secret, enabled"
            )
            
            logger.info(f"📊 Resultado query: {len(result) if result else 0} registros")
            
            if result and len(result) > 0:
                settings = result[0]
                secret = settings.get('secret')
                logger.info(f"✅ Secreto encontrado: {secret[:10] if secret else 'None'}...")
                return secret
            
            # Intentar sin filtrar por enabled (debug)
            logger.info(f"🔍 Intentando sin filtrar por enabled...")
            result_all = supabase_query(
                "two_factor_settings",
                "GET",
                params={"user_id": user_id},
                select="secret, enabled"
            )
            
            if result_all and len(result_all) > 0:
                logger.info(f"📊 Registro encontrado pero enabled={result_all[0].get('enabled')}")
                if result_all[0].get('enabled') == True:
                    return result_all[0].get('secret')
                else:
                    logger.warning(f"⚠️ 2FA encontrado pero deshabilitado")
            else:
                logger.warning(f"⚠️ No se encontró configuración 2FA para usuario {user_id}")
            
            return None
            
        except Exception as e:
            logger.error(f"❌ Error obteniendo secreto 2FA: {e}")
            import traceback
            traceback.print_exc()
            return None

    def is_2fa_enabled(self, user_id: str) -> bool:
        """Verifica si el usuario tiene 2FA activado"""
        try:
            result = supabase_query(
                "two_factor_settings",
                "GET",
                params={"user_id": user_id, "enabled": "eq.true"},
                select="enabled"
            )
            
            is_enabled = result and len(result) > 0 and result[0].get('enabled', False)
            logger.info(f"🔍 2FA enabled for {user_id}: {is_enabled}")
            return is_enabled
            
        except Exception as e:
            logger.error(f"❌ Error checking 2FA status: {e}")
            return False

    def enable_2fa(self, user_id: str, secret: str, backup_codes: List[str]) -> bool:
        """Activa 2FA para el usuario"""
        try:
            logger.info(f"🔐 Activando 2FA para usuario: {user_id}")
            
            # Verificar si ya existe configuración
            existing = supabase_query(
                "two_factor_settings",
                "GET",
                params={"user_id": user_id}
            )
            
            now = datetime.now(timezone.utc).isoformat()
            
            if existing and len(existing) > 0:
                # Actualizar existente
                result = supabase_query(
                    "two_factor_settings",
                    "PATCH",
                    params={"user_id": user_id},
                    data={
                        "secret": secret,
                        "backup_codes": backup_codes,
                        "enabled": True,
                        "method": "totp",
                        "updated_at": now
                    }
                )
                logger.info(f"✅ Configuración 2FA actualizada")
            else:
                # Crear nueva
                result = supabase_query(
                    "two_factor_settings",
                    "POST",
                    data={
                        "user_id": user_id,
                        "secret": secret,
                        "backup_codes": backup_codes,
                        "enabled": True,
                        "method": "totp",
                        "created_at": now,
                        "updated_at": now
                    }
                )
                logger.info(f"✅ Nueva configuración 2FA creada")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Error enabling 2FA: {e}")
            return False

    def disable_2fa(self, user_id: str) -> bool:
        """Desactiva 2FA para el usuario"""
        try:
            logger.info(f"🔐 Desactivando 2FA para usuario: {user_id}")
            
            result = supabase_query(
                "two_factor_settings",
                "PATCH",
                params={"user_id": user_id},
                data={"enabled": False, "updated_at": datetime.now(timezone.utc).isoformat()}
            )
            
            logger.info(f"✅ 2FA desactivado")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error disabling 2FA: {e}")
            return False

    def verify_backup_code(self, user_id: str, code: str) -> bool:
        """Verifica un código de respaldo"""
        try:
            logger.info(f"🔐 Verificando código de respaldo para usuario: {user_id}")
            
            # Obtener usuario con sus códigos de respaldo
            result = supabase_query(
                "two_factor_settings",
                "GET",
                params={"user_id": user_id, "enabled": "eq.true"},
                select="backup_codes"
            )
            
            if not result or len(result) == 0:
                logger.warning(f"⚠️ No se encontró configuración 2FA para usuario {user_id}")
                return False
            
            backup_codes = result[0].get('backup_codes', [])
            
            if not backup_codes:
                logger.warning(f"⚠️ No hay códigos de respaldo para usuario {user_id}")
                return False
            
            # Hashear el código ingresado para comparar
            hashed_code = hashlib.sha256(code.encode()).hexdigest()
            
            # Buscar el código en la lista
            if hashed_code in backup_codes:
                logger.info(f"✅ Código de respaldo válido encontrado")
                # Eliminar el código usado (opcional)
                backup_codes.remove(hashed_code)
                supabase_query(
                    "two_factor_settings",
                    "PATCH",
                    params={"user_id": user_id},
                    data={"backup_codes": backup_codes}
                )
                return True
            
            logger.warning(f"⚠️ Código de respaldo inválido")
            return False
            
        except Exception as e:
            logger.error(f"❌ Error verificando backup code: {e}")
            return False

    def get_2fa_status(self, user_id: str) -> Dict:
        """Obtiene el estado completo de 2FA del usuario"""
        try:
            logger.info(f"🔍 Obteniendo estado 2FA para: {user_id}")
            
            result = supabase_query(
                "two_factor_settings",
                "GET",
                params={"user_id": user_id},
                select="enabled, method, created_at, updated_at"
            )
            
            if result and len(result) > 0:
                settings = result[0]
                is_enabled = settings.get('enabled', False)
                
                return {
                    "enabled": is_enabled,
                    "method": settings.get('method') if is_enabled else None,
                    "created_at": settings.get('created_at') if is_enabled else None,
                    "updated_at": settings.get('updated_at') if is_enabled else None
                }
            
            return {"enabled": False, "method": None}
            
        except Exception as e:
            logger.error(f"❌ Error getting 2FA status: {e}")
            return {"enabled": False, "method": None, "error": str(e)}
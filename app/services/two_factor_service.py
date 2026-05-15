# app/services/two_factor_service.py
import os
import pyotp
import qrcode
import io
import base64
import secrets
import logging
from typing import List, Dict, Optional
from datetime import datetime, timezone
from supabase import create_client
from app.config import settings

logger = logging.getLogger(__name__)

# ✅ Crear cliente directamente
supabase = create_client(settings.supabase_url, settings.supabase_service_role_key)

class TwoFactorService:
    def __init__(self):
        pass

    def generate_secret(self, email: str) -> tuple:
        """Genera un secreto TOTP y un QR code"""
        try:
            secret = pyotp.random_base32()
            logger.info(f"🔐 Secreto generado: {secret[:10]}...")
            
            issuer_name = "QuickNote"
            totp = pyotp.TOTP(secret)
            provisioning_uri = totp.provisioning_uri(name=email, issuer_name=issuer_name)
            
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            buffered = io.BytesIO()
            img.save(buffered, format="PNG")
            img_str = base64.b64encode(buffered.getvalue()).decode()
            qr_code = f"data:image/png;base64,{img_str}"
            
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
        """Genera códigos de respaldo únicos como strings planos"""
        try:
            backup_codes = []
            for _ in range(num_codes):
                code = secrets.token_hex(5).upper()
                formatted_code = f"{code[:5]}-{code[5:]}"
                backup_codes.append(formatted_code)
            
            logger.info(f"📝 Generados {len(backup_codes)} códigos de respaldo")
            return backup_codes
        except Exception as e:
            logger.error(f"❌ Error generando backup codes: {e}")
            return [f"{secrets.token_hex(3).upper()}-{secrets.token_hex(2).upper()}" for _ in range(num_codes)]

    def get_user_2fa_secret(self, user_id: str) -> Optional[str]:
        """Obtiene el secreto TOTP del usuario"""
        try:
            logger.info(f"🔍 Buscando secreto 2FA para usuario: {user_id}")
            
            result = supabase.table('two_factor_settings')\
                .select('secret, enabled')\
                .eq('user_id', user_id)\
                .eq('enabled', True)\
                .execute()
            
            if result.data and len(result.data) > 0:
                secret = result.data[0].get('secret')
                if secret:
                    logger.info(f"✅ Secreto encontrado: {secret[:10]}...")
                    return secret
            
            logger.warning(f"⚠️ No se encontró secreto 2FA para usuario {user_id}")
            return None
            
        except Exception as e:
            logger.error(f"❌ Error obteniendo secreto 2FA: {e}")
            return None

    def is_2fa_enabled(self, user_id: str) -> bool:
        """Verifica si el usuario tiene 2FA activado"""
        try:
            result = supabase.table('two_factor_settings')\
                .select('enabled')\
                .eq('user_id', user_id)\
                .eq('enabled', True)\
                .execute()
            
            return result.data and len(result.data) > 0
        except Exception as e:
            logger.error(f"❌ Error checking 2FA status: {e}")
            return False

    def enable_2fa(self, user_id: str, secret: str, backup_codes: List[str]) -> bool:
        """Activa 2FA para el usuario"""
        try:
            logger.info("=" * 50)
            logger.info(f"🔐 Activando 2FA para usuario: {user_id}")
            logger.info(f"   Secret: {secret[:10]}...")
            logger.info(f"   Backup codes count: {len(backup_codes)}")
            
            now = datetime.now(timezone.utc).isoformat()
            
            # Verificar si ya existe
            existing = supabase.table('two_factor_settings')\
                .select('id')\
                .eq('user_id', user_id)\
                .execute()
            
            if existing.data and len(existing.data) > 0:
                # Actualizar
                result = supabase.table('two_factor_settings')\
                    .update({
                        "secret": secret,
                        "backup_codes": backup_codes,
                        "enabled": True,
                        "method": "totp",
                        "updated_at": now
                    })\
                    .eq('user_id', user_id)\
                    .execute()
                logger.info(f"✅ Configuración 2FA actualizada")
            else:
                # Crear nueva
                result = supabase.table('two_factor_settings')\
                    .insert({
                        "user_id": user_id,
                        "secret": secret,
                        "backup_codes": backup_codes,
                        "enabled": True,
                        "method": "totp",
                        "created_at": now,
                        "updated_at": now
                    })\
                    .execute()
                logger.info(f"✅ Nueva configuración 2FA creada")
            
            logger.info(f"✅ 2FA activado exitosamente para usuario {user_id}")
            logger.info("=" * 50)
            return True
            
        except Exception as e:
            logger.error(f"❌ Error enabling 2FA: {e}")
            import traceback
            traceback.print_exc()
            return False

    def disable_2fa(self, user_id: str) -> bool:
        """Desactiva 2FA para el usuario"""
        try:
            now = datetime.now(timezone.utc).isoformat()
            
            supabase.table('two_factor_settings')\
                .update({"enabled": False, "updated_at": now})\
                .eq('user_id', user_id)\
                .execute()
            
            logger.info(f"✅ 2FA desactivado para usuario {user_id}")
            return True
        except Exception as e:
            logger.error(f"❌ Error disabling 2FA: {e}")
            return False

    def verify_backup_code(self, user_id: str, code: str) -> bool:
        """Verifica un código de respaldo"""
        try:
            result = supabase.table('two_factor_settings')\
                .select('backup_codes')\
                .eq('user_id', user_id)\
                .eq('enabled', True)\
                .execute()
            
            if not result.data or len(result.data) == 0:
                return False
            
            backup_codes = result.data[0].get('backup_codes', [])
            
            if code in backup_codes:
                backup_codes.remove(code)
                supabase.table('two_factor_settings')\
                    .update({"backup_codes": backup_codes})\
                    .eq('user_id', user_id)\
                    .execute()
                return True
            
            return False
        except Exception as e:
            logger.error(f"❌ Error verifying backup code: {e}")
            return False

    def get_2fa_status(self, user_id: str) -> Dict:
        """Obtiene el estado completo de 2FA del usuario"""
        try:
            result = supabase.table('two_factor_settings')\
                .select('enabled, method, created_at, updated_at')\
                .eq('user_id', user_id)\
                .execute()
            
            if result.data and len(result.data) > 0:
                settings = result.data[0]
                return {
                    "enabled": settings.get('enabled', False),
                    "method": settings.get('method'),
                    "created_at": settings.get('created_at'),
                    "updated_at": settings.get('updated_at')
                }
            
            return {"enabled": False, "method": None}
        except Exception as e:
            logger.error(f"❌ Error getting 2FA status: {e}")
            return {"enabled": False, "method": None}
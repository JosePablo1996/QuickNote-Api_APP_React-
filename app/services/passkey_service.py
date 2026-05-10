# app/services/passkey_service.py
import json
import base64
import binascii
from typing import Dict, Any, Optional, Tuple
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
import logging

logger = logging.getLogger(__name__)

class PasskeyService:
    def __init__(self):
        self.rp_id = "localhost"
        self.rp_name = "QuickNote"
        self.origin = "http://localhost:5173"
    
    def generate_registration_challenge(self, email: str, user_id: str) -> Dict[str, Any]:
        """Genera opciones para registrar una nueva passkey"""
        
        user_id_bytes = user_id.encode('utf-8')[:64]
        
        try:
            registration_options = generate_registration_options(
                rp_id=self.rp_id,
                rp_name=self.rp_name,
                user_id=user_id_bytes,
                user_name=email,
                user_display_name=email.split('@')[0],
                authenticator_selection=AuthenticatorSelectionCriteria(
                    authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                    user_verification=UserVerificationRequirement.PREFERRED,
                    resident_key=ResidentKeyRequirement.PREFERRED
                ),
                timeout=60000,
            )
            
            options_dict = json.loads(options_to_json(registration_options))
            logger.info("Opciones de registro generadas correctamente")
            return options_dict
            
        except Exception as e:
            logger.error(f"Error generando opciones de registro: {str(e)}")
            logger.exception("Stacktrace completo:")
            raise
    
    def verify_registration(
        self, 
        credential: Dict[str, Any],
        challenge: str
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Verifica el registro de una passkey"""
        
        try:
            expected_challenge_bytes = base64url_to_bytes(challenge)
            
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=expected_challenge_bytes,
                expected_rp_id=self.rp_id,
                expected_origin=self.origin,
                require_user_verification=True,
            )
            
            # ✅ CORREGIDO: credential_public_key ya está en formato COSE/CBOR bytes
            # NO codificarlo de nuevo, guardarlo TAL CUAL como base64url
            public_key_bytes = verification.credential_public_key
            
            logger.info(f"📊 Public key raw bytes length: {len(public_key_bytes)}")
            logger.info(f"📊 Public key hex (first 50): {public_key_bytes[:50].hex()}")
            
            # Guardar como base64url (sin padding) para mantener compatibilidad
            public_key_base64url = base64.urlsafe_b64encode(public_key_bytes).decode('utf-8').rstrip('=')
            
            # Guardar credential_id como base64url también
            credential_id_base64url = base64.urlsafe_b64encode(verification.credential_id).decode('utf-8').rstrip('=')
            
            credential_data = {
                "credential_id": credential_id_base64url,
                "public_key": public_key_base64url,
                "sign_count": verification.sign_count,
            }
            
            logger.info("✅ Registro verificado correctamente")
            logger.info(f"📊 Public key base64url length: {len(public_key_base64url)} chars")
            logger.info(f"📊 Credential ID: {credential_id_base64url[:30]}...")
            
            return True, credential_data
            
        except Exception as e:
            logger.error(f"❌ Error verificando registro: {str(e)}")
            logger.exception("Stacktrace completo:")
            return False, None
    
    def generate_login_challenge(self, existing_credentials: list = []) -> Dict[str, Any]:
        """Genera opciones para login con passkey"""
        
        try:
            authentication_options = generate_authentication_options(
                rp_id=self.rp_id,
                timeout=60000,
                user_verification=UserVerificationRequirement.PREFERRED,
            )
            
            logger.info("Challenge de login generado")
            return json.loads(options_to_json(authentication_options))
            
        except Exception as e:
            logger.error(f"Error generando challenge de login: {str(e)}")
            raise
    
    def verify_login(
        self,
        credential: Dict[str, Any],
        challenge: str,
        stored_credential: Dict[str, Any]
    ) -> Tuple[bool, Optional[int]]:
        """Verifica el login con passkey"""
        
        try:
            expected_challenge_bytes = base64url_to_bytes(challenge)
            
            # ✅ CORREGIDO: La clave pública está guardada en base64url
            public_key_str = stored_credential.get("public_key", "")
            
            if not public_key_str:
                logger.error("❌ Public key vacía en stored_credential")
                return False, None
            
            logger.info(f"📊 Stored public key (first 50 chars): {public_key_str[:50]}...")
            logger.info(f"📊 Stored public key length: {len(public_key_str)} chars")
            
            # Decodificar de base64url a bytes
            try:
                # Agregar padding si es necesario
                padding = 4 - len(public_key_str) % 4
                if padding != 4:
                    public_key_str_padded = public_key_str + ('=' * padding)
                else:
                    public_key_str_padded = public_key_str
                
                credential_public_key = base64.urlsafe_b64decode(public_key_str_padded)
                logger.info(f"✅ Public key decodificada: {len(credential_public_key)} bytes")
                logger.info(f"📊 Public key hex (first 50): {credential_public_key[:50].hex()}")
                
            except Exception as e:
                logger.error(f"❌ Error decodificando public key: {str(e)}")
                return False, None
            
            # Obtener el contador actual
            sign_count = stored_credential.get("sign_count", 0)
            logger.info(f"📊 Sign count actual: {sign_count}")
            
            # Verificar la autenticación
            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=expected_challenge_bytes,
                expected_rp_id=self.rp_id,
                expected_origin=self.origin,
                credential_public_key=credential_public_key,
                credential_current_sign_count=sign_count,
                require_user_verification=True,
            )
            
            logger.info(f"✅ Login verificado, nuevo contador: {verification.new_sign_count}")
            return True, verification.new_sign_count
            
        except Exception as e:
            logger.error(f"❌ Error verificando login: {str(e)}")
            logger.exception("Stacktrace completo:")
            return False, None


# Instancia global
passkey_service = PasskeyService()
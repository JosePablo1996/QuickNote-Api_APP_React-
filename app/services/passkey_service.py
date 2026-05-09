# app/services/passkey_service.py
import json
import base64
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
    RegistrationCredential,
    AuthenticationCredential,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
)
import logging

logger = logging.getLogger(__name__)

class PasskeyService:
    def __init__(self):
        self.rp_id = "quicknote-api-app-react.onrender.com"  # Cambiar en producción
        self.rp_name = "QuickNote"
        self.origin = "https://quicknote-web-app.vercel.app"  # Cambiar según tu frontend
    
    def generate_registration_challenge(self, email: str, user_id: str) -> Dict[str, Any]:
        """Genera opciones para registrar una nueva passkey"""
        
        user_id_bytes = user_id.encode('utf-8')
        
        registration_options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            user_id=user_id_bytes,
            user_name=email,
            user_display_name=email.split('@')[0],
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment="platform",
                user_verification=UserVerificationRequirement.PREFERRED,
                resident_key="preferred"
            ),
            timeout=60000,
        )
        
        return json.loads(options_to_json(registration_options))
    
    def verify_registration(
        self, 
        credential: Dict[str, Any],
        challenge: str
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Verifica el registro de una passkey"""
        
        try:
            # Convertir la respuesta del cliente
            registration_credential = RegistrationCredential.model_validate(credential)
            
            # Verificar el registro
            expected_challenge = base64url_to_bytes(challenge)
            
            verification = verify_registration_response(
                credential=registration_credential,
                expected_challenge=expected_challenge,
                expected_rp_id=self.rp_id,
                expected_origin=self.origin,
                require_user_verification=True,
            )
            
            # Extraer información relevante de la credencial
            credential_data = {
                "credential_id": base64.b64encode(verification.credential_id).decode('utf-8'),
                "public_key": "stored_separately",  # En producción, guardar la public key en formato adecuado
                "sign_count": verification.sign_count,
            }
            
            return True, credential_data
            
        except Exception as e:
            logger.error(f"Error verificando registro: {str(e)}")
            return False, None
    
    def generate_login_challenge(self, existing_credentials: list = []) -> Dict[str, Any]:
        """Genera opciones para login con passkey"""
        
        authentication_options = generate_authentication_options(
            rp_id=self.rp_id,
            timeout=60000,
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        
        return json.loads(options_to_json(authentication_options))
    
    def verify_login(
        self,
        credential: Dict[str, Any],
        challenge: str,
        stored_credential: Dict[str, Any]
    ) -> Tuple[bool, Optional[int]]:
        """Verifica el login con passkey"""
        
        try:
            # Convertir la respuesta del cliente
            authentication_credential = AuthenticationCredential.model_validate(credential)
            
            # Verificar el login
            expected_challenge = base64url_to_bytes(challenge)
            
            verification = verify_authentication_response(
                credential=authentication_credential,
                expected_challenge=expected_challenge,
                expected_rp_id=self.rp_id,
                expected_origin=self.origin,
                require_user_verification=True,
            )
            
            return True, verification.new_sign_count
            
        except Exception as e:
            logger.error(f"Error verificando login: {str(e)}")
            return False, None

# Instancia global
passkey_service = PasskeyService()
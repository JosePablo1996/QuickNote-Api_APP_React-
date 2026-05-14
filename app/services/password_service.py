# app/services/password_service.py
import hashlib
import re
import secrets
import string
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, List, Dict, Any

from app.services.supabase_client import supabase_client

logger = logging.getLogger(__name__)


class PasswordService:
    """
    Servicio centralizado para gestion de contrasenas.
    Maneja: validacion, historial, expiracion, politicas
    """
    
    def __init__(self):
        self.default_policy = {
            "max_age_days": 90,
            "prevent_reuse_count": 5,
            "min_length": 8,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_numbers": True,
            "require_special_chars": True
        }
        logger.info("PasswordService inicializado")
    
    # ============================================
    # HASHEO Y VERIFICACION (SIN BCRYPT)
    # ============================================
    
    def hash_password(self, password: str) -> str:
        """Genera hash SHA-256 de una contrasena."""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verifica una contrasena contra su hash."""
        try:
            return self.hash_password(password) == hashed
        except Exception as e:
            logger.error(f"Error verificando contrasena: {e}")
            return False
    
    def hash_for_history(self, password: str) -> str:
        """Genera hash SHA-256 para almacenar en historial."""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    # ============================================
    # VALIDACION DE FORTALEZA
    # ============================================
    
    def validate_strength(self, password: str, policy: Dict = None) -> Tuple[bool, List[str]]:
        """Valida la fortaleza de una contrasena segun politica."""
        if policy is None:
            policy = self.default_policy
        
        errors = []
        
        min_length = policy.get("min_length", 8)
        if len(password) < min_length:
            errors.append(f"La contrasena debe tener al menos {min_length} caracteres")
        
        if policy.get("require_uppercase", True) and not re.search(r'[A-Z]', password):
            errors.append("La contrasena debe contener al menos una letra mayuscula")
        
        if policy.get("require_lowercase", True) and not re.search(r'[a-z]', password):
            errors.append("La contrasena debe contener al menos una letra minuscula")
        
        if policy.get("require_numbers", True) and not re.search(r'\d', password):
            errors.append("La contrasena debe contener al menos un numero")
        
        if policy.get("require_special_chars", True) and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("La contrasena debe contener al menos un caracter especial")
        
        return len(errors) == 0, errors
    
    def calculate_strength_score(self, password: str) -> int:
        """Calcula un puntaje de fortaleza (0-100)."""
        score = 0
        
        if len(password) >= 8:
            score += 10
        if len(password) >= 10:
            score += 5
        if len(password) >= 12:
            score += 5
        if len(password) >= 14:
            score += 5
        
        if re.search(r'[A-Z]', password):
            score += 10
        if re.search(r'[a-z]', password):
            score += 10
        if re.search(r'\d', password):
            score += 15
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 15
        
        unique_chars = len(set(password))
        if unique_chars >= 6:
            score += 10
        if unique_chars >= 8:
            score += 10
        if unique_chars >= 10:
            score += 5
        
        return min(score, 100)
    
    def get_strength_level(self, score: int) -> Dict:
        """Obtiene nivel de fortaleza basado en puntaje."""
        if score < 30:
            return {"level": "muy_debil", "color": "red", "message": "Muy debil", "icon": "🔴"}
        elif score < 50:
            return {"level": "debil", "color": "orange", "message": "Debil", "icon": "🟠"}
        elif score < 70:
            return {"level": "media", "color": "yellow", "message": "Media", "icon": "🟡"}
        elif score < 90:
            return {"level": "fuerte", "color": "lightgreen", "message": "Fuerte", "icon": "🟢"}
        else:
            return {"level": "muy_fuerte", "color": "green", "message": "Muy fuerte", "icon": "✅"}
    
    # ============================================
    # POLITICA DE CONTRASENAS
    # ============================================
    
    async def get_password_policy(self) -> Dict:
        """Obtiene la politica actual de contrasenas desde la base de datos."""
        try:
            result = supabase_client.table("password_policies").select("*").limit(1).execute()
            if result and len(result) > 0:
                policy = result[0]
                logger.debug(f"Politica obtenida: max_age={policy.get('max_age_days')} dias")
                return policy
        except Exception as e:
            logger.error(f"Error obteniendo politica: {e}")
        
        logger.info(f"Usando politica por defecto")
        return self.default_policy.copy()
    
    async def update_password_policy(self, updates: Dict) -> bool:
        """Actualiza la politica de contrasenas."""
        try:
            current = await self.get_password_policy()
            updated = {**current, **updates, "updated_at": datetime.now(timezone.utc).isoformat()}
            
            existing = supabase_client.table("password_policies").select("*").limit(1).execute()
            
            if existing and len(existing) > 0:
                supabase_client.table("password_policies")\
                    .update(updated)\
                    .eq("id", existing[0]["id"])\
                    .execute()
            else:
                supabase_client.table("password_policies").insert(updated).execute()
            
            logger.info(f"Politica actualizada: {updates}")
            return True
        except Exception as e:
            logger.error(f"Error actualizando politica: {e}")
            return False
    
    # ============================================
    # HISTORIAL DE CONTRASENAS
    # ============================================
    
    async def record_password_history(self, user_id: str, password_hash: str) -> bool:
        """Registra un hash de contrasena en el historial."""
        try:
            supabase_client.table("password_history").insert({
                "user_id": user_id,
                "password_hash": password_hash,
                "created_at": datetime.now(timezone.utc).isoformat()
            }).execute()
            logger.debug(f"Historial registrado para usuario {user_id}")
            return True
        except Exception as e:
            logger.error(f"Error registrando historial: {e}")
            return False
    
    async def check_password_reuse(self, user_id: str, new_password_hash: str) -> Tuple[bool, int]:
        """Verifica si una contrasena ya fue usada recientemente."""
        try:
            policy = await self.get_password_policy()
            prevent_reuse = policy.get("prevent_reuse_count", 5)
            
            result = supabase_client.table("password_history")\
                .select("password_hash")\
                .eq("user_id", user_id)\
                .order("created_at", desc=True)\
                .limit(prevent_reuse)\
                .execute()
            
            recent_hashes = [r["password_hash"] for r in (result or [])]
            
            if new_password_hash in recent_hashes:
                times_used = recent_hashes.count(new_password_hash)
                logger.warning(f"Contrasena reutilizada por usuario {user_id}")
                return False, times_used
            
            return True, 0
        except Exception as e:
            logger.error(f"Error verificando reuso: {e}")
            return True, 0
    
    async def cleanup_old_history(self, user_id: str, keep_count: int = 20) -> int:
        """Limpia historial antiguo de contrasenas."""
        try:
            result = supabase_client.table("password_history")\
                .select("id")\
                .eq("user_id", user_id)\
                .order("created_at", desc=True)\
                .offset(keep_count)\
                .execute()
            
            if not result:
                return 0
            
            ids_to_delete = [r["id"] for r in result]
            
            if ids_to_delete:
                for record_id in ids_to_delete:
                    supabase_client.table("password_history")\
                        .delete()\
                        .eq("id", record_id)\
                        .execute()
                
                logger.info(f"Limpiados {len(ids_to_delete)} registros antiguos")
                return len(ids_to_delete)
            return 0
        except Exception as e:
            logger.error(f"Error limpiando historial: {e}")
            return 0
    
    # ============================================
    # EXPIRACION DE CONTRASENAS
    # ============================================
    
    async def calculate_expiry_date(self) -> datetime:
        """Calcula fecha de expiracion basada en la politica actual."""
        policy = await self.get_password_policy()
        max_age_days = policy.get("max_age_days", 90)
        return datetime.now(timezone.utc) + timedelta(days=max_age_days)
    
    async def is_password_expired(self, expires_at: Optional[datetime] = None) -> Tuple[bool, Optional[int]]:
        """Verifica si una contrasena ha expirado."""
        try:
            if expires_at is None:
                return False, None
            
            now = datetime.now(timezone.utc)
            
            if expires_at < now:
                return True, 0
            
            days_remaining = (expires_at - now).days
            return False, days_remaining
        except Exception as e:
            logger.error(f"Error verificando expiracion: {e}")
            return False, None
    
    # ============================================
    # NOTIFICACIONES
    # ============================================
    
    def should_notify_expiry(self, days_remaining: int, last_notified_days: Optional[int] = None) -> bool:
        """Determina si se debe enviar notificacion de expiracion."""
        thresholds = [30, 14, 7, 3, 1]
        
        if days_remaining <= 0:
            return False
        
        for threshold in thresholds:
            if days_remaining <= threshold:
                if last_notified_days is None or last_notified_days > threshold:
                    return True
        
        return False
    
    def get_expiry_warning_message(self, days_remaining: int) -> str:
        """Obtiene mensaje de advertencia segun dias restantes."""
        if days_remaining <= 0:
            return "Tu contrasena ha expirado. Debes cambiarla para continuar."
        elif days_remaining == 1:
            return "Tu contrasena expirara manana. Por favor, cambiala cuanto antes."
        elif days_remaining <= 3:
            return f"Tu contrasena expirara en {days_remaining} dias. Te recomendamos cambiarla pronto."
        elif days_remaining <= 7:
            return f"Tu contrasena expirara en {days_remaining} dias. Considera cambiarla para mayor seguridad."
        elif days_remaining <= 30:
            return f"Tu contrasena expirara en {days_remaining} dias. Puedes cambiarla cuando lo desees."
        else:
            return f"Tu contrasena esta vigente por {days_remaining} dias mas."
    
    # ============================================
    # GENERACION DE CONTRASENAS SEGURAS
    # ============================================
    
    def generate_secure_password(self, length: int = 16) -> str:
        """Genera una contrasena segura aleatoria."""
        if length < 12:
            length = 12
        
        characters = (
            string.ascii_uppercase +
            string.ascii_lowercase +
            string.digits +
            "!@#$%^&*"
        )
        
        password = ''.join(secrets.choice(characters) for _ in range(length))
        
        while not all([
            re.search(r'[A-Z]', password),
            re.search(r'[a-z]', password),
            re.search(r'\d', password),
            re.search(r'[!@#$%^&*]', password)
        ]):
            password = ''.join(secrets.choice(characters) for _ in range(length))
        
        return password


# Instancia global
password_service = PasswordService()
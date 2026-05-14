# app/services/security_service.py
import logging
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Tuple
from uuid import UUID, uuid4

from app.services.supabase_client import supabase_client
from app.config import settings

logger = logging.getLogger(__name__)


class SecurityService:
    """
    Servicio centralizado para seguridad y auditoria.
    Maneja:
    - Eventos de seguridad
    - Gestion de sesiones activas
    - Bloqueo de cuentas
    - Verificacion de dispositivos
    - Rate limiting
    """
    
    def __init__(self):
        self.max_login_attempts = 5
        self.lockout_duration_minutes = 15
        self.session_timeout_hours = 24
        logger.info("SecurityService inicializado")
    
    # ============================================
    # EVENTOS DE SEGURIDAD
    # ============================================
    
    async def log_security_event(
        self,
        user_id: str,
        event_type: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict] = None
    ) -> bool:
        """
        Registra un evento de seguridad en la base de datos.
        
        Args:
            user_id: ID del usuario
            event_type: Tipo de evento
            ip_address: Direccion IP del usuario
            user_agent: User-Agent del navegador
            details: Detalles adicionales del evento
            
        Returns:
            True si se registro correctamente
        """
        try:
            # Usar cliente con service role
            client = supabase_client.with_service_role()
            
            event_data = {
                "user_id": user_id,
                "event_type": event_type,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "details": details or {},
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            
            result = client.table("security_events").insert(event_data)
            
            if result:
                logger.info(f"Evento de seguridad registrado: {event_type} para usuario {user_id}")
                return True
            return False
            
        except Exception as e:
            logger.error(f"Error registrando evento de seguridad: {e}")
            return False
    
    async def get_security_events(
        self,
        user_id: str,
        event_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict]:
        """
        Obtiene eventos de seguridad de un usuario.
        
        Args:
            user_id: ID del usuario
            event_type: Filtrar por tipo de evento (opcional)
            limit: Numero maximo de eventos
            offset: Desplazamiento para paginacion
            
        Returns:
            Lista de eventos de seguridad
        """
        try:
            client = supabase_client.with_service_role()
            query = client.table("security_events")\
                .select("*")\
                .eq("user_id", user_id)\
                .order("created_at", desc=True)\
                .limit(limit)\
                .offset(offset)
            
            if event_type:
                query = query.eq("event_type", event_type)
            
            result = query.execute()
            return result if result else []
            
        except Exception as e:
            logger.error(f"Error obteniendo eventos de seguridad: {e}")
            return []
    
    async def get_recent_security_events(
        self,
        user_id: str,
        hours: int = 24
    ) -> List[Dict]:
        """
        Obtiene eventos de seguridad recientes.
        
        Args:
            user_id: ID del usuario
            hours: Horas hacia atras
            
        Returns:
            Lista de eventos recientes
        """
        try:
            client = supabase_client.with_service_role()
            cutoff_time = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
            
            result = client.table("security_events")\
                .select("*")\
                .eq("user_id", user_id)\
                .gte("created_at", cutoff_time)\
                .order("created_at", desc=True)\
                .execute()
            
            return result if result else []
            
        except Exception as e:
            logger.error(f"Error obteniendo eventos recientes: {e}")
            return []
    
    # ============================================
    # GESTION DE SESIONES
    # ============================================
    
    async def create_session(
        self,
        user_id: str,
        session_token: str,
        device_info: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Optional[Dict]:
        """
        Crea una nueva sesion activa.
        
        Args:
            user_id: ID del usuario
            session_token: Token de sesion
            device_info: Informacion del dispositivo
            ip_address: Direccion IP
            user_agent: User-Agent
            
        Returns:
            Datos de la sesion creada o None
        """
        try:
            client = supabase_client.with_service_role()
            session_data = {
                "user_id": user_id,
                "session_token": session_token,
                "device_info": device_info,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_activity": datetime.now(timezone.utc).isoformat(),
                "is_active": True
            }
            
            result = client.table("active_sessions").insert(session_data)
            
            if result and len(result) > 0:
                logger.info(f"Sesion creada para usuario {user_id}")
                return result[0]
            return None
            
        except Exception as e:
            logger.error(f"Error creando sesion: {e}")
            return None
    
    async def update_session_activity(self, session_token: str) -> bool:
        """
        Actualiza la ultima actividad de una sesion.
        
        Args:
            session_token: Token de sesion
            
        Returns:
            True si se actualizo correctamente
        """
        try:
            client = supabase_client.with_service_role()
            client.table("active_sessions")\
                .update({"last_activity": datetime.now(timezone.utc).isoformat()})\
                .eq("session_token", session_token)\
                .execute()
            
            return True
            
        except Exception as e:
            logger.error(f"Error actualizando actividad de sesion: {e}")
            return False
    
    async def get_active_sessions(self, user_id: str) -> List[Dict]:
        """
        Obtiene todas las sesiones activas de un usuario.
        
        Args:
            user_id: ID del usuario
            
        Returns:
            Lista de sesiones activas
        """
        try:
            client = supabase_client.with_service_role()
            result = client.table("active_sessions")\
                .select("*")\
                .eq("user_id", user_id)\
                .eq("is_active", True)\
                .order("created_at", desc=True)\
                .execute()
            
            return result if result else []
            
        except Exception as e:
            logger.error(f"Error obteniendo sesiones activas: {e}")
            return []
    
    async def invalidate_session(self, session_token: str) -> bool:
        """
        Invalida una sesion especifica.
        
        Args:
            session_token: Token de sesion
            
        Returns:
            True si se invalido correctamente
        """
        try:
            client = supabase_client.with_service_role()
            client.table("active_sessions")\
                .update({"is_active": False})\
                .eq("session_token", session_token)\
                .execute()
            
            logger.info(f"Sesion invalidada: {session_token[:20]}...")
            return True
            
        except Exception as e:
            logger.error(f"Error invalidando sesion: {e}")
            return False
    
    async def invalidate_all_sessions(self, user_id: str, exclude_current: Optional[str] = None) -> int:
        """
        Invalida todas las sesiones de un usuario.
        
        Args:
            user_id: ID del usuario
            exclude_current: Token de sesion a excluir (opcional)
            
        Returns:
            Numero de sesiones invalidadas
        """
        try:
            client = supabase_client.with_service_role()
            query = client.table("active_sessions")\
                .update({"is_active": False})\
                .eq("user_id", user_id)\
                .eq("is_active", True)
            
            if exclude_current:
                query = query.neq("session_token", exclude_current)
            
            result = query.execute()
            
            count = len(result) if result else 0
            logger.info(f"{count} sesiones invalidadas para usuario {user_id}")
            return count
            
        except Exception as e:
            logger.error(f"Error invalidando todas las sesiones: {e}")
            return 0
    
    async def cleanup_expired_sessions(self) -> int:
        """
        Limpia sesiones expiradas (sin actividad por mas de session_timeout_hours).
        
        Returns:
            Numero de sesiones eliminadas
        """
        try:
            client = supabase_client.with_service_role()
            cutoff_time = (datetime.now(timezone.utc) - timedelta(hours=self.session_timeout_hours)).isoformat()
            
            result = client.table("active_sessions")\
                .update({"is_active": False})\
                .lt("last_activity", cutoff_time)\
                .eq("is_active", True)\
                .execute()
            
            count = len(result) if result else 0
            if count > 0:
                logger.info(f"Limpiadas {count} sesiones expiradas")
            return count
            
        except Exception as e:
            logger.error(f"Error limpiando sesiones expiradas: {e}")
            return 0
    
    # ============================================
    # BLOQUEO DE CUENTAS (RATE LIMITING)
    # ============================================
    
    async def record_failed_login(self, email: str, ip_address: str) -> Dict:
        """
        Registra un intento de login fallido.
        
        Args:
            email: Email del usuario
            ip_address: Direccion IP
            
        Returns:
            Dict con estado de bloqueo
        """
        try:
            client = supabase_client.with_service_role()
            
            # Buscar registro de intentos fallidos
            result = client.table("login_attempts")\
                .select("*")\
                .eq("email", email)\
                .eq("ip_address", ip_address)\
                .execute()
            
            if result and len(result) > 0:
                attempt = result[0]
                new_count = attempt.get("attempt_count", 0) + 1
                is_locked = new_count >= self.max_login_attempts
                
                client.table("login_attempts")\
                    .update({
                        "attempt_count": new_count,
                        "last_attempt": datetime.now(timezone.utc).isoformat(),
                        "is_locked": is_locked,
                        "locked_until": (datetime.now(timezone.utc) + timedelta(minutes=self.lockout_duration_minutes)).isoformat() if is_locked else None
                    })\
                    .eq("id", attempt["id"])\
                    .execute()
            else:
                client.table("login_attempts").insert({
                    "email": email,
                    "ip_address": ip_address,
                    "attempt_count": 1,
                    "last_attempt": datetime.now(timezone.utc).isoformat(),
                    "is_locked": False,
                    "locked_until": None
                }).execute()
                new_count = 1
                is_locked = False
            
            return {
                "attempts": new_count,
                "is_locked": is_locked,
                "max_attempts": self.max_login_attempts,
                "remaining_attempts": max(0, self.max_login_attempts - new_count)
            }
            
        except Exception as e:
            logger.error(f"Error registrando intento fallido: {e}")
            return {"attempts": 1, "is_locked": False, "remaining_attempts": self.max_login_attempts - 1}
    
    async def reset_failed_logins(self, email: str, ip_address: str) -> bool:
        """
        Resetea los intentos fallidos de login (despues de login exitoso).
        
        Args:
            email: Email del usuario
            ip_address: Direccion IP
            
        Returns:
            True si se resetearon correctamente
        """
        try:
            client = supabase_client.with_service_role()
            client.table("login_attempts")\
                .delete()\
                .eq("email", email)\
                .eq("ip_address", ip_address)\
                .execute()
            
            logger.info(f"Intentos fallidos reseteados para {email}")
            return True
            
        except Exception as e:
            logger.error(f"Error resetando intentos fallidos: {e}")
            return False
    
    async def is_account_locked(self, email: str, ip_address: str) -> Tuple[bool, Optional[datetime]]:
        """
        Verifica si una cuenta esta bloqueada.
        
        Args:
            email: Email del usuario
            ip_address: Direccion IP
            
        Returns:
            Tuple (esta_bloqueada, fecha_desbloqueo)
        """
        try:
            client = supabase_client.with_service_role()
            result = client.table("login_attempts")\
                .select("*")\
                .eq("email", email)\
                .eq("ip_address", ip_address)\
                .execute()
            
            if result and len(result) > 0:
                attempt = result[0]
                if attempt.get("is_locked") and attempt.get("locked_until"):
                    locked_until = datetime.fromisoformat(attempt["locked_until"].replace('Z', '+00:00'))
                    if locked_until > datetime.now(timezone.utc):
                        return True, locked_until
                    else:
                        await self.reset_failed_logins(email, ip_address)
                        return False, None
            
            return False, None
            
        except Exception as e:
            logger.error(f"Error verificando bloqueo: {e}")
            return False, None
    
    # ============================================
    # VERIFICACION DE DISPOSITIVOS
    # ============================================
    
    def generate_device_fingerprint(self, user_agent: str, ip_address: str) -> str:
        """
        Genera una huella digital del dispositivo.
        
        Args:
            user_agent: User-Agent del navegador
            ip_address: Direccion IP
            
        Returns:
            Hash SHA-256 de la huella
        """
        fingerprint_data = f"{user_agent}|{ip_address}"
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()
    
    async def is_trusted_device(self, user_id: str, device_fingerprint: str) -> bool:
        """
        Verifica si un dispositivo es confiable.
        
        Args:
            user_id: ID del usuario
            device_fingerprint: Huella del dispositivo
            
        Returns:
            True si es un dispositivo confiable
        """
        try:
            client = supabase_client.with_service_role()
            result = client.table("trusted_devices")\
                .select("*")\
                .eq("user_id", user_id)\
                .eq("device_fingerprint", device_fingerprint)\
                .eq("is_trusted", True)\
                .execute()
            
            return result is not None and len(result) > 0
            
        except Exception as e:
            logger.error(f"Error verificando dispositivo confiable: {e}")
            return False
    
    async def add_trusted_device(
        self,
        user_id: str,
        device_fingerprint: str,
        device_name: str,
        user_agent: str
    ) -> bool:
        """
        Marca un dispositivo como confiable.
        
        Args:
            user_id: ID del usuario
            device_fingerprint: Huella del dispositivo
            device_name: Nombre del dispositivo
            user_agent: User-Agent
            
        Returns:
            True si se agrego correctamente
        """
        try:
            client = supabase_client.with_service_role()
            client.table("trusted_devices").insert({
                "user_id": user_id,
                "device_fingerprint": device_fingerprint,
                "device_name": device_name,
                "user_agent": user_agent,
                "is_trusted": True,
                "last_used": datetime.now(timezone.utc).isoformat(),
                "created_at": datetime.now(timezone.utc).isoformat()
            }).execute()
            
            logger.info(f"Dispositivo confiable agregado para usuario {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error agregando dispositivo confiable: {e}")
            return False
    
    # ============================================
    # GENERACION DE TOKENS SEGUROS
    # ============================================
    
    def generate_secure_token(self, length: int = 32) -> str:
        """
        Genera un token seguro aleatorio.
        
        Args:
            length: Longitud del token
            
        Returns:
            Token hexadecimal
        """
        return secrets.token_hex(length)
    
    def generate_session_token(self) -> str:
        """
        Genera un token de sesion unico.
        
        Returns:
            Token de sesion
        """
        return f"session_{secrets.token_urlsafe(32)}"
    
    def generate_csrf_token(self) -> str:
        """
        Genera un token CSRF.
        
        Returns:
            Token CSRF
        """
        return secrets.token_urlsafe(32)
    
    # ============================================
    # AUDITORIA Y ESTADISTICAS
    # ============================================
    
    async def get_security_stats(self, user_id: str, days: int = 30) -> Dict:
        """
        Obtiene estadisticas de seguridad de un usuario.
        
        Args:
            user_id: ID del usuario
            days: Dias hacia atras
            
        Returns:
            Dict con estadisticas
        """
        try:
            client = supabase_client.with_service_role()
            cutoff_time = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
            
            events = client.table("security_events")\
                .select("*")\
                .eq("user_id", user_id)\
                .gte("created_at", cutoff_time)\
                .execute()
            
            events = events if events else []
            
            stats = {
                "total_events": len(events),
                "period_days": days,
                "by_type": {},
                "recent_activity": []
            }
            
            for event in events:
                event_type = event.get("event_type")
                if event_type:
                    stats["by_type"][event_type] = stats["by_type"].get(event_type, 0) + 1
                
                if len(stats["recent_activity"]) < 10:
                    stats["recent_activity"].append({
                        "type": event_type,
                        "created_at": event.get("created_at"),
                        "ip_address": event.get("ip_address")
                    })
            
            active_sessions = await self.get_active_sessions(user_id)
            stats["active_sessions_count"] = len(active_sessions)
            
            return stats
            
        except Exception as e:
            logger.error(f"Error obteniendo estadisticas de seguridad: {e}")
            return {
                "total_events": 0,
                "period_days": days,
                "by_type": {},
                "recent_activity": [],
                "active_sessions_count": 0
            }


# Tipos de eventos de seguridad predefinidos
class SecurityEventType:
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT = "LOGOUT"
    LOGOUT_ALL_SESSIONS = "LOGOUT_ALL_SESSIONS"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    PASSWORD_EXPIRING_SOON = "PASSWORD_EXPIRING_SOON"
    PASSWORD_EXPIRED = "PASSWORD_EXPIRED"
    PASSWORD_REUSE_ATTEMPT = "PASSWORD_REUSE_ATTEMPT"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    ACCOUNT_UNLOCKED = "ACCOUNT_UNLOCKED"
    TWO_FACTOR_ENABLED = "TWO_FACTOR_ENABLED"
    TWO_FACTOR_DISABLED = "TWO_FACTOR_DISABLED"
    TWO_FACTOR_VERIFIED = "TWO_FACTOR_VERIFIED"
    TWO_FACTOR_FAILED = "TWO_FACTOR_FAILED"
    DEVICE_TRUSTED = "DEVICE_TRUSTED"
    DEVICE_UNTRUSTED = "DEVICE_UNTRUSTED"
    EMAIL_CHANGED = "EMAIL_CHANGED"
    PROFILE_UPDATED = "PROFILE_UPDATED"


# Instancia global del servicio
security_service = SecurityService()
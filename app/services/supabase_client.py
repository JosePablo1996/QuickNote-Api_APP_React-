# app/services/supabase_client.py
import httpx
from app.config import settings
from typing import Optional, Dict, Any, List, Union
from datetime import datetime, timezone
import logging

# Configurar logger
logger = logging.getLogger(__name__)


class SupabaseClient:
    """
    Cliente personalizado para Supabase.
    """
    
    def __init__(self):
        self.url = settings.supabase_url
        self.key = settings.supabase_key
        self.service_role_key = getattr(settings, 'supabase_service_role_key', settings.supabase_key)
        self.base_headers = {
            "apikey": self.key,
            "Content-Type": "application/json",
        }
        self.client = httpx.Client(timeout=30.0)
        logger.info("=" * 50)
        logger.info("Cliente Supabase manual inicializado")
        logger.info(f"URL: {self.url}")
        logger.info("=" * 50)
    
    def with_token(self, token: str):
        """Crear una nueva instancia con un token de usuario."""
        headers = self.base_headers.copy()
        headers["Authorization"] = f"Bearer {token}"
        headers["Prefer"] = "return=representation"
        return SupabaseClientWithToken(self, headers, token)
    
    def with_service_role(self):
        """Crear una instancia con service role key (bypass RLS)."""
        headers = self.base_headers.copy()
        headers["apikey"] = self.service_role_key
        headers["Authorization"] = f"Bearer {self.service_role_key}"
        headers["Prefer"] = "return=representation"
        return SupabaseClientWithToken(self, headers, self.service_role_key)
    
    def get_table(self, table_name: str):
        """Obtener un manejador de tabla con service role."""
        return self.with_service_role().table(table_name)
    
    # ============================================
    # METODOS DE HISTORIAL DE CONTRASENAS
    # ============================================
    
    async def record_password_history(self, user_id: str, password_hash: str) -> bool:
        """Registra un hash de contrasena en el historial."""
        try:
            client = self.with_service_role()
            result = client.table("password_history").insert({
                "user_id": user_id,
                "password_hash": password_hash,
                "created_at": datetime.now(timezone.utc).isoformat()
            })
            logger.debug(f"Historial registrado para usuario {user_id}")
            return result is not None and len(result) > 0
        except Exception as e:
            logger.error(f"Error registrando historial: {e}")
            return False
    
    async def check_password_reuse(self, user_id: str, new_password_hash: str, prevent_reuse: int = 5) -> bool:
        """Verifica si una contrasena ya fue usada recientemente."""
        try:
            client = self.with_service_role()
            result = client.table("password_history")\
                .select("password_hash")\
                .eq("user_id", user_id)\
                .order("created_at", desc=True)\
                .limit(prevent_reuse)\
                .execute()
            
            recent_hashes = [r["password_hash"] for r in (result or [])]
            
            if new_password_hash in recent_hashes:
                logger.warning(f"Contrasena reutilizada por usuario {user_id}")
                return False
            return True
        except Exception as e:
            logger.error(f"Error verificando reuso: {e}")
            return True
    
    async def cleanup_old_password_history(self, user_id: str, keep_count: int = 20) -> int:
        """Limpia historial antiguo de contrasenas."""
        try:
            client = self.with_service_role()
            result = client.table("password_history")\
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
                    client.table("password_history")\
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
    # METODOS DE SESIONES
    # ============================================
    
    async def invalidate_all_sessions(self, user_id: str) -> int:
        """Invalida todas las sesiones de un usuario."""
        try:
            client = self.with_service_role()
            result = client.table("active_sessions")\
                .update({"is_active": False})\
                .eq("user_id", user_id)\
                .eq("is_active", True)\
                .execute()
            count = len(result) if result else 0
            if count > 0:
                logger.info(f"{count} sesiones invalidadas para usuario {user_id}")
            return count
        except Exception as e:
            logger.error(f"Error invalidando sesiones: {e}")
            return 0
    
    async def get_active_sessions(self, user_id: str) -> List[Dict]:
        """Obtiene todas las sesiones activas de un usuario."""
        try:
            client = self.with_service_role()
            result = client.table("active_sessions")\
                .select("*")\
                .eq("user_id", user_id)\
                .eq("is_active", True)\
                .order("created_at", desc=True)\
                .execute()
            return result if result else []
        except Exception as e:
            logger.error(f"Error obteniendo sesiones: {e}")
            return []
    
    # ============================================
    # METODOS DE POLITICA DE CONTRASENAS
    # ============================================
    
    async def get_password_policy(self) -> Dict:
        """Obtiene la politica actual de contrasenas."""
        try:
            client = self.with_service_role()
            result = client.table("password_policies").select("*").limit(1).execute()
            if result and len(result) > 0:
                return result[0]
        except Exception as e:
            logger.error(f"Error obteniendo politica: {e}")
        
        return {
            "max_age_days": 90,
            "prevent_reuse_count": 5,
            "min_length": 8,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_numbers": True,
            "require_special_chars": True
        }
    
    async def update_password_policy(self, updates: Dict) -> bool:
        """Actualiza la politica de contrasenas."""
        try:
            client = self.with_service_role()
            current = await self.get_password_policy()
            
            if current.get("id"):
                client.table("password_policies")\
                    .update({**updates, "updated_at": datetime.now(timezone.utc).isoformat()})\
                    .eq("id", current["id"])\
                    .execute()
            else:
                client.table("password_policies").insert({
                    **updates,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "updated_at": datetime.now(timezone.utc).isoformat()
                }).execute()
            
            logger.info(f"Politica actualizada: {updates}")
            return True
        except Exception as e:
            logger.error(f"Error actualizando politica: {e}")
            return False
    
    # ============================================
    # METODOS DE USUARIO (CORREGIDOS CON MAPEO DE CAMPOS)
    # ============================================
    
    async def get_user_metadata(self, user_id: str) -> Optional[Dict]:
        """
        Obtiene metadata de un usuario desde la tabla profiles.
        Devuelve los nombres de campos consistentes con el backend.
        """
        try:
            client = self.with_service_role()
            result = client.table("profiles").select("*").eq("id", user_id).execute()
            if result and len(result) > 0:
                user_data = result[0]
                # Mapear nombres de vuelta para consistencia con el backend
                return {
                    "id": user_data.get("id"),
                    "full_name": user_data.get("full_name"),
                    "avatar": user_data.get("avatar_url"),      # avatar_url -> avatar
                    "banner": user_data.get("banner_url"),      # banner_url -> banner
                    "email": user_data.get("email"),
                    "session_version": user_data.get("session_version"),
                    "password_changed_at": user_data.get("password_changed_at"),
                    "password_expires_at": user_data.get("password_expires_at"),
                    "password_reset_via_otp": user_data.get("password_reset_via_otp"),
                    "updated_at": user_data.get("updated_at")
                }
            return None
        except Exception as e:
            logger.error(f"Error obteniendo usuario: {e}")
            return None
    
    async def update_user_metadata(self, user_id: str, metadata: Dict) -> bool:
        """
        Actualiza metadata de un usuario en la tabla profiles.
        Mapea los nombres de campos del backend a los nombres reales en la tabla.
        """
        try:
            client = self.with_service_role()
            
            # Mapeo de campos del backend a nombres reales en la tabla
            field_mapping = {
                "avatar": "avatar_url",
                "banner": "banner_url",
                "full_name": "full_name",
                "session_version": "session_version",
                "password_changed_at": "password_changed_at",
                "password_expires_at": "password_expires_at",
                "password_reset_via_otp": "password_reset_via_otp",
                "username": "username",
                "bio": "bio"
            }
            
            # Campos permitidos en la tabla profiles (usando nombres reales)
            allowed_fields = [
                "avatar_url",
                "banner_url", 
                "full_name",
                "session_version",
                "password_changed_at",
                "password_expires_at",
                "password_reset_via_otp",
                "username",
                "bio"
            ]
            
            logger.info(f"Actualizando metadata para usuario {user_id}: {metadata}")
            
            # Convertir nombres de campos y filtrar
            filtered_metadata = {}
            for key, value in metadata.items():
                # Mapear el nombre del campo si es necesario
                db_field = field_mapping.get(key, key)
                
                if db_field in allowed_fields and value is not None:
                    # Asegurar tipos correctos
                    if db_field == "session_version":
                        # Convertir a entero
                        try:
                            filtered_metadata[db_field] = int(float(value))
                        except (ValueError, TypeError):
                            filtered_metadata[db_field] = 0
                        logger.info(f"  Campo mapeado: {key} -> {db_field} = {filtered_metadata[db_field]}")
                    elif db_field in ["password_changed_at", "password_expires_at"]:
                        # Mantener formato ISO
                        filtered_metadata[db_field] = value
                        logger.info(f"  Campo mapeado: {key} -> {db_field} = {value}")
                    else:
                        filtered_metadata[db_field] = value
                        logger.info(f"  Campo mapeado: {key} -> {db_field} = {value}")
                elif value is None:
                    logger.warning(f"Campo {key} tiene valor None, ignorando")
                else:
                    logger.warning(f"Campo ignorado (no existe en profiles): {key}")
            
            if not filtered_metadata:
                logger.warning(f"No hay campos validos para actualizar para usuario {user_id}")
                return True
            
            # Verificar si existe el perfil
            existing = client.table("profiles").select("*").eq("id", user_id).execute()
            logger.info(f"Perfil existe: {existing is not None and len(existing) > 0}")
            
            if existing and len(existing) > 0:
                # Actualizar perfil existente (sin updated_at porque tiene default)
                result = client.table("profiles")\
                    .update(filtered_metadata)\
                    .eq("id", user_id)\
                    .execute()
                
                if result:
                    logger.info(f"Metadata actualizada para usuario {user_id}: {list(filtered_metadata.keys())}")
                    return True
                else:
                    logger.error(f"Error actualizando perfil para usuario {user_id} - resultado vacio")
                    return False
            else:
                # Crear nuevo perfil
                insert_data = {
                    "id": user_id,
                    **filtered_metadata
                }
                result = client.table("profiles").insert(insert_data).execute()
                
                if result:
                    logger.info(f"Perfil creado para usuario {user_id}: {list(filtered_metadata.keys())}")
                    return True
                else:
                    logger.error(f"Error creando perfil para usuario {user_id}")
                    return False
            
        except Exception as e:
            logger.error(f"Error actualizando usuario: {e}")
            import traceback
            traceback.print_exc()
            return False


class SupabaseClientWithToken:
    """Cliente de Supabase con token de usuario."""
    
    def __init__(self, parent: SupabaseClient, headers: Dict, token: str):
        self.parent = parent
        self.headers = headers
        self.token = token
        self.client = parent.client
    
    def table(self, table_name: str):
        return TableQueryWithToken(self, table_name)


class TableQueryWithToken:
    """Constructor de consultas para una tabla especifica."""
    
    def __init__(self, client: SupabaseClientWithToken, table_name: str):
        self.client = client
        self.table_name = table_name
        self.base_url = f"{client.parent.url}/rest/v1/{table_name}"
        self.params: Dict[str, str] = {}
        self.data: Optional[Dict] = None
        self._method: str = 'GET'
    
    def select(self, columns: str = "*"):
        self.params["select"] = columns
        self._method = 'GET'
        return self
    
    def eq(self, column: str, value: Any):
        self.params[f"{column}"] = f"eq.{value}"
        return self
    
    def neq(self, column: str, value: Any):
        self.params[f"{column}"] = f"neq.{value}"
        return self
    
    def gt(self, column: str, value: Any):
        self.params[f"{column}"] = f"gt.{value}"
        return self
    
    def gte(self, column: str, value: Any):
        self.params[f"{column}"] = f"gte.{value}"
        return self
    
    def lt(self, column: str, value: Any):
        self.params[f"{column}"] = f"lt.{value}"
        return self
    
    def lte(self, column: str, value: Any):
        self.params[f"{column}"] = f"lte.{value}"
        return self
    
    def like(self, column: str, pattern: str):
        self.params[f"{column}"] = f"like.{pattern}"
        return self
    
    def ilike(self, column: str, pattern: str):
        self.params[f"{column}"] = f"ilike.{pattern}"
        return self
    
    def in_(self, column: str, values: List):
        values_str = ','.join(str(v) for v in values)
        self.params[f"{column}"] = f"in.({values_str})"
        return self
    
    def is_null(self, column: str):
        """Filtro IS NULL"""
        self.params[f"{column}"] = "is.null"
        return self
    
    def is_not_null(self, column: str):
        """Filtro IS NOT NULL"""
        self.params[f"{column}"] = "not.is.null"
        return self
    
    def order(self, column: str, desc: bool = False):
        direction = "desc" if desc else "asc"
        self.params["order"] = f"{column}.{direction}"
        return self
    
    def limit(self, value: int):
        self.params["limit"] = str(value)
        return self
    
    def offset(self, value: int):
        self.params["offset"] = str(value)
        return self
    
    def insert(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.data = data
        self._method = 'POST'
        return self.execute()
    
    def update(self, data: Dict[str, Any]):
        self.data = data
        self._method = 'PATCH'
        return self
    
    def delete(self):
        self._method = 'DELETE'
        return self
    
    def execute(self) -> List[Dict[str, Any]]:
        try:
            method = self._method or 'GET'
            
            if method in ('POST', 'UPSERT'):
                response = self.client.client.post(
                    self.base_url,
                    headers=self.client.headers,
                    params=self.params,
                    json=self.data
                )
            elif method == 'PATCH':
                response = self.client.client.patch(
                    self.base_url,
                    headers=self.client.headers,
                    params=self.params,
                    json=self.data
                )
            elif method == 'DELETE':
                response = self.client.client.delete(
                    self.base_url,
                    headers=self.client.headers,
                    params=self.params
                )
            else:
                response = self.client.client.get(
                    self.base_url,
                    headers=self.client.headers,
                    params=self.params
                )
            
            response.raise_for_status()
            
            if method == 'DELETE':
                return [{"deleted": True}]
            
            result = response.json()
            return result if isinstance(result, list) else [result]
            
        except httpx.HTTPStatusError as e:
            logger.error(f"Error HTTP: {e.response.status_code}")
            raise
        except Exception as e:
            logger.error(f"Error inesperado: {str(e)}")
            raise


# Instancia global
supabase_client = SupabaseClient()
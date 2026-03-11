import httpx
from app.config import settings
from typing import Optional, Dict, Any, List
import logging
import jwt
from datetime import datetime

logger = logging.getLogger(__name__)

class SupabaseClient:
    def __init__(self):
        self.url = settings.supabase_url
        self.key = settings.supabase_key
        self.jwt_secret = settings.jwt_secret
        self.base_headers = {
            "apikey": self.key,
            "Content-Type": "application/json",
        }
        self.client = httpx.Client(timeout=30.0)
        logger.info("✅ Cliente Supabase manual inicializado")
        logger.info(f"🔑 JWT Secret configurado: {self.jwt_secret[:20]}...")
    
    def with_token(self, token: str):
        """Crear una nueva instancia con un token de usuario validado"""
        
        # ✅ VALIDACIÓN DEL TOKEN JWT
        try:
            # Decodificar y verificar el token
            payload = jwt.decode(
                token, 
                self.jwt_secret, 
                algorithms=[settings.jwt_algorithm],
                options={"verify_signature": True, "verify_exp": True}
            )
            
            # Verificar que el token contiene userId
            user_id = payload.get("userId")
            if not user_id:
                logger.error("❌ Token no contiene userId")
                raise ValueError("Token inválido: no contiene userId")
            
            # Verificar expiración (jwt.decode ya lo hace, pero verificamos manualmente)
            exp = payload.get("exp")
            if exp:
                exp_time = datetime.fromtimestamp(exp)
                now = datetime.now()
                if exp_time < now:
                    logger.error(f"❌ Token expirado desde: {exp_time}")
                    raise ValueError("Token expirado")
            
            logger.info(f"✅ Token válido para usuario: {user_id}")
            logger.info(f"📧 Email: {payload.get('email', 'No email')}")
            logger.info(f"🔑 Expira: {datetime.fromtimestamp(exp) if exp else 'No expira'}")
            
        except jwt.ExpiredSignatureError:
            logger.error("❌ Token expirado")
            raise ValueError("Token expirado")
        except jwt.InvalidTokenError as e:
            logger.error(f"❌ Token inválido: {e}")
            raise ValueError(f"Token inválido: {e}")
        except Exception as e:
            logger.error(f"❌ Error validando token: {e}")
            raise
        
        # Crear headers con el token
        headers = self.base_headers.copy()
        headers["Authorization"] = f"Bearer {token}"
        headers["Prefer"] = "return=representation"
        
        logger.info(f"🔑 Cliente con token creado - Headers: {list(headers.keys())}")
        return SupabaseClientWithToken(self, headers, token)

class SupabaseClientWithToken:
    def __init__(self, parent: SupabaseClient, headers: Dict, token: str):
        self.parent = parent
        self.headers = headers
        self.token = token
        self.client = parent.client
    
    def table(self, table_name: str):
        """Obtener un manejador para una tabla con el token del usuario"""
        return TableQueryWithToken(self, table_name)

class TableQueryWithToken:
    def __init__(self, client: SupabaseClientWithToken, table_name: str):
        self.client = client
        self.table_name = table_name
        self.base_url = f"{client.parent.url}/rest/v1/{table_name}"
        self.params: Dict[str, str] = {}
    
    def select(self, columns: str = "*"):
        """Seleccionar columnas"""
        self.params["select"] = columns
        return self
    
    def eq(self, column: str, value: Any):
        """Filtro de igualdad"""
        self.params[f"{column}"] = f"eq.{value}"
        return self
    
    def not_eq(self, column: str, value: Any):
        """Filtro de no igualdad"""
        self.params[f"{column}"] = f"neq.{value}"
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
        """Ordenar resultados"""
        direction = "desc" if desc else "asc"
        self.params["order"] = f"{column}.{direction}"
        return self
    
    def execute(self) -> List[Dict[str, Any]]:
        """Ejecutar la consulta SELECT"""
        try:
            logger.info(f"📤 Ejecutando SELECT en {self.table_name}")
            logger.info(f"📦 Headers: {list(self.client.headers.keys())}")
            logger.info(f"🔍 Params: {self.params}")
            
            response = self.client.client.get(
                self.base_url,
                headers=self.client.headers,
                params=self.params
            )
            response.raise_for_status()
            result = response.json()
            logger.info(f"✅ SELECT completado: {len(result)} registros")
            return result
        except httpx.HTTPStatusError as e:
            logger.error(f"❌ Error en consulta: {e.response.status_code}")
            logger.error(f"📄 Respuesta: {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            raise
    
    def insert(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Insertar un registro"""
        try:
            logger.info(f"📤 Insertando en {self.table_name}")
            logger.info(f"📦 Headers: {list(self.client.headers.keys())}")
            logger.info(f"📝 Data: {data}")
            
            response = self.client.client.post(
                self.base_url,
                headers=self.client.headers,
                json=data
            )
            response.raise_for_status()
            result = response.json()
            logger.info(f"✅ Insert completado: {result}")
            return result
        except httpx.HTTPStatusError as e:
            logger.error(f"❌ Error al insertar: {e.response.status_code}")
            logger.error(f"📄 Respuesta: {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            raise
    
    def update(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Actualizar registros"""
        try:
            logger.info(f"📤 Actualizando en {self.table_name}")
            logger.info(f"🔍 Params: {self.params}")
            response = self.client.client.patch(
                self.base_url,
                headers=self.client.headers,
                params=self.params,
                json=data
            )
            response.raise_for_status()
            result = response.json()
            logger.info(f"✅ Update completado")
            return result
        except httpx.HTTPStatusError as e:
            logger.error(f"❌ Error al actualizar: {e.response.status_code}")
            logger.error(f"📄 Respuesta: {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            raise
    
    def delete(self) -> List[Dict[str, Any]]:
        """Eliminar registros"""
        try:
            logger.info(f"📤 Eliminando de {self.table_name}")
            logger.info(f"🔍 Params: {self.params}")
            response = self.client.client.delete(
                self.base_url,
                headers=self.client.headers,
                params=self.params
            )
            response.raise_for_status()
            result = response.json() if response.content else []
            logger.info(f"✅ Delete completado")
            return result
        except httpx.HTTPStatusError as e:
            logger.error(f"❌ Error al eliminar: {e.response.status_code}")
            logger.error(f"📄 Respuesta: {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            raise
    
    def upsert(self, data: Dict[str, Any], on_conflict: Optional[str] = None) -> List[Dict[str, Any]]:
        """Insertar o actualizar"""
        headers = self.client.headers.copy()
        headers["Prefer"] = "return=representation,resolution=merge-duplicates"
        
        params = {}
        if on_conflict:
            params["on_conflict"] = on_conflict
        
        try:
            logger.info(f"📤 Upsert en {self.table_name}")
            logger.info(f"🔍 Params: {params}")
            response = self.client.client.post(
                self.base_url,
                headers=headers,
                params=params,
                json=data if isinstance(data, list) else [data]
            )
            response.raise_for_status()
            result = response.json()
            logger.info(f"✅ Upsert completado")
            return result
        except httpx.HTTPStatusError as e:
            logger.error(f"❌ Error al upsert: {e.response.status_code}")
            logger.error(f"📄 Respuesta: {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            raise

# Instancia global (sin token)
supabase_client = SupabaseClient()
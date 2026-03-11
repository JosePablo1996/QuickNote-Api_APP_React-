import httpx
from app.config import settings
from typing import Optional, Dict, Any, List
import logging

# Configurar logger
logger = logging.getLogger(__name__)

class SupabaseClient:
    def __init__(self):
        self.url = settings.supabase_url
        self.key = settings.supabase_key
        self.base_headers = {
            "apikey": self.key,
            "Content-Type": "application/json",
        }
        self.client = httpx.Client(timeout=30.0)
        logger.info("=" * 50)
        logger.info("✅ Cliente Supabase manual inicializado")
        logger.info(f"🔑 API Key configurada: {self.key[:20]}...")
        logger.info(f"🌐 URL: {self.url}")
        logger.info("=" * 50)
    
    def with_token(self, token: str):
        """Crear una nueva instancia con un token de usuario"""
        headers = self.base_headers.copy()
        # ✅ El token debe ir en el header Authorization, NO en apikey
        headers["Authorization"] = f"Bearer {token}"
        headers["Prefer"] = "return=representation"
        
        logger.info("=" * 50)
        logger.info(f"🔑 Cliente con token creado")
        logger.info(f"📦 Token (primeros 50): {token[:50]}...")
        logger.info(f"📦 Headers configurados: {list(headers.keys())}")
        logger.info(f"🔐 Authorization header: {headers['Authorization'][:70]}...")
        logger.info("=" * 50)
        
        return SupabaseClientWithToken(self, headers, token)

class SupabaseClientWithToken:
    def __init__(self, parent: SupabaseClient, headers: Dict, token: str):
        self.parent = parent
        self.headers = headers
        self.token = token
        self.client = parent.client
    
    def table(self, table_name: str):
        """Obtener un manejador para una tabla con el token del usuario"""
        logger.info(f"📋 Accediendo a tabla: {table_name}")
        return TableQueryWithToken(self, table_name)

class TableQueryWithToken:
    def __init__(self, client: SupabaseClientWithToken, table_name: str):
        self.client = client
        self.table_name = table_name
        self.base_url = f"{client.parent.url}/rest/v1/{table_name}"
        self.params: Dict[str, str] = {}
        self.data: Optional[Dict] = None
    
    def select(self, columns: str = "*"):
        self.params["select"] = columns
        logger.info(f"🔍 SELECT {columns} FROM {self.table_name}")
        return self
    
    def eq(self, column: str, value: Any):
        self.params[f"{column}"] = f"eq.{value}"
        logger.info(f"📌 Filtro: {column} = {value}")
        return self
    
    def is_null(self, column: str):
        self.params[f"{column}"] = "is.null"
        logger.info(f"📌 Filtro: {column} IS NULL")
        return self
    
    def is_not_null(self, column: str):
        self.params[f"{column}"] = "not.is.null"
        logger.info(f"📌 Filtro: {column} IS NOT NULL")
        return self
    
    def order(self, column: str, desc: bool = False):
        direction = "desc" if desc else "asc"
        self.params["order"] = f"{column}.{direction}"
        logger.info(f"📌 Orden: {column} {direction}")
        return self
    
    def update(self, data: Dict[str, Any]):
        """Preparar actualización de datos"""
        self.data = data
        logger.info(f"✏️ Preparando UPDATE en {self.table_name}")
        logger.info(f"📦 Datos a actualizar: {data}")
        return self
    
    def delete(self):
        """Preparar eliminación de datos"""
        logger.info(f"🗑️ Preparando DELETE en {self.table_name}")
        return self
    
    def upsert(self, data: Dict[str, Any]):
        """Preparar upsert de datos"""
        self.data = data
        self.params["on_conflict"] = "id"
        logger.info(f"🔄 Preparando UPSERT en {self.table_name}")
        logger.info(f"📦 Datos a upsert: {data}")
        return self
    
    def execute(self) -> List[Dict[str, Any]]:
        """Ejecutar la consulta"""
        try:
            logger.info("=" * 50)
            logger.info(f"📤 Ejecutando operación en {self.table_name}")
            logger.info(f"🌐 URL: {self.base_url}")
            logger.info(f"📦 Headers: {list(self.client.headers.keys())}")
            logger.info(f"📊 Parámetros: {self.params}")
            
            # Determinar el método HTTP basado en los datos
            if self.data is not None:
                # Si hay datos, es POST (insert) o PATCH (update)
                if hasattr(self, '_method') and self._method == 'PATCH':
                    # Es una actualización
                    logger.info("📤 Método: PATCH (UPDATE)")
                    response = self.client.client.patch(
                        self.base_url,
                        headers=self.client.headers,
                        params=self.params,
                        json=self.data
                    )
                elif hasattr(self, '_method') and self._method == 'DELETE':
                    # Es una eliminación
                    logger.info("📤 Método: DELETE")
                    response = self.client.client.delete(
                        self.base_url,
                        headers=self.client.headers,
                        params=self.params
                    )
                else:
                    # Es un insert
                    logger.info("📤 Método: POST (INSERT)")
                    response = self.client.client.post(
                        self.base_url,
                        headers=self.client.headers,
                        params=self.params,
                        json=self.data
                    )
            else:
                # Si no hay datos, es GET (select)
                logger.info("📤 Método: GET (SELECT)")
                response = self.client.client.get(
                    self.base_url,
                    headers=self.client.headers,
                    params=self.params
                )
            
            logger.info(f"📥 Código de respuesta: {response.status_code}")
            
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"✅ Operación completada exitosamente")
            logger.info(f"📦 Resultados: {len(result) if result else 0} registros")
            logger.info("=" * 50)
            
            return result
            
        except httpx.HTTPStatusError as e:
            logger.error(f"❌ Error HTTP: {e.response.status_code}")
            logger.error(f"📄 Respuesta: {e.response.text}")
            logger.error(f"🔍 URL: {e.request.url}")
            logger.error(f"📦 Headers enviados: {dict(e.request.headers)}")
            logger.exception("📝 Stacktrace completo:")
            raise
        except Exception as e:
            logger.error(f"❌ Error inesperado: {str(e)}")
            logger.exception("📝 Stacktrace completo:")
            raise
    
    def insert(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Insertar un registro"""
        self.data = data
        logger.info(f"📝 INSERT en {self.table_name}")
        logger.info(f"📦 Datos a insertar: {data}")
        return self.execute()
    
    # Métodos auxiliares para encadenar
    def _set_method(self, method: str):
        self._method = method
        return self

# Instancia global
supabase_client = SupabaseClient()
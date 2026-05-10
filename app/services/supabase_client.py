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
        # El token debe ir en el header Authorization, NO en apikey
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
        self._method: str = 'GET'
    
    def select(self, columns: str = "*"):
        """Seleccionar columnas"""
        self.params["select"] = columns
        self._method = 'GET'
        logger.info(f"🔍 SELECT {columns} FROM {self.table_name}")
        return self
    
    def eq(self, column: str, value: Any):
        """Filtro de igualdad"""
        self.params[f"{column}"] = f"eq.{value}"
        logger.info(f"📌 Filtro: {column} = {value}")
        return self
    
    def is_null(self, column: str):
        """Filtro IS NULL"""
        self.params[f"{column}"] = "is.null"
        logger.info(f"📌 Filtro: {column} IS NULL")
        return self
    
    def is_not_null(self, column: str):
        """Filtro IS NOT NULL"""
        self.params[f"{column}"] = "not.is.null"
        logger.info(f"📌 Filtro: {column} IS NOT NULL")
        return self
    
    def order(self, column: str, desc: bool = False):
        """Ordenar resultados"""
        direction = "desc" if desc else "asc"
        self.params["order"] = f"{column}.{direction}"
        logger.info(f"📌 Orden: {column} {direction}")
        return self
    
    def insert(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Insertar un registro.
        ✅ Ejecuta automáticamente y devuelve la lista de resultados.
        """
        self.data = data
        self._method = 'POST'
        logger.info(f"📝 INSERT en {self.table_name}")
        logger.info(f"📦 Datos a insertar: {data}")
        return self.execute()
    
    def update(self, data: Dict[str, Any]):
        """
        Preparar actualización de datos.
        ⚠️ NO ejecuta automáticamente - requiere filtros y luego .execute()
        """
        self.data = data
        self._method = 'PATCH'
        logger.info(f"✏️ UPDATE en {self.table_name}")
        logger.info(f"📦 Datos a actualizar: {data}")
        return self
    
    def delete(self):
        """
        Preparar eliminación de datos.
        ⚠️ NO ejecuta automáticamente - requiere filtros y luego .execute()
        """
        self._method = 'DELETE'
        logger.info(f"🗑️ DELETE en {self.table_name}")
        return self
    
    def upsert(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Insertar o actualizar un registro.
        ✅ Ejecuta automáticamente y devuelve la lista de resultados.
        """
        self.data = data
        self._method = 'UPSERT'
        self.params["on_conflict"] = "id"
        logger.info(f"🔄 UPSERT en {self.table_name}")
        logger.info(f"📦 Datos a upsert: {data}")
        return self.execute()
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Ejecutar la consulta construida.
        ✅ Devuelve una lista de diccionarios con los resultados.
        """
        try:
            logger.info("=" * 50)
            logger.info(f"📤 Ejecutando operación en {self.table_name}")
            logger.info(f"🌐 URL: {self.base_url}")
            logger.info(f"📦 Headers: {list(self.client.headers.keys())}")
            logger.info(f"📊 Parámetros: {self.params}")
            
            method = self._method or 'GET'
            
            if method in ('POST', 'UPSERT'):
                logger.info(f"📤 Método: POST")
                response = self.client.client.post(
                    self.base_url,
                    headers=self.client.headers,
                    params=self.params,
                    json=self.data
                )
            elif method == 'PATCH':
                logger.info(f"📤 Método: PATCH")
                response = self.client.client.patch(
                    self.base_url,
                    headers=self.client.headers,
                    params=self.params,
                    json=self.data
                )
            elif method == 'DELETE':
                logger.info(f"📤 Método: DELETE")
                response = self.client.client.delete(
                    self.base_url,
                    headers=self.client.headers,
                    params=self.params
                )
            else:
                logger.info(f"📤 Método: GET")
                response = self.client.client.get(
                    self.base_url,
                    headers=self.client.headers,
                    params=self.params
                )
            
            logger.info(f"📥 Código de respuesta: {response.status_code}")
            
            response.raise_for_status()
            
            # Para DELETE, no hay cuerpo en la respuesta
            if method == 'DELETE':
                logger.info(f"✅ Operación DELETE completada exitosamente")
                logger.info("=" * 50)
                return [{"deleted": True}]
            
            result = response.json()
            logger.info(f"✅ Operación completada exitosamente")
            logger.info(f"📦 Resultados: {len(result) if isinstance(result, list) else 1} registros")
            logger.info("=" * 50)
            
            # Asegurar que siempre devolvemos una lista
            if isinstance(result, list):
                return result
            else:
                return [result]
            
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


# ✅ Instancia global del cliente
supabase_client = SupabaseClient()
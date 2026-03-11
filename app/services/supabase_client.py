import httpx
from app.config import settings
from typing import Optional, Dict, Any, List
import logging

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
        logger.info("✅ Cliente Supabase manual inicializado")
        logger.info(f"🔑 API Key configurada: {self.key[:20]}...")
    
    def with_token(self, token: str):
        """Crear una nueva instancia con un token de usuario"""
        headers = self.base_headers.copy()
        # ✅ El token debe ir en el header Authorization, NO en apikey
        headers["Authorization"] = f"Bearer {token}"
        headers["Prefer"] = "return=representation"
        logger.info(f"🔑 Cliente con token creado - Token: {token[:20]}...")
        logger.info(f"📦 Headers: {list(headers.keys())}")
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
        self.params["select"] = columns
        return self
    
    def eq(self, column: str, value: Any):
        self.params[f"{column}"] = f"eq.{value}"
        return self
    
    def is_null(self, column: str):
        self.params[f"{column}"] = "is.null"
        return self
    
    def is_not_null(self, column: str):
        self.params[f"{column}"] = "not.is.null"
        return self
    
    def order(self, column: str, desc: bool = False):
        direction = "desc" if desc else "asc"
        self.params["order"] = f"{column}.{direction}"
        return self
    
    def execute(self) -> List[Dict[str, Any]]:
        """Ejecutar la consulta SELECT"""
        try:
            logger.info(f"📤 Ejecutando SELECT en {self.table_name}")
            response = self.client.client.get(
                self.base_url,
                headers=self.client.headers,
                params=self.params
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"❌ Error en consulta: {e.response.status_code}")
            logger.error(f"📄 Respuesta: {e.response.text}")
            raise
    
    def insert(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Insertar un registro"""
        try:
            logger.info(f"📤 Insertando en {self.table_name}")
            response = self.client.client.post(
                self.base_url,
                headers=self.client.headers,
                json=data
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"❌ Error al insertar: {e.response.status_code}")
            logger.error(f"📄 Respuesta: {e.response.text}")
            raise

# Instancia global
supabase_client = SupabaseClient()
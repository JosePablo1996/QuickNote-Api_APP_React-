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
    
    def with_token(self, token: str):
        """Crear una nueva instancia con un token de usuario"""
        headers = self.base_headers.copy()
        headers["Authorization"] = f"Bearer {token}"
        headers["Prefer"] = "return=representation"
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
    
    def order(self, column: str, desc: bool = False):
        """Ordenar resultados"""
        direction = "desc" if desc else "asc"
        self.params["order"] = f"{column}.{direction}"
        return self
    
    def limit(self, limit: int):
        """Limitar resultados"""
        self.params["limit"] = str(limit)
        return self
    
    def execute(self) -> List[Dict[str, Any]]:
        """Ejecutar la consulta SELECT"""
        try:
            response = self.client.client.get(
                self.base_url,
                headers=self.client.headers,
                params=self.params
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"Error en consulta: {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"Error: {e}")
            raise
    
    def insert(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Insertar un registro"""
        try:
            response = self.client.client.post(
                self.base_url,
                headers=self.client.headers,
                json=data
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"Error al insertar: {e.response.text}")
            raise
    
    def update(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Actualizar registros"""
        try:
            response = self.client.client.patch(
                self.base_url,
                headers=self.client.headers,
                params=self.params,
                json=data
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"Error al actualizar: {e.response.text}")
            raise
    
    def delete(self) -> List[Dict[str, Any]]:
        """Eliminar registros"""
        try:
            response = self.client.client.delete(
                self.base_url,
                headers=self.client.headers,
                params=self.params
            )
            response.raise_for_status()
            # DELETE puede devolver 204 sin contenido
            return response.json() if response.content else []
        except httpx.HTTPStatusError as e:
            logger.error(f"Error al eliminar: {e.response.text}")
            raise
    
    def upsert(self, data: Dict[str, Any], on_conflict: Optional[str] = None) -> List[Dict[str, Any]]:
        """Insertar o actualizar"""
        headers = self.client.headers.copy()
        headers["Prefer"] = "return=representation,resolution=merge-duplicates"
        
        params = {}
        if on_conflict:
            params["on_conflict"] = on_conflict
        
        try:
            response = self.client.client.post(
                self.base_url,
                headers=headers,
                params=params,
                json=data if isinstance(data, list) else [data]
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"Error al upsert: {e.response.text}")
            raise

# Instancia global (sin token)
supabase_client = SupabaseClient()
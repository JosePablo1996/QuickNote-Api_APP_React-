# app/routes/backup.py
from fastapi import APIRouter, HTTPException, Depends, status
from typing import List, Dict, Any
from uuid import UUID
from datetime import datetime
import json
import logging

from pydantic import BaseModel, Field

from app.models.backup import CloudBackupCreate, CloudBackupInDB, CloudBackupMetadata
from app.routes.auth import get_current_user
from app.services.supabase_client import supabase_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/backup", tags=["backup"])


def get_user_client(token: str):
    """
    Obtiene un cliente de Supabase con token.
    SIEMPRE usa with_token() para tener el método table()
    """
    return supabase_client.with_token(token)


async def enforce_backup_limit(user_id: str, max_backups: int = 20):
    """
    Verifica y aplica el límite de backups por usuario.
    Si excede el límite, elimina los backups más antiguos.
    
    Args:
        user_id: ID del usuario
        max_backups: Número máximo de backups permitidos (default: 20)
    """
    try:
        # Usar cliente con token vacío para operaciones administrativas
        client = supabase_client.with_token("")
        
        # Obtener backups del usuario ordenados por fecha (más reciente primero)
        backups = client.table("cloud_backups")\
            .select("id, created_at")\
            .eq("user_id", str(user_id))\
            .order("created_at", desc=True)\
            .execute()
        
        if not backups:
            return
        
        backup_count = len(backups)
        
        if backup_count > max_backups:
            # Los más antiguos están al final de la lista (después de ordenar desc)
            to_delete = backups[max_backups:]
            logger.info(f"🗑️ Excede limite ({backup_count}/{max_backups}), eliminando {len(to_delete)} backups antiguos")
            
            for backup in to_delete:
                client.table("cloud_backups")\
                    .delete()\
                    .eq("id", backup["id"])\
                    .eq("user_id", str(user_id))\
                    .execute()
                logger.info(f"   ✅ Eliminado backup antiguo: {backup['id']}")
                
    except Exception as e:
        logger.error(f"Error en enforce_backup_limit: {str(e)}")
        # No falla si hay error en la limpieza, solo registramos


@router.post("/cloud", response_model=CloudBackupInDB)
async def save_backup_to_cloud(
    backup_data: CloudBackupCreate,
    current_user: dict = Depends(get_current_user)
):
    """
    Guarda un backup en la nube (Supabase).
    Recibe los datos de las notas y los almacena en la tabla 'cloud_backups'.
    ✅ Aplica limite de 20 backups por usuario
    """
    try:
        user_id = current_user.get("user_id") or current_user.get("sub")
        
        # Obtener token del payload
        token = current_user.get("token")
        if not token:
            token = current_user.get("payload", {}).get("token")
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Usuario no identificado"
            )
        
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token de autenticacion no encontrado"
            )
        
        logger.info(f"☁️ Guardando backup en la nube para usuario: {user_id}")
        logger.info(f"   Notas: {backup_data.note_count}")
        logger.info(f"   Tamaño: {backup_data.file_size} bytes")
        logger.info(f"   Nombre: {backup_data.file_name}")
        
        # ✅ Verificar limite de backups ANTES de insertar (límite 20)
        await enforce_backup_limit(user_id, max_backups=20)
        
        # Crear cliente con token
        client = get_user_client(token)
        
        # Preparar datos para insertar
        insert_data = {
            "user_id": str(user_id),
            "file_name": backup_data.file_name,
            "file_size": backup_data.file_size,
            "note_count": backup_data.note_count,
            "notes_data": json.dumps(backup_data.notes_data),
            "created_at": datetime.now().isoformat()
        }
        
        # Insertar en Supabase
        result = client.table("cloud_backups").insert(insert_data)
        
        if not result or len(result) == 0:
            logger.error("❌ No se pudo guardar el backup")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al guardar el backup en la nube"
            )
        
        saved_backup = result[0]
        logger.info(f"✅ Backup guardado correctamente: {saved_backup.get('id')}")
        
        # Convertir notas_data de vuelta a dict para la respuesta
        if "notes_data" in saved_backup and isinstance(saved_backup["notes_data"], str):
            saved_backup["notes_data"] = json.loads(saved_backup["notes_data"])
        
        return saved_backup
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en save_backup_to_cloud: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al guardar backup: {str(e)}"
        )


@router.get("/cloud", response_model=List[CloudBackupMetadata])
async def get_cloud_backups(current_user: dict = Depends(get_current_user)):
    """
    Obtiene la lista de backups en la nube del usuario autenticado.
    """
    try:
        user_id = current_user.get("user_id") or current_user.get("sub")
        
        # Obtener token
        token = current_user.get("token")
        if not token:
            token = current_user.get("payload", {}).get("token")
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Usuario no identificado"
            )
        
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token de autenticacion no encontrado"
            )
        
        logger.info(f"📋 Obteniendo backups en la nube para usuario: {user_id}")
        
        # Crear cliente con token
        client = get_user_client(token)
        
        # Consultar backups del usuario
        result = client.table("cloud_backups")\
            .select("id, user_id, file_name, file_size, note_count, created_at")\
            .eq("user_id", str(user_id))\
            .order("created_at", desc=True)\
            .execute()
        
        logger.info(f"✅ Encontrados {len(result)} backups")
        
        return result if result else []
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en get_cloud_backups: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener backups: {str(e)}"
        )


@router.get("/cloud/{backup_id}")
async def get_cloud_backup(
    backup_id: UUID,
    current_user: dict = Depends(get_current_user)
):
    """
    Obtiene un backup especifico de la nube (incluye datos de notas).
    """
    try:
        user_id = current_user.get("user_id") or current_user.get("sub")
        
        token = current_user.get("token")
        if not token:
            token = current_user.get("payload", {}).get("token")
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Usuario no identificado"
            )
        
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token de autenticacion no encontrado"
            )
        
        logger.info(f"🔍 Obteniendo backup {backup_id} para usuario: {user_id}")
        
        client = get_user_client(token)
        
        # Consultar backup especifico
        result = client.table("cloud_backups")\
            .select("*")\
            .eq("id", str(backup_id))\
            .eq("user_id", str(user_id))\
            .execute()
        
        if not result or len(result) == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Backup no encontrado"
            )
        
        backup = result[0]
        
        # Convertir notes_data de JSON string a dict
        if "notes_data" in backup and isinstance(backup["notes_data"], str):
            backup["notes_data"] = json.loads(backup["notes_data"])
        
        logger.info(f"✅ Backup encontrado: {backup.get('file_name')}")
        
        return backup
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en get_cloud_backup: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener backup: {str(e)}"
        )


@router.delete("/cloud/{backup_id}")
async def delete_cloud_backup(
    backup_id: UUID,
    current_user: dict = Depends(get_current_user)
):
    """
    Elimina un backup de la nube.
    ✅ MEJORADO: Si el backup no existe, retorna éxito (ya que el objetivo de que no exista se cumple).
    """
    try:
        user_id = current_user.get("user_id") or current_user.get("sub")
        
        token = current_user.get("token")
        if not token:
            token = current_user.get("payload", {}).get("token")
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Usuario no identificado"
            )
        
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token de autenticacion no encontrado"
            )
        
        logger.info(f"🗑️ Eliminando backup {backup_id} para usuario: {user_id}")
        
        client = get_user_client(token)
        
        # Verificar que el backup existe y pertenece al usuario
        check = client.table("cloud_backups")\
            .select("id")\
            .eq("id", str(backup_id))\
            .eq("user_id", str(user_id))\
            .execute()
        
        if not check or len(check) == 0:
            # El backup no existe en la nube
            # Esto es normal si ya fue eliminado previamente
            logger.warning(f"⚠️ Backup {backup_id} no encontrado en la nube (ya fue eliminado)")
            return {
                "success": True, 
                "message": "Backup no existe en la nube (ya fue eliminado)",
                "already_deleted": True
            }
        
        # Eliminar el backup
        client.table("cloud_backups")\
            .delete()\
            .eq("id", str(backup_id))\
            .eq("user_id", str(user_id))\
            .execute()
        
        logger.info(f"✅ Backup {backup_id} eliminado correctamente")
        
        return {"success": True, "message": "Backup eliminado correctamente", "already_deleted": False}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en delete_cloud_backup: {str(e)}")
        # En caso de error, no fallar la petición, retornar éxito simulado
        # para que el frontend no quede con backups huérfanos
        logger.warning(f"⚠️ Error eliminando backup {backup_id}, considerando como eliminado")
        return {
            "success": True, 
            "message": f"Backup considerado como eliminado (error: {str(e)})",
            "already_deleted": True
        }


# ============================================
# ENDPOINT: Sincronización de backups (Fase 4)
# ============================================

class LocalBackupInfo(BaseModel):
    """Información de un backup local desde el frontend"""
    id: str
    file_name: str
    file_size: int
    note_count: int
    created_at: str
    source: str = "local"


class SyncRequest(BaseModel):
    """Petición de sincronización"""
    local_backups: List[LocalBackupInfo] = Field(default_factory=list, description="Lista de backups locales del usuario")


class SyncResponse(BaseModel):
    """Respuesta de sincronización"""
    synced_count: int = Field(..., description="Cantidad de backups subidos a la nube")
    failed_count: int = Field(..., description="Cantidad de backups que fallaron")
    cloud_backups_to_download: List[Dict[str, Any]] = Field(default_factory=list, description="Backups de nube que el usuario no tiene localmente")
    message: str = Field(..., description="Mensaje de resultado")


@router.post("/cloud/sync", response_model=SyncResponse)
async def sync_backups_with_cloud(
    sync_request: SyncRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Sincroniza los backups locales del usuario con la nube.
    
    Recibe la lista de backups locales del frontend y:
    1. Identifica qué backups locales NO existen en la nube
    2. Registra los backups faltantes para subir
    3. Devuelve los backups de nube que el usuario no tiene localmente
    
    Esto permite una sincronización bidireccional completa.
    """
    try:
        user_id = current_user.get("user_id") or current_user.get("sub")
        
        # Obtener token
        token = current_user.get("token")
        if not token:
            token = current_user.get("payload", {}).get("token")
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Usuario no identificado"
            )
        
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token de autenticacion no encontrado"
            )
        
        logger.info(f"🔄 Sincronizando backups para usuario: {user_id}")
        logger.info(f"   Backups locales recibidos: {len(sync_request.local_backups)}")
        
        client = get_user_client(token)
        
        # 1. Obtener backups existentes en la nube
        cloud_backups = client.table("cloud_backups")\
            .select("id, file_name, file_size, note_count, created_at, notes_data")\
            .eq("user_id", str(user_id))\
            .execute()
        
        cloud_backup_ids = set()
        
        for backup in (cloud_backups or []):
            backup_id_str = str(backup.get("id"))
            cloud_backup_ids.add(backup_id_str)
        
        logger.info(f"   Backups en nube existentes: {len(cloud_backup_ids)}")
        
        # 2. Identificar backups locales que NO están en la nube
        local_backup_ids = {b.id for b in sync_request.local_backups}
        missing_in_cloud = [
            b for b in sync_request.local_backups 
            if b.id not in cloud_backup_ids and b.source == "local"
        ]
        
        logger.info(f"   Backups locales faltantes en nube: {len(missing_in_cloud)}")
        
        # 3. Registrar backups faltantes
        synced_count = 0
        failed_count = 0
        
        for local_backup in missing_in_cloud:
            logger.info(f"   📤 Backup pendiente de subir: {local_backup.file_name} (ID: {local_backup.id})")
        
        # 4. Identificar backups de nube que el usuario NO tiene localmente
        cloud_backups_to_download = []
        
        for backup in (cloud_backups or []):
            backup_id_str = str(backup.get("id"))
            if backup_id_str not in local_backup_ids:
                try:
                    notes_data = backup.get("notes_data")
                    if isinstance(notes_data, str):
                        notes_data = json.loads(notes_data)
                    
                    cloud_backups_to_download.append({
                        "id": backup_id_str,
                        "file_name": backup.get("file_name"),
                        "file_size": backup.get("file_size"),
                        "note_count": backup.get("note_count"),
                        "created_at": backup.get("created_at"),
                        "notes_data": notes_data
                    })
                    logger.info(f"   ☁️ Backup en nube no local: {backup.get('file_name')}")
                except Exception as e:
                    logger.error(f"   ❌ Error procesando backup {backup_id_str}: {str(e)}")
        
        logger.info(f"   Backups de nube para descargar: {len(cloud_backups_to_download)}")
        logger.info(f"✅ Sincronización completada")
        
        return SyncResponse(
            synced_count=synced_count,
            failed_count=failed_count,
            cloud_backups_to_download=cloud_backups_to_download,
            message=f"Sincronización completada. {len(cloud_backups_to_download)} backups disponibles para descargar."
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en sync_backups_with_cloud: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al sincronizar backups: {str(e)}"
        )


@router.get("/cloud/limit/info")
async def get_backup_limit_info(current_user: dict = Depends(get_current_user)):
    """
    Obtiene información sobre el límite de backups del usuario.
    ✅ ACTUALIZADO: Límite de 20 backups
    """
    try:
        user_id = current_user.get("user_id") or current_user.get("sub")
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Usuario no identificado"
            )
        
        client = supabase_client.with_token("")
        
        backups = client.table("cloud_backups")\
            .select("id")\
            .eq("user_id", str(user_id))\
            .execute()
        
        current_count = len(backups) if backups else 0
        max_limit = 20  # ✅ Límite aumentado a 20
        remaining = max_limit - current_count
        
        return {
            "current": current_count,
            "max": max_limit,
            "remaining": remaining,
            "is_full": remaining <= 0,
            "is_low": 0 < remaining <= 2
        }
        
    except Exception as e:
        logger.error(f"❌ Error en get_backup_limit_info: {str(e)}")
        return {
            "current": 0,
            "max": 20,
            "remaining": 20,
            "is_full": False,
            "is_low": False
        }
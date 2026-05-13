# app/routes/backup.py
from fastapi import APIRouter, HTTPException, Depends, status
from typing import List
from uuid import UUID
from datetime import datetime
import json
import logging

from app.models.backup import CloudBackupCreate, CloudBackupInDB, CloudBackupMetadata
from app.routes.auth import get_current_user
from app.services.supabase_client import supabase_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/backup", tags=["backup"])


def get_user_client(token: str):
    """Obtener cliente de Supabase con token del usuario"""
    return supabase_client.with_token(token)


@router.post("/cloud", response_model=CloudBackupInDB)
async def save_backup_to_cloud(
    backup_data: CloudBackupCreate,
    current_user: dict = Depends(get_current_user)
):
    """
    Guarda un backup en la nube (Supabase).
    Recibe los datos de las notas y los almacena en la tabla 'cloud_backups'.
    """
    try:
        user_id = current_user.get("user_id") or current_user.get("sub")
        token = current_user.get("token") if "token" in current_user else None
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Usuario no identificado"
            )
        
        logger.info(f"☁️ Guardando backup en la nube para usuario: {user_id}")
        logger.info(f"   Notas: {backup_data.note_count}")
        logger.info(f"   Tamaño: {backup_data.file_size} bytes")
        logger.info(f"   Nombre: {backup_data.file_name}")
        
        # Crear cliente con token si está disponible
        if token:
            client = get_user_client(token)
        else:
            client = supabase_client
        
        # Preparar datos para insertar
        insert_data = {
            "user_id": str(user_id),
            "file_name": backup_data.file_name,
            "file_size": backup_data.file_size,
            "note_count": backup_data.note_count,
            "notes_data": json.dumps(backup_data.notes_data),  # Convertir a JSON string
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
        token = current_user.get("token") if "token" in current_user else None
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Usuario no identificado"
            )
        
        logger.info(f"📋 Obteniendo backups en la nube para usuario: {user_id}")
        
        # Crear cliente con token
        if token:
            client = get_user_client(token)
        else:
            client = supabase_client
        
        # Consultar backups del usuario (solo metadatos, sin notes_data)
        result = client.table("cloud_backups")\
            .select("id, user_id, file_name, file_size, note_count, created_at")\
            .eq("user_id", str(user_id))\
            .order("created_at", desc=True)\
            .execute()
        
        logger.info(f"✅ Encontrados {len(result)} backups")
        
        return result if result else []
        
    except Exception as e:
        logger.error(f"❌ Error en get_cloud_backups: {str(e)}")
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
    Obtiene un backup específico de la nube (incluye datos de notas).
    """
    try:
        user_id = current_user.get("user_id") or current_user.get("sub")
        token = current_user.get("token") if "token" in current_user else None
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Usuario no identificado"
            )
        
        logger.info(f"🔍 Obteniendo backup {backup_id} para usuario: {user_id}")
        
        # Crear cliente con token
        if token:
            client = get_user_client(token)
        else:
            client = supabase_client
        
        # Consultar backup específico
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
    """
    try:
        user_id = current_user.get("user_id") or current_user.get("sub")
        token = current_user.get("token") if "token" in current_user else None
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Usuario no identificado"
            )
        
        logger.info(f"🗑️ Eliminando backup {backup_id} para usuario: {user_id}")
        
        # Crear cliente con token
        if token:
            client = get_user_client(token)
        else:
            client = supabase_client
        
        # Verificar que el backup existe y pertenece al usuario
        check = client.table("cloud_backups")\
            .select("id")\
            .eq("id", str(backup_id))\
            .eq("user_id", str(user_id))\
            .execute()
        
        if not check or len(check) == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Backup no encontrado"
            )
        
        # Eliminar el backup
        client.table("cloud_backups")\
            .delete()\
            .eq("id", str(backup_id))\
            .eq("user_id", str(user_id))\
            .execute()
        
        logger.info(f"✅ Backup {backup_id} eliminado correctamente")
        
        return {"success": True, "message": "Backup eliminado correctamente"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en delete_cloud_backup: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al eliminar backup: {str(e)}"
        )
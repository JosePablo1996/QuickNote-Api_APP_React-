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
    """
    Obtiene un cliente de Supabase con token.
    SIEMPRE usa with_token() para tener el método table()
    """
    return supabase_client.with_token(token)


async def enforce_backup_limit(user_id: str, max_backups: int = 10):
    """
    Verifica y aplica el límite de backups por usuario.
    Si excede el límite, elimina los backups más antiguos.
    
    Args:
        user_id: ID del usuario
        max_backups: Número máximo de backups permitidos (default: 10)
    """
    try:
        # Usar cliente con token vacío para operaciones administrativas
        # Nota: Esto requiere service role key para funcionar
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
    ✅ NUEVO: Aplica limite de 10 backups por usuario
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
        
        # ✅ NUEVO: Verificar limite de backups ANTES de insertar
        await enforce_backup_limit(user_id, max_backups=10)
        
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


@router.get("/cloud/limit/info")
async def get_backup_limit_info(current_user: dict = Depends(get_current_user)):
    """
    Obtiene información sobre el límite de backups del usuario.
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
        max_limit = 10
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
            "max": 10,
            "remaining": 10,
            "is_full": False,
            "is_low": False
        }
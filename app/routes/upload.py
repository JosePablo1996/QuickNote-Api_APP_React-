# app/routes/upload.py
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File
from fastapi.responses import JSONResponse
import logging
from datetime import datetime
import httpx
from app.routes.auth import get_current_user
from app.config import settings
from app.services.supabase_client import supabase_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/upload", tags=["upload"])

# Configuración de imágenes
ALLOWED_IMAGE_TYPES = {
    "image/jpeg": ".jpg",
    "image/png": ".png", 
    "image/webp": ".webp",
    "image/jpg": ".jpg"
}

MAX_AVATAR_SIZE = 5 * 1024 * 1024  # 5MB
MAX_BANNER_SIZE = 10 * 1024 * 1024  # 10MB


@router.post("/avatar")
async def upload_avatar(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    """
    Sube una imagen de avatar para el usuario actual.
    """
    try:
        user_id = current_user.get("user_id") or current_user.get("sub")
        
        if not user_id:
            raise HTTPException(status_code=400, detail="Usuario no identificado")
        
        # Validar tipo de archivo
        if file.content_type not in ALLOWED_IMAGE_TYPES:
            raise HTTPException(
                status_code=400,
                detail=f"Tipo de archivo no permitido. Permitidos: {', '.join(ALLOWED_IMAGE_TYPES.keys())}"
            )
        
        # Validar tamaño
        content = await file.read()
        if len(content) > MAX_AVATAR_SIZE:
            raise HTTPException(
                status_code=400,
                detail=f"Archivo demasiado grande. Máximo: 5MB"
            )
        
        # Generar nombre único
        timestamp = int(datetime.now().timestamp() * 1000)
        extension = ALLOWED_IMAGE_TYPES[file.content_type]
        filename = f"avatar-{timestamp}{extension}"
        file_path = f"{user_id}/{filename}"
        
        # Subir a Supabase Storage
        storage_url = f"{settings.supabase_url}/storage/v1/object/avatars/{file_path}"
        
        logger.info(f"📤 Subiendo avatar para usuario {user_id}: {filename}")
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                storage_url,
                headers={
                    "apikey": settings.supabase_key,
                    "Authorization": f"Bearer {settings.supabase_service_role_key}",
                    "Content-Type": file.content_type
                },
                content=content
            )
            
            if response.status_code not in (200, 201):
                logger.error(f"Error subiendo avatar: {response.status_code} - {response.text}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Error al subir archivo a storage"
                )
        
        # Obtener URL pública
        public_url = f"{settings.supabase_url}/storage/v1/object/public/avatars/{file_path}"
        
        # Actualizar perfil del usuario
        client_supabase = supabase_client.with_service_role()
        result = client_supabase.table("profiles")\
            .update({
                "avatar_url": public_url,
                "updated_at": datetime.now().isoformat()
            })\
            .eq("id", user_id)\
            .execute()
        
        logger.info(f"✅ Avatar actualizado para usuario {user_id}")
        
        return {
            "success": True,
            "avatar_url": public_url,
            "message": "Avatar actualizado correctamente"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en upload_avatar: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error al subir avatar: {str(e)}")


@router.post("/banner")
async def upload_banner(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    """
    Sube una imagen de banner para el usuario actual.
    """
    try:
        user_id = current_user.get("user_id") or current_user.get("sub")
        
        if not user_id:
            raise HTTPException(status_code=400, detail="Usuario no identificado")
        
        # Validar tipo de archivo
        if file.content_type not in ALLOWED_IMAGE_TYPES:
            raise HTTPException(
                status_code=400,
                detail=f"Tipo de archivo no permitido. Permitidos: {', '.join(ALLOWED_IMAGE_TYPES.keys())}"
            )
        
        # Validar tamaño (banner puede ser más grande)
        content = await file.read()
        if len(content) > MAX_BANNER_SIZE:
            raise HTTPException(
                status_code=400,
                detail=f"Archivo demasiado grande. Máximo: 10MB"
            )
        
        # Generar nombre único
        timestamp = int(datetime.now().timestamp() * 1000)
        extension = ALLOWED_IMAGE_TYPES[file.content_type]
        filename = f"banner-{timestamp}{extension}"
        file_path = f"{user_id}/{filename}"
        
        # Subir a Supabase Storage
        storage_url = f"{settings.supabase_url}/storage/v1/object/banners/{file_path}"
        
        logger.info(f"📤 Subiendo banner para usuario {user_id}: {filename}")
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                storage_url,
                headers={
                    "apikey": settings.supabase_key,
                    "Authorization": f"Bearer {settings.supabase_service_role_key}",
                    "Content-Type": file.content_type
                },
                content=content
            )
            
            if response.status_code not in (200, 201):
                logger.error(f"Error subiendo banner: {response.status_code} - {response.text}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Error al subir archivo a storage"
                )
        
        # Obtener URL pública
        public_url = f"{settings.supabase_url}/storage/v1/object/public/banners/{file_path}"
        
        # Actualizar perfil del usuario
        client_supabase = supabase_client.with_service_role()
        result = client_supabase.table("profiles")\
            .update({
                "banner_url": public_url,
                "updated_at": datetime.now().isoformat()
            })\
            .eq("id", user_id)\
            .execute()
        
        logger.info(f"✅ Banner actualizado para usuario {user_id}")
        
        return {
            "success": True,
            "banner_url": public_url,
            "message": "Banner actualizado correctamente"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en upload_banner: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error al subir banner: {str(e)}")


@router.delete("/avatar")
async def delete_avatar(
    current_user: dict = Depends(get_current_user)
):
    """
    Elimina el avatar del usuario actual.
    """
    try:
        user_id = current_user.get("user_id") or current_user.get("sub")
        
        if not user_id:
            raise HTTPException(status_code=400, detail="Usuario no identificado")
        
        # Obtener avatar actual
        client_supabase = supabase_client.with_service_role()
        profile = client_supabase.table("profiles")\
            .select("avatar_url")\
            .eq("id", user_id)\
            .execute()
        
        current_avatar = profile[0].get("avatar_url") if profile and len(profile) > 0 else None
        
        # Eliminar de storage si existe
        if current_avatar:
            try:
                # Extraer path del archivo desde la URL
                if "/public/avatars/" in current_avatar:
                    file_path = current_avatar.split("/public/avatars/")[1]
                    storage_url = f"{settings.supabase_url}/storage/v1/object/avatars/{file_path}"
                    
                    async with httpx.AsyncClient() as client:
                        await client.delete(
                            storage_url,
                            headers={
                                "apikey": settings.supabase_key,
                                "Authorization": f"Bearer {settings.supabase_service_role_key}"
                            }
                        )
                    logger.info(f"🗑️ Avatar eliminado del storage: {file_path}")
            except Exception as e:
                logger.warning(f"Error eliminando archivo de storage: {e}")
        
        # Actualizar perfil (poner null)
        client_supabase.table("profiles")\
            .update({
                "avatar_url": None,
                "updated_at": datetime.now().isoformat()
            })\
            .eq("id", user_id)\
            .execute()
        
        logger.info(f"✅ Avatar eliminado para usuario {user_id}")
        
        return {
            "success": True,
            "message": "Avatar eliminado correctamente"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en delete_avatar: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error al eliminar avatar: {str(e)}")


@router.delete("/banner")
async def delete_banner(
    current_user: dict = Depends(get_current_user)
):
    """
    Elimina el banner del usuario actual.
    """
    try:
        user_id = current_user.get("user_id") or current_user.get("sub")
        
        if not user_id:
            raise HTTPException(status_code=400, detail="Usuario no identificado")
        
        # Obtener banner actual
        client_supabase = supabase_client.with_service_role()
        profile = client_supabase.table("profiles")\
            .select("banner_url")\
            .eq("id", user_id)\
            .execute()
        
        current_banner = profile[0].get("banner_url") if profile and len(profile) > 0 else None
        
        # Eliminar de storage si existe
        if current_banner:
            try:
                # Extraer path del archivo desde la URL
                if "/public/banners/" in current_banner:
                    file_path = current_banner.split("/public/banners/")[1]
                    storage_url = f"{settings.supabase_url}/storage/v1/object/banners/{file_path}"
                    
                    async with httpx.AsyncClient() as client:
                        await client.delete(
                            storage_url,
                            headers={
                                "apikey": settings.supabase_key,
                                "Authorization": f"Bearer {settings.supabase_service_role_key}"
                            }
                        )
                    logger.info(f"🗑️ Banner eliminado del storage: {file_path}")
            except Exception as e:
                logger.warning(f"Error eliminando archivo de storage: {e}")
        
        # Actualizar perfil (poner null)
        client_supabase.table("profiles")\
            .update({
                "banner_url": None,
                "updated_at": datetime.now().isoformat()
            })\
            .eq("id", user_id)\
            .execute()
        
        logger.info(f"✅ Banner eliminado para usuario {user_id}")
        
        return {
            "success": True,
            "message": "Banner eliminado correctamente"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en delete_banner: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error al eliminar banner: {str(e)}")
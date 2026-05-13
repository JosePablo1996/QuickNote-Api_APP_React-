# app/routes/__init__.py
from .notes import router as notes_router
from .passkeys import router as passkeys_router
from .auth import router as auth_router
from .backup import router as backup_router

__all__ = ["notes_router", "passkeys_router", "auth_router", "backup_router"]
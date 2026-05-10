from .notes import router as notes_router
from .passkeys import router as passkeys_router
from .auth import router as auth_router  # ✅ NUEVO

__all__ = ["notes_router", "passkeys_router", "auth_router"]  # ✅ auth_router agregado
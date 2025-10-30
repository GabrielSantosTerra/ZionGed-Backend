from fastapi import APIRouter
from .user import router as user_router, protected_router as user_protected_router

api_router = APIRouter()

api_router.include_router(user_router, prefix="/usuarios", tags=["Usuários"])
api_router.include_router(user_protected_router, prefix="/usuarios", tags=["Usuários"])

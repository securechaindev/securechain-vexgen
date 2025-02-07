from fastapi import APIRouter

from app.controllers import (
    auth_controller,
    health_controller,
    vex_controller,
)

api_router = APIRouter()
api_router.include_router(health_controller.router, tags=["/api/health"])
api_router.include_router(auth_controller.router, tags=["/api/auth"])
api_router.include_router(vex_controller.router, tags=["/api/vex"])

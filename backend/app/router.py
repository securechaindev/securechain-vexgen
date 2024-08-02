from fastapi import APIRouter

from app.controllers import (
    health_controller,
    auth_controller,
    assisting_information_vex_controller,
)

api_router = APIRouter()
api_router.include_router(health_controller.router, tags=["health"])
api_router.include_router(auth_controller.router, tags=["auth"])
api_router.include_router(assisting_information_vex_controller.router, tags=["vex"])

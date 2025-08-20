from fastapi import APIRouter

from app.controllers import (
    health_controller,
    vex_controller,
)

api_router = APIRouter()
api_router.include_router(health_controller.router, tags=["Secure Chain VEXGen Health"])
api_router.include_router(vex_controller.router, tags=["Secure Chain VEXGen - VEX/TIX"])

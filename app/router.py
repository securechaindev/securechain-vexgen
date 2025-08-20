from fastapi import APIRouter

from app.controllers import (
    health_controller,
    tix_controller,
    vex_controller,
    vex_tix_controller,
)

api_router = APIRouter()
api_router.include_router(health_controller.router, tags=["Secure Chain VEXGen Health"])
api_router.include_router(vex_controller.router, tags=["Secure Chain VEXGen - VEX"])
api_router.include_router(tix_controller.router, tags=["Secure Chain VEXGen - TIX"])
api_router.include_router(vex_tix_controller.router, tags=["Secure Chain VEXGen - VEX/TIX"])

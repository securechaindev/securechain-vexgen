from fastapi import APIRouter

from app.controllers import (
    assisting_information_vex_controller,
    graph_controller,
)

api_router = APIRouter()
api_router.include_router(graph_controller.router, tags=["graph"])
api_router.include_router(assisting_information_vex_controller.router, tags=["vex/van"])

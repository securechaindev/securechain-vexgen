from contextlib import asynccontextmanager
from os import getenv

from fastapi import FastAPI
from fastapi.exceptions import HTTPException, RequestValidationError
from fastapi.middleware.cors import CORSMiddleware

from app.exception_handler import (
    http_exception_handler,
    request_validation_exception_handler,
    unhandled_exception_handler,
)
from app.http_session import close_session
from app.middleware import log_request_middleware
from app.router import api_router

DESCRIPTION = """
A simple generating tool of VEX files and assisting information supporting the creation of VEX files.
"""

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await close_session()

app = FastAPI(
    title="VEXGen",
    description=DESCRIPTION,
    # openapi_url=None,
    version="0.3.0",
    contact={
        "name": "Antonio Germán Márquez Trujillo",
        "url": "https://github.com/GermanMT",
        "email": "amtrujillo@us.es",
    },
    license_info={
        "name": "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "url": "https://www.gnu.org/licenses/gpl-3.0.html",
    },
    lifespan=lifespan,
)

frontend_url = getenv("FRONTEND_URL", default="http://localhost:3000")

app.middleware("http")(log_request_middleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[frontend_url],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_exception_handler(RequestValidationError, request_validation_exception_handler)
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)
app.include_router(api_router)

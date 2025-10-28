from http import HTTPStatus
from time import time

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.dependencies import get_logger


class LogRequestMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        logger = get_logger()
        url = f"{request.url.path}?{request.query_params}" if request.query_params else request.url.path
        start_time = time()
        response = await call_next(request)
        process_time = (time() - start_time) * 1000
        formatted_process_time = f"{process_time:.2f}"
        host = getattr(getattr(request, "client", None), "host", None)
        port = getattr(getattr(request, "client", None), "port", None)
        try:
            status_phrase = HTTPStatus(response.status_code).phrase
        except ValueError:
            status_phrase = ""
        logger.info(
            f'{host}:{port} - "{request.method} {url}" {response.status_code} {status_phrase} {formatted_process_time}ms'
        )
        return response

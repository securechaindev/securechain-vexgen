from datetime import datetime
from json import JSONEncoder, loads
from typing import Any

from aiofiles import open
from bson import ObjectId
from neo4j.time import DateTime


class JSONencoder(JSONEncoder):
    def default(self, o: Any) -> Any:
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime):
            return str(o)
        if isinstance(o, DateTime):
            return str(o)
        return JSONEncoder.default(self, o)


def json_encoder(raw_response: dict[str, Any]) -> Any:
    return loads(JSONencoder().encode(raw_response))


async def load_json_template(path: str):
    async with open(path, encoding="utf-8") as f:
        return loads(await f.read())

from typing import Any

from bson import ObjectId

from app.database import DatabaseManager
from app.schemas import VEXCreate, VEXResponse
from app.utils import JSONEncoder


class VEXService:
    def __init__(self, db: DatabaseManager, json_encoder: JSONEncoder):
        self.vexs_collection = db.get_vexs_collection()
        self.users_collection = db.get_users_collection()
        self.json_encoder = json_encoder

    async def create_vex(self, vex: VEXCreate) -> str:
        vex_dict = vex.model_dump(exclude_unset=True)
        result = await self.vexs_collection.replace_one(
            {"owner": vex.owner, "name": vex.name, "sbom_path": vex.sbom_path},
            vex_dict,
            upsert=True
        )
        return str(result.upserted_id)

    async def read_vex_by_id(self, vex_id: str) -> VEXResponse | None:
        vex_dict = await self.vexs_collection.find_one({"_id": ObjectId(vex_id)})
        if vex_dict:
            vex_dict = self.json_encoder.encode(vex_dict)
            return VEXResponse(**vex_dict)
        return None

    async def read_vex_by_owner_name_sbom_name(self, owner: str, name: str, sbom_path: str) -> VEXResponse | None:
        vex_dict = await self.vexs_collection.find_one({"owner": owner, "name": name, "sbom_path": sbom_path})
        if vex_dict:
            vex_dict = self.json_encoder.encode(vex_dict)
            return VEXResponse(**vex_dict)
        return None

    async def read_user_vexs(self, user_id: str) -> list[VEXResponse]:
        pipeline: Any = [
            {
                "$match": {
                    "_id": ObjectId(user_id)
                }
            },
            {
                "$lookup": {
                    "from": "vex",
                    "localField": "vexs",
                    "foreignField": "_id",
                    "as": 'lookup'
                }
            },
            {"$unwind": "$lookup"},
            {
                "$project": {
                    "_id": "$lookup._id",
                    "owner": "$lookup.owner",
                    "name": "$lookup.name",
                    "sbom_path": "$lookup.sbom_path",
                    "sbom_name": "$lookup.sbom_name",
                    "moment": "$lookup.moment",
                    "metadata": "$lookup.metadata"
                }
            }
        ]
        try:
            vexs = []
            async for vex in self.users_collection.aggregate(pipeline):
                if vex:
                    vex = self.json_encoder.encode(vex)
                    vexs.append(VEXResponse(**vex))
            return vexs
        except Exception as _:
            return []

    async def update_user_vexs(self, vex_id: str, user_id: str) -> None:
        await self.users_collection.update_one({"_id": ObjectId(user_id)}, {"$addToSet": {"vexs": ObjectId(vex_id)}})

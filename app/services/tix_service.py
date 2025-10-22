from typing import Any

from bson import ObjectId

from app.database import DatabaseManager
from app.schemas import TIXCreate, TIXResponse


class TIXService:
    def __init__(self, db: DatabaseManager):
        self.tix_collection = db.get_tixs_collection()
        self.user_collection = db.get_user_collection()

    async def create_tix(self, tix: TIXCreate) -> str:
        tix_dict = tix.model_dump(exclude_unset=True)
        result = await self.tix_collection.replace_one(
            {"owner": tix.owner, "name": tix.name, "sbom_path": tix.sbom_path},
            tix_dict,
            upsert=True
        )
        return str(result.upserted_id)

    async def read_tix_by_id(self, tix_id: str) -> TIXResponse | None:
        tix_dict = await self.tix_collection.find_one({"_id": ObjectId(tix_id)})
        if tix_dict:
            return TIXResponse(**tix_dict)
        return None

    async def read_tix_by_owner_name_sbom_name(self, owner: str, name: str, sbom_path: str) -> TIXResponse | None:
        tix_dict = await self.tix_collection.find_one({"owner": owner, "name": name, "sbom_path": sbom_path})
        if tix_dict:
            return TIXResponse(**tix_dict)
        return None

    async def read_user_tixs(self, user_id: str) -> list[TIXResponse]:
        pipeline: Any = [
            {
                "$match": {
                    "_id": ObjectId(user_id)
                }
            },
            {
                "$lookup": {
                    "from": "tixs",
                    "localField": "tixs",
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
                    "statements": "$lookup.statements"
                }
            }
        ]
        try:
            return [
                TIXResponse(**tix) async for tix in self.user_collection.aggregate(pipeline) if tix
            ]
        except Exception as _:
            return []


    async def update_user_tixs(self, tix_id: str, user_id: str) -> None:
        await self.user_collection.update_one({"_id": ObjectId(user_id)}, {"$addToSet": {"tixs": ObjectId(tix_id)}})

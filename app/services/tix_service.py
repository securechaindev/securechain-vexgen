from typing import Any

from bson import ObjectId

from .dbs import get_collection


async def create_tix(tix: dict[str, Any]) -> str:
    tixs_collection = get_collection("tixs")
    result = await tixs_collection.replace_one({"owner": tix["owner"], "name": tix["name"], "sbom_name": tix["sbom_name"]}, tix, upsert=True)
    return result.upserted_id


async def read_tix_by_id(tix_id: str) -> dict[str, Any]:
    tixs_collection = get_collection("tixs")
    return await tixs_collection.find_one({"_id": ObjectId(tix_id)})


async def read_tix_by_owner_name_sbom_name(owner: str, name: str, sbom_name: str) -> dict[str, Any]:
    tixs_collection = get_collection("tixs")
    return await tixs_collection.find_one({"owner": owner, "name": name, "sbom_name": sbom_name})


async def read_user_tixs(user_id: str) -> list[dict[str, Any]]:
    user_collection = get_collection("user")
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
                "sbom_name": "$lookup.sbom_name",
                "moment": "$lookup.moment"
            }
        }
    ]
    try:
        return [
            tix async for tix in user_collection.aggregate(pipeline) if tix
        ]
    except Exception as _:
        return []


async def update_user_tixs(tix_id: str, user_id: str) -> None:
    user_collection = get_collection("user")
    await user_collection.update_one({"_id": ObjectId(user_id)}, {"$addToSet": {"tixs": ObjectId(tix_id)}})

from typing import Any

from bson import ObjectId

from .dbs import get_collection


async def create_vex(vex: dict[str, Any]) -> str:
    vexs_collection = get_collection("vexs")
    result = await vexs_collection.replace_one({"owner": vex["owner"], "name": vex["name"], "sbom_name": vex["sbom_name"]}, vex, upsert=True)
    return result.upserted_id


async def read_vex_by_id(vex_id: str) -> dict[str, Any]:
    vexs_collection = get_collection("vexs")
    return await vexs_collection.find_one({"_id": ObjectId(vex_id)})


async def read_vex_by_owner_name_sbom_name(owner: str, name: str, sbom_name: str) -> dict[str, Any]:
    vexs_collection = get_collection("vexs")
    return await vexs_collection.find_one({"owner": owner, "name": name, "sbom_name": sbom_name})


async def read_user_vexs(user_id: str) -> list[dict[str, Any]]:
    user_collection = get_collection("user")
    pipeline: Any = [
        {
            "$match": {
                "_id": ObjectId(user_id)
            }
        },
        {
            "$lookup": {
                "from": "vexs",
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
                "sbom_name": "$lookup.sbom_name",
                "moment": "$lookup.moment"
            }
        }
    ]
    try:
        return [
            vex async for vex in user_collection.aggregate(pipeline) if vex
        ]
    except Exception as _:
        return []


async def update_user_vexs(vex_id: str, user_id: str) -> None:
    user_collection = get_collection("user")
    await user_collection.update_one({"_id": ObjectId(user_id)}, {"$addToSet": {"vexs": ObjectId(vex_id)}})

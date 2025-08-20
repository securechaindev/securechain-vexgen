from typing import Any

from bson import ObjectId

from .dbs import get_collection


async def create_vex(vex: dict[str, Any]) -> str:
    vexs_collection = get_collection("vexs")
    result = await vexs_collection.replace_one({"owner": vex["owner"], "name": vex["name"], "sbom_name": vex["sbom_name"]}, vex, upsert=True)
    return result.upserted_id


async def create_tix(tix: dict[str, Any]) -> str:
    tixs_collection = get_collection("tixs")
    result = await tixs_collection.replace_one({"owner": tix["owner"], "name": tix["name"], "sbom_name": tix["sbom_name"]}, tix, upsert=True)
    return result.upserted_id


async def read_vex_by_id(vex_id: str) -> dict[str, Any]:
    vexs_collection = get_collection("vexs")
    return await vexs_collection.find_one({"_id": ObjectId(vex_id)})


async def read_tix_by_id(tix_id: str) -> dict[str, Any]:
    tixs_collection = get_collection("tixs")
    return await tixs_collection.find_one({"_id": ObjectId(tix_id)})


async def read_vex_moment_by_owner_name_sbom_name(owner: str, name: str, sbom_name: str) -> dict[str, Any]:
    vexs_collection = get_collection("vexs")
    return await vexs_collection.find_one({"owner": owner, "name": name, "sbom_name": sbom_name})


async def read_tix_moment_by_owner_name_sbom_name(owner: str, name: str, sbom_name: str) -> dict[str, Any]:
    tixs_collection = get_collection("tixs")
    return await tixs_collection.find_one({"owner": owner, "name": name, "sbom_name": sbom_name})


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
        {
            "$project": {
                "_id": {"$first": "$lookup._id"},
                "owner": {"$first": "$lookup.owner"},
                "name": {"$first": "$lookup.name"},
                "sbom_name": {"$first" : "$lookup.sbom_name"}
            }
        }
    ]
    try:
        return [
            vex async for vex in user_collection.aggregate(pipeline) if vex
        ]
    except Exception as _:
        return []


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
        {
            "$project": {
                "_id": {"$first": "$lookup._id"},
                "owner": {"$first": "$lookup.owner"},
                "name": {"$first": "$lookup.name"},
                "sbom_name": {"$first" : "$lookup.sbom_name"}
            }
        }
    ]
    try:
        return [
            tix async for tix in user_collection.aggregate(pipeline) if tix
        ]
    except Exception as _:
        return []


async def update_user_vexs(vex_id: str, user_id: str) -> None:
    user_collection = get_collection("user")
    await user_collection.update_one({"_id": ObjectId(user_id)}, {"$addToSet": {"vexs": ObjectId(vex_id)}})


async def update_user_tixs(tix_id: str, user_id: str) -> None:
    user_collection = get_collection("user")
    await user_collection.update_one({"_id": ObjectId(user_id)}, {"$addToSet": {"tixs": ObjectId(tix_id)}})

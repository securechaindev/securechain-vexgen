from time import sleep
from typing import Any

from requests import ConnectionError, ConnectTimeout, get
from xmltodict import parse


async def get_all_maven_versions(
    package_artifact_id: str, package_group_id: str
) -> list[dict[str, Any]]:
    versions: list[dict[str, Any]] = []
    while True:
        try:
            response = get(
                f"https://repo1.maven.org/maven2/{package_group_id.replace(".", "/")}/{package_artifact_id}/maven-metadata.xml"
            )
            break
        except (ConnectTimeout, ConnectionError):
            sleep(5)
    xml_string = response.text
    try:
        pom_dict = parse(xml_string)
    except Exception as _:
        return versions
    if isinstance(pom_dict["metadata"]["versioning"]["versions"]["version"], list):
        raw_versions = pom_dict["metadata"]["versioning"]["versions"]["version"]
    else:
        raw_versions = [pom_dict["metadata"]["versioning"]["versions"]["version"]]
    for count, version in enumerate(raw_versions):
        versions.append({"name": version, "release_date": None, "count": count})
    return versions

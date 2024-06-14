from json import JSONDecodeError
from time import sleep
from typing import Any

from requests import ConnectionError, ConnectTimeout, get


# TODO: En las nuevas actualizaciones de la API JSON se debería devolver la info de forma diferente, estar atento a nuevas versiones.
async def get_all_pypi_versions(pkg_name: str) -> list[dict[str, Any]]:
    while True:
        try:
            response = get(f"https://pypi.python.org/pypi/{pkg_name}/json").json()
            break
        except (ConnectTimeout, ConnectionError):
            sleep(5)
        except JSONDecodeError:
            print("Error en el paquete: ", pkg_name)
            return []
    if "releases" in response:
        versions: list[dict[str, Any]] = []
        for count, version in enumerate(response["releases"]):
            versions.append(
                {"name": version, "count": count}
            )
        return versions
    return []

from os import makedirs
from os.path import exists

from requests import post

# First, open the file with the info of each sbom file
with open("repos_sbom.txt") as txt_file:
    if not exists("tests/vex_van"):
        makedirs("tests/vex_van")
    for line in txt_file.read().split("\n"):
        owner_name, sbom_path = line.split(":")
        owner, name = owner_name.split("/")

        # Second, generate the VEX and VAN file for each sbom file
        response = post(
            f"http://localhost:8000/vex/van/{owner}/{name}?sbom_path={sbom_path}"
        )
        s_path = sbom_path.replace("/", "*")
        with open(f"tests/vex_van/{owner}_{name}:{s_path}.zip", "wb") as file:
            file.write(response.content)

from os import makedirs, system
from os.path import exists

from requests import post

# First, open the file with the info of each sbom file
with open("repos_sbom.txt") as txt_file:
    system("rm -rf tests/vex_van")
    if not exists("tests/vex_van"):
        makedirs("tests/vex_van")
    for line in txt_file.read().split("\n"):
        owner_name, sbom_path = line.split(":")
        owner, name = owner_name.split("/")

        # Change the variable statements_group for any value like [no_clustering, cwe_type, attack_vector_av, attack_vector_ac,
        # attack_vector_au, attack_vector_c, attack_vector_i, attack_vector_a, reachable_code] to creare clusters
        statements_group = "no_clustering"

        # Second, generate the VEX and VAN file for each sbom file
        response = post(
            f"http://localhost:8000/vex/van/{owner}/{name}?sbom_path={sbom_path}&statements_group={statements_group}"
        )
        s_path = sbom_path.replace("/", "*")
        with open(f"tests/vex_van/{owner}*{name}:{s_path}.zip", "wb") as file:
            file.write(response.content)

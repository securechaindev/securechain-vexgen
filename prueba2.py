from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection, AsyncIOMotorDatabase
from requests import get
from asyncio import run
from time import sleep
from regex import compile

# Reemplaza con tu token de acceso personal
GITHUB_TOKEN = "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"
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.cloak-preview"}

async def buscar_commits_por_cve(cve):
    while True:
        try:
            url = f"https://api.github.com/search/commits?q={cve}"
            response = get(url, headers=HEADERS)
            return response.json()
        except:
            sleep(1)

async def obtener_diffs_de_commits(repo, commit_sha):
    while True:
        try:
            url = f"https://api.github.com/repos/{repo}/commits/{commit_sha}"
            response = get(url, headers=HEADERS)
            return response.json()
        except:
            sleep(1)

async def extraer_funciones_modificadas(diff_patch, languaje):
    match languaje:
        case "py":
            patron_clase = compile(r'\bclass\s+(\w+)\s*:\s*')
            patron_metodo = compile(r'\bdef\s+(\w+)\s*\(.*?\)\s*:')
        case "java":
            patron_clase = compile(r'\bclass\s+(\w+)\s*\{')
            patron_metodo = compile(r'(public|protected|private|static|\s)*\s+[\w\<\>\[\]]+\s+(\w+)\s*\([^\)]*\)\s*\{')
        case "rs":
            patron_clase = compile(r'\bstruct\s+(\w+)|\bimpl\s+(\w+)\s*{?')
            patron_metodo = compile(r'\bfn\s+(\w+)\s*\(.*?\)\s*{?')
        case "js":
            patron_clase = compile(r'\bclass\s+(\w+)\s*{?')
            patron_metodo = compile(r'(public|protected|private|static|\s)*\s*(\w+)\s*\(.*?\)\s*{?')
        case "ts":
            patron_clase = compile(r'\bclass\s+(\w+)\s*{?')
            patron_metodo = compile(r'(public|protected|private|static|\s)*\s*(\w+)\s*\(.*?\)\s*{?')
        case "cs":
            patron_clase = compile(r'\bclass\s+(\w+)\s*{?')
            patron_metodo = compile(r'(public|protected|private|internal|static|\s)*\s+[\w\<\>\[\]]+\s+(\w+)\s*\(.*?\)\s*{?')
    funciones_modificadas = []
    for linea in diff_patch.split("\n"):
        if linea.startswith("+"):
            for match_clase in patron_clase.finditer(linea):
                nombre_clase = match_clase.group(1) or match_clase.group(2)
                if nombre_clase:
                    funciones_modificadas.append(nombre_clase)
            for match_metodo in patron_metodo.finditer(linea):
                nombre_metodo = match_metodo.group(1) or match_metodo.group(2)
                if nombre_metodo:
                    funciones_modificadas.append(nombre_metodo)
    return funciones_modificadas

async def extract_vuln_funcs():
    client = AsyncIOMotorClient("mongodb://mongoDepex:mongoDepex@localhost:27017/admin")
    nvd_db: AsyncIOMotorDatabase = client.nvd
    cve_collection: AsyncIOMotorCollection = nvd_db.get_collection("cves")
    txt_file = open("cves.txt")
    for cve_ghsa in txt_file.read().split("\n"):
        func_modificadas = set()
        ids = cve_ghsa.split(":")
        cve_id = ids[0]
        cve = await cve_collection.find_one({"id": cve_id})
        # if "affected_artefacts" not in cve:
        for id in ids:
            if id != "None":
                commits = await buscar_commits_por_cve(id)
                if "items" in commits:
                    for item in commits["items"]:
                        repo_full_name = item["repository"]["full_name"]
                        if (
                            "upgrade" not in item["commit"]["message"].lower() and
                            "bump" not in item["commit"]["message"].lower()
                            # ("fix" in item["commit"]["message"].lower() or
                            # "mitigation" in item["commit"]["message"].lower() or
                            # f"merge {id}" in item["commit"]["message"].lower())
                        ):
                            commit_data = await obtener_diffs_de_commits(repo_full_name, item["sha"])
                            if "files" in commit_data:
                                for file in commit_data["files"]:
                                    if file["filename"].endswith((".java", ".py", ".cs", ".rs", ".js", ".ts")):
                                        if "patch" in file:
                                            func_modificadas.update(await extraer_funciones_modificadas(file["patch"], file["filename"].split(".")[-1]))
        cve["affected_artefacts"] = list(func_modificadas)
        await cve_collection.replace_one({"id": cve_id}, cve)
        print(cve_id)

run(extract_vuln_funcs())

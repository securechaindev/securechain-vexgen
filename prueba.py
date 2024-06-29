import requests
import time

owner_name = set()
txt_file = open("repos_vex.txt", "w")

def search_github_repositories(keyword, extension):
    url = f"https://api.github.com/search/code?q={keyword}+extension:{extension}+in:path"
    repositories = []
    page = 1

    while True:
        response = requests.get(url + f"&page={page}", headers={"Authorization": "Bearer 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"})
        time.sleep(10)
        if response.status_code == 200:
            data = response.json()
            items = data.get("items", [])
            if not items:
                break
            repositories.extend(items)
            page += 1
        else:
            print("Failed to retrieve data from GitHub API.")
            break

    for item in repositories:
        repository = item.get("repository", {})
        owner = repository.get("owner", {}).get("login")
        name = repository.get("name")
        file_path = item.get("path")
        owner_name.add(f"{owner}/{name}:{file_path}")
    print(len(owner_name))

search_github_repositories("openvex", "json")

for _ in owner_name:
    txt_file.write(_+"\n")
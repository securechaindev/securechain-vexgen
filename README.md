# VexGen Project

<!-- <p>
  <a href="https://github.com/GermanMT/depex/releases" target="_blank">
    <img src="https://img.shields.io/github/v/release/GermanMT/depex?color=green&logo=github" alt="release">
  </a>

  <a href="https://github.com/GermanMT/depex/blob/main/LICENSE.md" target="_blank">
    <img src="https://img.shields.io/github/license/GermanMT/depex?logo=gnu" alt="license">
  </a>

  <a href="https://github.com/GermanMT/depex/actions/workflows/analisys.yml" target="_blank">
    <img src="https://img.shields.io/github/actions/workflow/status/GermanMT/depex/analisys.yml?branch=main&event=push&label=code%20analisys" alt="code analisys">
  </a>

  <a href="https://doi.org/10.5281/zenodo.7692304">
    <img src="https://zenodo.org/badge/DOI/10.5281/zenodo.7692304.svg" alt="DOI">
  </a>
</p> -->

## Video tutorial

https://github.com/user-attachments/assets/5750712e-8429-410b-b697-ce8414fe5063

## Deployment requirements

1. [Docker](https://www.docker.com/) to deploy the tool.

2. [Git Large Files Storage](https://git-lfs.com/) (git-lfs) for cloning correctly the seeds of the repository.

## Deployment with docker

### Step 1
 Create a .env file from template.env

#### Get API Keys

- How to get a GitHub [API key](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens).

- Modify the **Json Web Token (JWT)** secret key with your own. You can generate your own with the command **node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"**.

### Step 2
Create the **graphs** folder inside the **seeds** folder in the root of the project, download the graphs seed from this [link](https://goo.su/YjuzmQ), and insert it into the **graphs** folder.

### Step 3
Run command *docker compose up --build*.

### Step 4
Enter [here](http://0.0.0.0:3000) for the frontend Web API.

#### Other tools
1. It is recommended to use a GUI such as [MongoDB Compass](https://www.mongodb.com/en/products/compass) to see what information is being indexed in vulnerability database

2. You can see the created graph built for [here](http://0.0.0.0:7474/browser/), using the Neo4J browser interfaces.

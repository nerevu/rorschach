# Timero — Timely <-> Xero sync service

## Usage

1. Create and activate a virtual environment:

    `Mac`

    ```bash
    virtualenv env
    source env/bin/activate
    ```

    `Windows`

    ```bash
    virtualenv env
     ./env/Scripts/activate
    ```

2. Install requirements::

    ```bash
    pip install -r requirements.txt
    ```

3. Run the service:

    ```bash
    bin/sync-time
    ```

4. If you are contributing to this repo, install dev-requirements::

```bash
pip install -r dev-requirements.txt
```

## Xero Setup

Your own [Xero](https://developer.xero.com/documentation/getting-started/getting-started-guide) API account is required.

## Headless Setup

https://sites.google.com/a/chromium.org/chromedriver/home

## API Docs

- [Timely](https://dev.timelyapp.com/)
- [Xero Projects](https://developer.xero.com/documentation/projects/projects)

## Configuration

Environment Variable | Description
---------------------|------------
TIMERO_SECRET_KEY | Flask App secret key
TIMELY_CLIENT_ID | Timely API client ID
TIMELY_SECRET | Timely API secret
XERO_CLIENT_ID | Xero API client ID
XERO_SECRET | Xero API secret

We use python-dotenv to manage environment variables. To access the values to the environment variables above, you need to create a symbolic link (symlink) to Timero's `.env` file.

To create a symlink:

`Windows`

- Open a Command Prompt (right click and `Run as Administrator`)
- run the following code with the correct paths
    ```bash
    mklink "C:\{path_to_project}\\.env" "C:\{path_to_nerevu_dropbox}\Security\{username}\timero-env"
    ```

You can read more about symlinks [here](https://www.maketecheasier.com/create-symbolic-links-windows10/).

`Linux`

- Open a Terminal
- run the following code with the correct paths to create a soft link
    ```bash
    ln -s /{path_to_nerevu_dropbox}/Security/{username}/timero-env /{path_to_project}/.env
    ```

## Chrome driver

`Macports`

`sudo port install chromedriver-{version}`

`Download`

[chromium.org](https://sites.google.com/a/chromium.org/chromedriver/downloads)

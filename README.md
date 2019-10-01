# Alegna Commission Calculator

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

3. Run the application:

    ```bash
    manage serve
    ```
    This code may break at first if some needed packes were not properly installed. Look at the error in the console to determine what packages need installed, and `pip install` them individually. After each `pip install` you can run `manage serve` again to see if there are any more packages that need installed. If not, the app should start running.


4. Open API

    [127.0.0.1:5000/v1](http://127.0.0.1:5000/v1)

5. If you are contributing to this repo, install dev-requirements::

```bash
pip install -r dev-requirements.txt
```

## Quickbooks Setup
Your own developer account is required to work with the Quickbooks sandbox. To set up your own account, visit [this site](https://developer.intuit.com/app/developer/sandbox) and follow the instructions using your work email address.

*If you are already logged into a personal account, you will need to log out first.*

## Notes

- To disable route caching, set [config.py#L67](https://github.com/nerevu/commissioner/blob/6feb4945e2971fc5bf949b33fe7edfa124d7c218/config.py#L67) to `ROUTE_TIMEOUT = get_seconds(0)`
- The debugger for VScode will not work because it does not use the `manage.py` file. If you figure out a way to configure it to work with the manage.py file, please let everyone know.

## Configuration

Environment Variable | Description
---------------------|------------
QB_SANDBOX_CLIENT_ID | Quickbooks sandbox client ID (requires QB dev account)
QB_SANDBOX_CLIENT_SECRET | Quickbooks sandbox client secret (requires QB dev account)
ALEGNA_QB_CLIENT_ID | Quickbooks Alegna, Inc client ID
ALEGNA_QB_CLIENT_SECRET | Quickbooks Alegna, Inc client secret

We use python-dotenv to manage environment variables. To access the values to the environment variables above, you need to create a symbolic link (symlink) to the Alegna Commissioner App's `.env` file.

To create a symlink:

`Windows`
- Open a Command Prompt (right click and `Run as Administrator`)
- run the following code with the correct paths
    ```bash
    mklink "C:\{path_to_project}\commissioner\.env" "C:\{path_to_dropbox}\Nerevu Group Dropbox\Clients\Alegna\commissioner\.env"
    ```

You can read more about symlinks [here](https://www.maketecheasier.com/create-symbolic-links-windows10/).
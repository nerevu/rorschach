# -*- coding: utf-8 -*-
"""
    app
    ~~~

    Provides the flask application

    ###########################################################################
    # WARNING: if running on a a staging server, you MUST set the 'STAGE' env
    # heroku config:set STAGE=true --remote staging

    # WARNING: The heroku project must either have a postgres or memcache db to be
    # recognized as production. If it is not recognized as production, Talisman
    # will not run (see config.py).
    ###########################################################################
"""
from functools import partial
from os import path as p
from pathlib import Path
from pickle import DEFAULT_PROTOCOL

from flask import Flask, redirect, request
from flask_cors import CORS
from flask_caching import Cache
from flask_compress import Compress

import pygogo as gogo

from rq_dashboard import default_settings
from rq_dashboard.cli import add_basic_auth

from app.helpers import configure

from mezmorize.utils import get_cache_config, get_cache_type
from meza.fntools import CustomEncoder

__version__ = "0.22.0"
__title__ = "Timero API"
__package_name__ = "timero-api"
__author__ = "Reuben Cummings"
__description__ = "API for the Timero Timely-Xero sync webapp"
__email__ = "rcummings@nerevu.com"
__license__ = "MIT"
__copyright__ = "Copyright 2019 Nerevu Group"

BASEDIR = p.dirname(__file__)

cache = Cache()
compress = Compress()
cors = CORS()

logger = gogo.Gogo(__name__, monolog=True).logger


def register_rq(app):
    username = app.config.get("RQ_DASHBOARD_USERNAME")
    password = app.config.get("RQ_DASHBOARD_PASSWORD")

    if username and password:
        add_basic_auth(blueprint=rq, username=username, password=password)
        logger.info(f"Creating RQ-dashboard login for {username}")

    app.register_blueprint(rq, url_prefix="/dashboard")


def configure_talisman(app):
    from flask_talisman import Talisman

    talisman_kwargs = {
        k.replace("TALISMAN_", "").lower(): v
        for k, v in app.config.items()
        if k.startswith("TALISMAN_")
    }

    Talisman(app, **talisman_kwargs)


def configure_cache(app):
    if app.config.get("PROD_SERVER") or app.config.get("DEBUG_MEMCACHE"):
        cache_type = get_cache_type(spread=False)
        cache_dir = None
    else:
        cache_type = "filesystem"
        parent_dir = Path(p.dirname(BASEDIR))
        cache_dir = parent_dir.joinpath(".cache", f"v{DEFAULT_PROTOCOL}")

    message = f"Set cache type to {cache_type}"
    cache_config = get_cache_config(cache_type, CACHE_DIR=cache_dir, **app.config)

    if cache_config["CACHE_TYPE"] == "filesystem":
        message += f" in {cache_config['CACHE_DIR']}"

    logger.debug(message)
    cache.init_app(app, config=cache_config)

    # TODO: keep until https://github.com/sh4nks/flask-caching/issues/113 is solved
    DEF_TIMEOUT = app.config.get("CACHE_DEFAULT_TIMEOUT")
    timeout = app.config.get("SET_TIMEOUT", DEF_TIMEOUT)
    cache.set = partial(cache.set, timeout=timeout)


def check_settings(app):
    required_setting_missing = False

    for setting in app.config.get("REQUIRED_SETTINGS", []):
        if not app.config.get(setting):
            required_setting_missing = True
            logger.error(f"App setting {setting} is missing!")

    if app.config.get("PROD_SERVER"):
        server_name = app.config.get("SERVER_NAME")

        if server_name:
            logger.info(f"SERVER_NAME is {server_name}.")
        else:
            logger.error("SERVER_NAME is not set!")

        for setting in app.config.get("REQUIRED_PROD_SETTINGS", []):
            if not app.config.get(setting):
                required_setting_missing = True
                logger.error(f"Production app setting {setting} is missing!")

    if not required_setting_missing:
        logger.info("All required app settings present!")

    return required_setting_missing


def create_app(script_info=None, **kwargs):
    app = Flask(__name__)
    app.url_map.strict_slashes = False
    cors.init_app(app)
    compress.init_app(app)

    @app.before_request
    def clear_trailing():
        request_path = request.path
        is_root = request_path == "/"
        is_admin = request_path.startswith("/admin")
        has_trailing = request_path.endswith("/")

        if not (is_root or is_admin) and has_trailing:
            return redirect(request_path[:-1])

    app.config.from_object(default_settings)

    try:
        if script_info.flask_config:
            app.config.from_mapping(script_info.flask_config)
    except AttributeError:
        if kwargs:
            configure(app.config, **kwargs)
        else:
            logger.warning("Invalid command. Use `manage run` to start the server.")

    check_settings(app)
    app.register_blueprint(api)
    register_rq(app)

    if app.config.get("TALISMAN"):
        configure_talisman(app)

    configure_cache(app)

    app.json_encoder = CustomEncoder
    return app


# put at bottom to avoid circular reference errors
from app.api import blueprint as api  # noqa
from rq_dashboard import blueprint as rq  # noqa

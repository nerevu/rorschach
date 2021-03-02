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
from os import path as p, getenv
from pathlib import Path
from pickle import DEFAULT_PROTOCOL
from logging import WARNING, DEBUG

from flask import Flask
from flask.logging import default_handler
from flask_cors import CORS
from flask_caching import Cache
from flask_compress import Compress

from rq_dashboard import default_settings
from rq_dashboard.cli import add_basic_auth

from app.helpers import configure, email_hdlr, flask_formatter

from mezmorize.utils import get_cache_config, get_cache_type
from meza.fntools import CustomEncoder

__version__ = "0.27.0"
__title__ = "Nerevu API"
__package_name__ = "api"
__author__ = "Reuben Cummings"
__description__ = "Nerevu monolith API"
__email__ = "rcummings@nerevu.com"
__license__ = "MIT"
__copyright__ = "Copyright 2019 Nerevu Group"

BASEDIR = p.dirname(__file__)

cache = Cache()
compress = Compress()
cors = CORS()


def register_rq(app):
    username = app.config.get("RQ_DASHBOARD_USERNAME")
    password = app.config.get("RQ_DASHBOARD_PASSWORD")

    if username and password:
        add_basic_auth(blueprint=rq, username=username, password=password)
        app.logger.info(f"Creating RQ-dashboard login for {username}")

    app.register_blueprint(rq, url_prefix="/dashboard")


def configure_talisman(app):
    if app.config.get("TALISMAN"):
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

    app.logger.debug(message)
    cache.init_app(app, config=cache_config)

    # TODO: keep until https://github.com/sh4nks/flask-caching/issues/113 is solved
    DEF_TIMEOUT = app.config.get("CACHE_DEFAULT_TIMEOUT")
    timeout = app.config.get("SET_TIMEOUT", DEF_TIMEOUT)
    cache.set = partial(cache.set, timeout=timeout)


def set_settings(app):
    optional_settings = app.config.get("OPTIONAL_SETTINGS", [])
    required_settings = app.config.get("REQUIRED_SETTINGS", [])
    required_prod_settings = app.config.get("REQUIRED_PROD_SETTINGS", [])
    settings = optional_settings + required_settings + required_prod_settings

    for setting in settings:
        app.config.setdefault(setting, getenv(setting))


def check_settings(app):
    required_setting_missing = False

    for setting in app.config.get("REQUIRED_SETTINGS", []):
        if not app.config.get(setting):
            required_setting_missing = True
            app.logger.error(f"App setting {setting} is missing!")

    if app.config.get("PROD_SERVER"):
        server_name = app.config.get("SERVER_NAME")

        if server_name:
            app.logger.info(f"SERVER_NAME from init is {server_name}.")
        else:
            app.logger.error("SERVER_NAME is not set!")

        for setting in app.config.get("REQUIRED_PROD_SETTINGS", []):
            if not app.config.get(setting):
                required_setting_missing = True
                app.logger.error(f"Production app setting {setting} is missing!")
    else:
        app.logger.info("Production server not detected.")

    if not required_setting_missing:
        app.logger.info("All required app settings present!")

    for setting in app.config.get("OPTIONAL_SETTINGS", []):
        if not app.config.get(setting):
            app.logger.info(f"Optional app setting {setting} is missing!")

    return required_setting_missing


def create_app(script_info=None, **kwargs):
    # https://flask.palletsprojects.com/en/1.1.x/logging/#basic-configuration
    default_handler.setLevel(DEBUG)
    default_handler.setFormatter(flask_formatter)

    app = Flask(__name__)
    app.url_map.strict_slashes = False
    cors.init_app(app)
    compress.init_app(app)
    app.config.from_object(default_settings)

    try:
        if script_info.flask_config:
            app.config.from_mapping(script_info.flask_config)
    except AttributeError:
        if kwargs:
            configure(app.config, **kwargs)
        else:
            app.logger.warning("Invalid command. Use `manage run` to start the server.")

    set_settings(app)

    if not app.debug:
        email_hdlr.setLevel(WARNING)
        email_hdlr.setFormatter(flask_formatter)
        app.logger.addHandler(email_hdlr)

    app.register_blueprint(housekeeping)
    check_settings(app)

    app.register_blueprint(api)
    register_rq(app)
    configure_talisman(app)
    configure_cache(app)
    app.json_encoder = CustomEncoder
    return app


# put at bottom to avoid circular reference errors
from app.routes.api import blueprint as api  # noqa
from app.routes.housekeeping import blueprint as housekeeping  # noqa
from rq_dashboard import blueprint as rq  # noqa

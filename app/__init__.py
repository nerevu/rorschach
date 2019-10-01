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
    # will not be run (see config.py).
    ###########################################################################
"""
import config

from os import getenv, path
from flask import Flask, redirect, request
from flask_cors import CORS
from flask_caching import Cache
from flask_compress import Compress

from mezmorize.utils import get_cache_config, get_cache_type

__version__ = "0.14.0"
__title__ = "Timero API"
__package_name__ = "timero-api"
__author__ = "Reuben Cummings"
__description__ = "API for the Timero Timely-Xero sync webapp"
__email__ = "rcummings@nerevu.com"
__license__ = "MIT"
__copyright__ = "Copyright 2019 Nerevu Group"

cache = Cache()
compress = Compress()
cors = CORS()


def create_app(config_mode=None, config_file=None):
    app = Flask(__name__)
    app.url_map.strict_slashes = False
    cors.init_app(app)
    compress.init_app(app)

    app.register_blueprint(api)

    @app.before_request
    def clear_trailing():
        request_path = request.path

        if request_path != "/" and request_path.endswith("/"):
            return redirect(request_path[:-1])

    if config_mode:
        app.config.from_object(getattr(config, config_mode))
    elif config_file:
        app.config.from_pyfile(config_file)
    else:
        app.config.from_envvar("APP_SETTINGS", silent=True)

    if app.config.get("TALISMAN"):
        from flask_talisman import Talisman

        Talisman(app)

    if app.config.get("HEROKU") or app.config.get("DEBUG_MEMCACHE"):
        cache_type = get_cache_type(spread=False)
    else:
        cache_type = "filesystem"

    cache_config = get_cache_config(cache_type, **app.config)

    ###########################################################################
    # TODO - remove once mezmorize PR is merged
    if cache_type == "filesystem" and not cache_config.get("CACHE_DIR"):
        cache_config["CACHE_DIR"] = path.join(
            path.abspath(path.dirname(__file__)), "cache"
        )
    ###########################################################################

    cache.init_app(app, config=cache_config)
    return app


# put at bottom to avoid circular reference errors
from app.api import blueprint as api  # noqa

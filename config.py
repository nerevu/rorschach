# -*- coding: utf-8 -*-
"""
    config
    ~~~~~~

    Provides the flask config options
    ###########################################################################
    # WARNING: if running on a a staging server, you MUST set the 'STAGE' env
    # heroku config:set STAGE=true --remote staging

    # WARNING: The heroku project must either have a postgres or memcache db to be
    # recognized as production. If it is not recognized as production, Talisman
    # will not be run.
    ###########################################################################
"""
from os import getenv, urandom, path as p
from datetime import timedelta
from collections import namedtuple
from socket import error as SocketError, timeout as SocketTimeout

import requests
import pygogo as gogo

from pkutils import parse_module
from meza.process import merge

PARENT_DIR = p.abspath(p.dirname(__file__))
DAYS_PER_MONTH = 30

app = parse_module(p.join(PARENT_DIR, "app", "__init__.py"))
user = getenv("USER", "user")

__APP_NAME__ = app.__package_name__
__APP_TITLE__ = app.__title__
__PROD_SERVER__ = getenv("DATABASE_URL") or getenv("MEMCACHIER_SERVERS")
__STAG_SERVER__ = getenv("STAGE")
__END__ = "-stage" if __STAG_SERVER__ else ""
__SUB_DOMAIN__ = f"{__APP_NAME__}{__END__}"


Admin = namedtuple("Admin", ["name", "email"])
get_path = lambda name: f"file://{p.join(PARENT_DIR, 'data', name)}"
logger = gogo.Gogo(__name__, monolog=True).logger


def get_seconds(seconds=0, months=0, **kwargs):
    seconds = timedelta(seconds=seconds, **kwargs).total_seconds()

    if months:
        seconds += timedelta(DAYS_PER_MONTH).total_seconds() * months

    return int(seconds)


class Config(object):
    HEROKU = False
    DEBUG = False
    TESTING = False
    DEBUG_MEMCACHE = True
    DEBUG_QB_CLIENT = False
    PARALLEL = False
    OAUTHLIB_INSECURE_TRANSPORT = False

    # see http://bootswatch.com/3/ for available swatches
    FLASK_ADMIN_SWATCH = "cerulean"
    ADMIN = Admin(app.__author__, app.__email__)
    ADMINS = frozenset([ADMIN.email])
    HOST = "127.0.0.1"

    # These don't change
    ROUTE_DEBOUNCE = get_seconds(5)
    ROUTE_TIMEOUT = get_seconds(hours=3)
    SET_TIMEOUT = get_seconds(days=30)
    REPORT_MONTHS = 1
    LRU_CACHE_SIZE = 128
    REPORT_DAYS = REPORT_MONTHS * DAYS_PER_MONTH
    SEND_FILE_MAX_AGE_DEFAULT = ROUTE_TIMEOUT
    EMPTY_TIMEOUT = ROUTE_TIMEOUT * 10
    API_URL_PREFIX = "/v1"
    SECRET_KEY = getenv("ALEGNA_SECRET_KEY", urandom(24))
    AUTHORIZATION_BASE = "authorize"
    TOKEN_BASE = "token"

    # https://app.timelyapp.com/777870/oauth_applications
    TIMELY_ACCOUNT_ID = "777870"
    TIMELY_CLIENT_ID = getenv("TIMELY_CLIENT_ID")
    TIMELY_SECRET = getenv("TIMELY_SECRET")
    TIMELY_API_BASE_URL = "https://api.timelyapp.com/1.1"
    TIMELY_OAUTH_BASE_URL = f"{TIMELY_API_BASE_URL}/oauth"
    TIMELY_AUTHORIZATION_BASE_URL = f"{TIMELY_OAUTH_BASE_URL}/{AUTHORIZATION_BASE}"
    TIMELY_TOKEN_URL = f"{TIMELY_OAUTH_BASE_URL}/{TOKEN_BASE}"
    TIMELY_REFRESH_URL = TIMELY_TOKEN_URL

    # https://developer.xero.com/myapps/
    XERO_CLIENT_ID = getenv("XERO_CLIENT_ID")
    XERO_SECRET = getenv("XERO_SECRET")
    XERO_CONSUMER_KEY = getenv("XERO_CONSUMER_KEY")
    XERO_CONSUMER_SECRET = getenv("XERO_CONSUMER_SECRET")
    XERO_API_BASE_URL = "https://api.xero.com"
    XERO_OAUTH_BASE_URL = "https://login.xero.com/identity/connect"
    XERO_SCOPES = ["projects", "offline_access"]
    XERO_AUTHORIZATION_BASE_URL = f"{XERO_OAUTH_BASE_URL}/{AUTHORIZATION_BASE}"
    XERO_TOKEN_URL = f"{XERO_OAUTH_BASE_URL}/{TOKEN_BASE}"
    XERO_REFRESH_URL = XERO_TOKEN_URL

    # Change based on mode
    TIMELY_REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob"
    XERO_REDIRECT_URI = f"http://localhost:5000{API_URL_PREFIX}/xero-callback"
    CACHE_DEFAULT_TIMEOUT = get_seconds(hours=24)
    CHUNK_SIZE = 256
    ROW_LIMIT = 32
    API_RESULTS_PER_PAGE = 32
    API_MAX_RESULTS_PER_PAGE = 256
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False


class Production(Config):
    # TODO: setup nginx http://docs.gunicorn.org/en/latest/deploy.html
    #       or waitress https://github.com/etianen/django-herokuapp/issues/9
    #       test with slowloris https://github.com/gkbrk/slowloris
    #       look into preboot https://devcenter.heroku.com/articles/preboot
    defaultdb = f"postgres://{user}@localhost/{__APP_NAME__.replace('-','_')}"
    SQLALCHEMY_DATABASE_URI = getenv("DATABASE_URL", defaultdb)

    # max 20 connections per dyno spread over 4 workers
    # look into a Null pool with pgbouncer
    # https://devcenter.heroku.com/articles/python-concurrency-and-database-connections
    SQLALCHEMY_POOL_SIZE = 3
    SQLALCHEMY_MAX_OVERFLOW = 2

    if __PROD_SERVER__:
        TALISMAN = True
        TALISMAN_PERMANENT = True

    HOST = "0.0.0.0"


class Heroku(Production):
    HEROKU = True
    DOMAIN = "herokuapp.com"
    TIMELY_REDIRECT_URI = (
        f"https://{__SUB_DOMAIN__}.{DOMAIN}{Config.API_URL_PREFIX}/timely-callback"
    )
    XERO_REDIRECT_URI = (
        f"https://{__SUB_DOMAIN__}.{DOMAIN}{Config.API_URL_PREFIX}/xero-callback"
    )

    if __PROD_SERVER__:
        SERVER_NAME = f"{__SUB_DOMAIN__}.{DOMAIN}"
        logger.info(f"SERVER_NAME is {SERVER_NAME}")


class Custom(Production):
    DOMAIN = "nerevu.com"
    TIMELY_REDIRECT_URI = (
        f"https://{__SUB_DOMAIN__}.{DOMAIN}{Config.API_URL_PREFIX}/timely-callback"
    )
    XERO_REDIRECT_URI = (
        f"https://{__SUB_DOMAIN__}.{DOMAIN}{Config.API_URL_PREFIX}/xero-callback"
    )

    if __PROD_SERVER__:
        TALISMAN_SUBDOMAINS = True
        SERVER_NAME = f"{__SUB_DOMAIN__}.{DOMAIN}"
        logger.info(f"SERVER_NAME is {SERVER_NAME}")


class Development(Config):
    base = "sqlite:///{}?check_same_thread=False"
    SQLALCHEMY_DATABASE_URI = base.format(p.join(PARENT_DIR, "app.db"))
    DEBUG = True
    DEBUG_MEMCACHE = False
    DEBUG_QB_CLIENT = False
    CACHE_DEFAULT_TIMEOUT = get_seconds(hours=8)
    CHUNK_SIZE = 128
    ROW_LIMIT = 16
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    OAUTHLIB_INSECURE_TRANSPORT = True


class Test(Config):
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    DEBUG = True
    DEBUG_MEMCACHE = False
    TESTING = True
    CACHE_DEFAULT_TIMEOUT = get_seconds(hours=1)
    CHUNK_SIZE = 64
    ROW_LIMIT = 8
    OAUTHLIB_INSECURE_TRANSPORT = True

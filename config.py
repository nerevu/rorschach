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

import pygogo as gogo

from dotenv import load_dotenv

PARENT_DIR = p.abspath(p.dirname(__file__))
DAYS_PER_MONTH = 30

load_dotenv(p.join(PARENT_DIR, ".env"))
db_env_list = ["DATABASE_URL", "REDIS_URL", "MEMCACHIER_SERVERS", "REDISTOGO_URL"]

__USER__ = "reubano"
__APP_NAME__ = "timero"
__PROD_SERVER__ = any(map(getenv, db_env_list))
__DEF_HOST__ = "127.0.0.1"
__DEF_REDIS_PORT__ = 6379
__DEF_REDIS_HOST__ = getenv("REDIS_PORT_6379_TCP_ADDR", __DEF_HOST__)
__DEF_REDIS_URL__ = "redis://{}:{}".format(__DEF_REDIS_HOST__, __DEF_REDIS_PORT__)

__STAG_SERVER__ = getenv("STAGE")
__END__ = "-stage" if __STAG_SERVER__ else ""
__SUB_DOMAIN__ = f"{__APP_NAME__}{__END__}"
__AUTHOR__ = "Reuben Cummings"
__AUTHOR_EMAIL__ = "rcummings@nerevu.com"

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
    ADMIN = Admin(__AUTHOR__, __AUTHOR_EMAIL__)
    ADMINS = frozenset([ADMIN.email])
    HOST = "127.0.0.1"

    # These don't change
    ROUTE_DEBOUNCE = get_seconds(5)
    ROUTE_TIMEOUT = get_seconds(0)
    SET_TIMEOUT = get_seconds(days=30)
    REPORT_MONTHS = 3
    LRU_CACHE_SIZE = 128
    REPORT_DAYS = REPORT_MONTHS * DAYS_PER_MONTH
    SEND_FILE_MAX_AGE_DEFAULT = ROUTE_TIMEOUT
    EMPTY_TIMEOUT = ROUTE_TIMEOUT * 10
    API_URL_PREFIX = "/v1"
    SECRET_KEY = getenv("TIMERO_SECRET_KEY", urandom(24))
    CHROME_DRIVER_VERSIONS = [None] + list(range(81, 77, -1))

    KEY_WHITELIST = {
        "CHUNK_SIZE",
        "ROW_LIMIT",
        "ERR_LIMIT",
        "WEBHOOKS",
    }

    # Variables warnings
    REQUIRED_SETTINGS = []
    REQUIRED_PROD_SETTINGS = []

    # Authentication
    AUTHENTICATION = {
        "gsheets": {
            "auth_type": "service",
            "service": {
                "keyfile_path": "internal-256716-b2f899ddbdc5.json",
                "sheet_id": "1Q-0R_q5-dWeaIAktvxRirZGXJZmMxd8qjVTujauMdak",
                "worksheet_name": "options",
                "scope": [
                    "https://spreadsheets.google.com/feeds",
                    "https://www.googleapis.com/auth/drive",
                ],
            },
        },
        # https://app.timelyapp.com/777870/oauth_applications
        "timely": {
            "auth_type": "oauth2",
            "oauth2": {
                "api_base_url": "https://api.timelyapp.com/1.1",
                "authorization_base_url": "https://api.timelyapp.com/1.1/oauth/authorize",
                "token_url": "https://api.timelyapp.com/1.1/oauth/token",
                "refresh_url": "https://api.timelyapp.com/1.1/oauth/token",
                "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
                "account_id": "777870",
                "client_id": getenv("TIMELY_CLIENT_ID"),
                "client_secret": getenv("TIMELY_SECRET"),
                "username": getenv("TIMELY_USERNAME"),
                "password": getenv("TIMELY_PASSWORD"),
            },
        },
        # https://developer.xero.com/myapps/
        "xero": {
            "auth_type": "oauth2",
            "oauth2": {
                "api_base_url": "https://api.xero.com",
                "authorization_base_url": "https://login.xero.com/identity/connect/authorize",
                "token_url": "https://identity.xero.com/connect/token",
                "refresh_url": "https://identity.xero.com/connect/token",
                "redirect_uri": f"http://localhost:5000{API_URL_PREFIX}/xero-callback",
                "domain": "projects",
                "client_id": getenv("XERO_CLIENT_ID"),
                "client_secret": getenv("XERO_SECRET"),
                "username": getenv("XERO_USERNAME"),
                "password": getenv("XERO_PASSWORD"),
                "scope": [
                    "projects",
                    "offline_access",
                    "accounting.transactions",
                    "accounting.settings",
                    "accounting.contacts",
                    "accounting.attachments",
                    "files",
                    "assets",
                ],
            },
            "oauth1": {
                "api_base_url": "https://api.xero.com",
                "request_url": "https://api.xero.com/oauth/RequestToken",
                "authorization_base_url": "https://api.xero.com/oauth/Authorize",
                "token_url": "https://api.xero.com/oauth/AccessToken",
                "client_id": getenv("XERO_CONSUMER_KEY"),
                "client_secret": getenv("XERO_CONSUMER_SECRET"),
                "headers": {
                    "post": {"Content-Type": "application/x-www-form-urlencoded"},
                },
            },
        },
    }

    # Webhooks
    WEBHOOKS = {
        "xero": {
            "signature_header": "x-xero-signature",
            "webhook_secret": getenv("XERO_WEBHOOK_SECRET"),
            "digest": "sha256",
            "b64_encode": True,
            "payload_key": "events",
        },
    }

    # RQ
    REQUIRED_PROD_SETTINGS += ["RQ_DASHBOARD_USERNAME", "RQ_DASHBOARD_PASSWORD"]
    RQ_DASHBOARD_REDIS_URL = (
        getenv("REDIS_URL") or getenv("REDISTOGO_URL") or __DEF_REDIS_URL__
    )
    RQ_DASHBOARD_USERNAME = getenv("RQ_DASHBOARD_USERNAME")
    RQ_DASHBOARD_PASSWORD = getenv("RQ_DASHBOARD_PASSWORD")
    RQ_DASHBOARD_DEBUG = False

    # Change based on mode
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
    defaultdb = f"postgres://{__USER__}@{__DEF_HOST__}/{__APP_NAME__.replace('-','_')}"
    SQLALCHEMY_DATABASE_URI = getenv("DATABASE_URL", defaultdb)

    # max 20 connections per dyno spread over 4 workers
    # look into a Null pool with pgbouncer
    # https://devcenter.heroku.com/articles/python-concurrency-and-database-connections
    SQLALCHEMY_POOL_SIZE = 3
    SQLALCHEMY_MAX_OVERFLOW = 2

    if __PROD_SERVER__:
        TALISMAN = True
        TALISMAN_FORCE_HTTPS_PERMANENT = True

        # https://stackoverflow.com/a/18428346/408556
        # https://github.com/Parallels/rq-dashboard/issues/328
        TALISMAN_CONTENT_SECURITY_POLICY = {
            "default-src": "'self'",
            "script-src": "'self' 'unsafe-inline' 'unsafe-eval'",
            "style-src": "'self' 'unsafe-inline'",
        }

    HOST = "0.0.0.0"


class Heroku(Production):
    HEROKU = True
    DOMAIN = "herokuapp.com"
    Config.AUTHENTICATION["timely"]["oauth2"][
        "redirect_uri"
    ] = f"https://{__SUB_DOMAIN__}.{DOMAIN}{Config.API_URL_PREFIX}/timely-callback"
    Config.AUTHENTICATION["xero"]["oauth2"][
        "redirect_uri"
    ] = f"https://{__SUB_DOMAIN__}.{DOMAIN}{Config.API_URL_PREFIX}/xero-callback"

    if __PROD_SERVER__:
        SERVER_NAME = f"{__SUB_DOMAIN__}.{DOMAIN}"
        logger.info(f"SERVER_NAME is {SERVER_NAME}")


class Custom(Production):
    DOMAIN = "nerevu.com"
    AUTHENTICATION = Config.AUTHENTICATION
    AUTHENTICATION["timely"]["oauth2"][
        "redirect_uri"
    ] = f"https://{__SUB_DOMAIN__}.{DOMAIN}{Config.API_URL_PREFIX}/timely-callback"
    AUTHENTICATION["xero"]["oauth2"][
        "redirect_uri"
    ] = f"https://{__SUB_DOMAIN__}.{DOMAIN}{Config.API_URL_PREFIX}/xero-callback"

    if __PROD_SERVER__:
        SERVER_NAME = f"{__SUB_DOMAIN__}.{DOMAIN}"
        logger.info(f"SERVER_NAME is {SERVER_NAME}")


class Development(Config):
    base = "sqlite:///{}?check_same_thread=False"
    ENV = "development"
    SQLALCHEMY_DATABASE_URI = base.format(p.join(PARENT_DIR, "app.db"))
    RQ_DASHBOARD_DEBUG = True
    DEBUG = True
    DEBUG_MEMCACHE = False
    DEBUG_QB_CLIENT = False
    CACHE_DEFAULT_TIMEOUT = get_seconds(hours=8)
    CHUNK_SIZE = 128
    ROW_LIMIT = 16
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    OAUTHLIB_INSECURE_TRANSPORT = True


class Ngrok(Development):
    # Xero localhost callbacks work fine
    AUTHENTICATION = Config.AUTHENTICATION
    AUTHENTICATION["xero"]["oauth2"][
        "redirect_uri"
    ] = f"https://nerevu-api.ngrok.io{Config.API_URL_PREFIX}/xero-callback"
    AUTHENTICATION["timely"]["oauth2"][
        "redirect_uri"
    ] = f"https://nerevu-api.ngrok.io{Config.API_URL_PREFIX}/timely-callback"


class Test(Config):
    ENV = "development"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    DEBUG = True
    DEBUG_MEMCACHE = False
    TESTING = True
    CACHE_DEFAULT_TIMEOUT = get_seconds(hours=1)
    CHUNK_SIZE = 64
    ROW_LIMIT = 8
    OAUTHLIB_INSECURE_TRANSPORT = True

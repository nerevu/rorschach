# -*- coding: utf-8 -*-
"""
    config
    ~~~~~~

    Provides the flask config options
    ###########################################################################
    # WARNING: if running on a a staging server, you MUST set the 'STAGE' env
    # heroku config:set STAGE=true remote staging

    # WARNING: The heroku project must either have a postgres, redis, or memcache db to
    # be recognized as production. If it is not recognized as production, Talisman
    # will not be run.
    ###########################################################################
"""
from os import getenv, urandom, path as p
from datetime import timedelta
from collections import namedtuple

from dotenv import load_dotenv
from mezmorize.utils import get_cache_config, get_cache_type

PARENT_DIR = p.abspath(p.dirname(__file__))

load_dotenv(p.join(PARENT_DIR, ".env"), override=True)
db_env_list = ["DATABASE_URL", "REDIS_URL", "MEMCACHIER_SERVERS", "REDISTOGO_URL"]

__USER__ = "reubano"
__APP_NAME__ = "api"
__PROD_SERVER__ = any(map(getenv, db_env_list))
__DEF_HOST__ = "127.0.0.1"

__STAG_SERVER__ = getenv("STAGE")
__END__ = "-stage" if __STAG_SERVER__ else ""
__SUB_DOMAIN__ = f"{__APP_NAME__}{__END__}"
__AUTHOR__ = "Reuben Cummings"
__AUTHOR_EMAIL__ = "rcummings@nerevu.com"

DAYS_PER_MONTH = 30
DAYS_PER_YEAR = 365
SECRET_ENV = f"{__APP_NAME__}_SECRET".upper()
HEROKU_PR_NUMBER = getenv("HEROKU_PR_NUMBER")
HEROKU_TEST_RUN_ID = getenv("HEROKU_TEST_RUN_ID")

Admin = namedtuple("Admin", ["name", "email"])
cache_type = get_cache_type(cache="redis")
redis_config = get_cache_config(cache_type)
get_path = lambda name: f"file://{p.join(PARENT_DIR, 'data', name)}"


def get_seconds(seconds=0, months=0, years=0, **kwargs):
    seconds = timedelta(seconds=seconds, **kwargs).total_seconds()

    if months:
        seconds += timedelta(DAYS_PER_MONTH).total_seconds() * months

    if years:
        seconds += timedelta(DAYS_PER_YEAR).total_seconds() * years

    return int(seconds)


def get_server_name(heroku=False):
    if HEROKU_PR_NUMBER:
        DOMAIN = "herokuapp.com"
        HEROKU_APP_NAME = getenv("HEROKU_APP_NAME")
        SUB_DOMAIN = f"{HEROKU_APP_NAME}-pr-{HEROKU_PR_NUMBER}"
    elif heroku or HEROKU_TEST_RUN_ID:
        DOMAIN = "herokuapp.com"
        SUB_DOMAIN = f"nerevu-{__SUB_DOMAIN__}"
    else:
        DOMAIN = "nerevu.com"
        SUB_DOMAIN = __SUB_DOMAIN__

    return f"{SUB_DOMAIN}.{DOMAIN}"


class Config(object):
    DEBUG = False
    TESTING = False
    DEBUG_MEMCACHE = True
    DEBUG_QB_CLIENT = False
    PARALLEL = False
    OAUTHLIB_INSECURE_TRANSPORT = False
    PROD_SERVER = __PROD_SERVER__

    # see http://bootswatch.com/3/ for available swatches
    FLASK_ADMIN_SWATCH = "cerulean"
    ADMIN = Admin(__AUTHOR__, __AUTHOR_EMAIL__)
    ADMINS = frozenset([ADMIN.email])
    HOST = "127.0.0.1"

    # These don't change
    ROUTE_DEBOUNCE = get_seconds(5)
    ROUTE_TIMEOUT = get_seconds(0)
    SET_TIMEOUT = get_seconds(days=30)
    FAILURE_TTL = get_seconds(hours=1)
    REPORT_MONTHS = 3
    LRU_CACHE_SIZE = 128
    REPORT_DAYS = REPORT_MONTHS * DAYS_PER_MONTH
    SEND_FILE_MAX_AGE_DEFAULT = ROUTE_TIMEOUT
    EMPTY_TIMEOUT = ROUTE_TIMEOUT * 10
    API_URL_PREFIX = "/v1"
    API_URL = f"http://localhost:5000{API_URL_PREFIX}"
    SECRET_KEY = SECRET = getenv(SECRET_ENV, urandom(24))
    CHROME_DRIVER_VERSIONS = [None] + list(range(87, 77, -1))

    APP_CONFIG_WHITELIST = {
        "CHUNK_SIZE",
        "ROW_LIMIT",
        "ERR_LIMIT",
        "ADMIN",
        "SECRET",
        "SECRET_KEY",
    }

    # Variables warnings
    REQUIRED_SETTINGS = []
    OPTIONAL_SETTINGS = []
    REQUIRED_PROD_SETTINGS = [SECRET_ENV]

    # Logging
    MAILGUN_DOMAIN = getenv("MAILGUN_DOMAIN")
    MAILGUN_SMTP_PASSWORD = getenv("MAILGUN_SMTP_PASSWORD")
    REQUIRED_PROD_SETTINGS += ["MAILGUN_DOMAIN", "MAILGUN_SMTP_PASSWORD"]

    # Authentication
    AUTHENTICATION = {
        # https://airtable.com/apph4M6HDXw0rWaYW/api/docs
        "airtable": {
            "auth_type": "bearer",
            "bearer": {
                "api_base_url": "https://api.airtable.com/v0/{base_id}",
                "token": getenv("AIRTABLE_API_KEY"),
                "params": {"maxRecords": 2048, "pageSize": 100, "offset": None},
                "attrs": {"base_id": getenv("AIRTABLE_BASE_ID"), "subkey": "records"},
            },
        },
        "mailgun": {
            "auth_type": "basic",
            "basic": {
                "api_base_url": "https://api.mailgun.net/v3/{domain}",
                "username": "api",
                "password": getenv("MAILGUN_API_KEY"),
                "attrs": {"domain": MAILGUN_DOMAIN, "json_data": False},
            },
        },
        # https://postmarkapp.com/developer/api/overview
        "postmark": {
            "auth_type": "custom",
            "custom": {
                "api_base_url": "https://api.postmarkapp.com",
                "params": {"count": 100, "offset": 0},
                "headers": {
                    "all": {
                        "X-Postmark-Server-Token": getenv("POSTMARK_SERVER_TOKEN"),
                        "X-Postmark-Account-Token": getenv("POSTMARK_ACCOUNT_TOKEN"),
                        "Content-Type": "application/json",
                    },
                },
            },
        },
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
                "api_base_url": "https://api.timelyapp.com/1.1/{account_id}",
                "api_status_resource": "accounts",
                "authorization_base_url": "https://api.timelyapp.com/1.1/oauth/authorize",
                "token_url": "https://api.timelyapp.com/1.1/oauth/token",
                "refresh_url": "https://api.timelyapp.com/1.1/oauth/token",
                "redirect_uri": "/timely-callback",
                "account_id": getenv("TIMELY_ACCOUNT_ID"),
                "client_id": getenv("TIMELY_CLIENT_ID"),
                "client_secret": getenv("TIMELY_SECRET"),
                "username": getenv("TIMELY_USERNAME"),
                "password": getenv("TIMELY_PASSWORD"),
                "method_map": {"patch": "put"},
                "param_map": {"start": "since", "end": "upto"},
                "attrs": {"singularize": True},
                "headless_elements": [
                    {
                        "selector": "#email",
                        "description": "timely email",
                        "content": getenv("TIMELY_USERNAME"),
                    },
                    {
                        "selector": "#next-btn",
                        "description": "next",
                        "action": "submit",
                    },
                    {
                        "selector": "#Email",
                        "description": "google email",
                        "content": getenv("GOOGLE_USERNAME"),
                    },
                    {"selector": "#next", "description": "next", "action": "submit"},
                    {
                        "selector": '[type="password"]',
                        "description": "google password",
                        "content": getenv("GOOGLE_PASSWORD"),
                    },
                    {
                        "selector": '#submit[type="submit"]',
                        "description": "google submit",
                        "action": "click",
                    },
                ],
            },
        },
        # https://developer.xero.com/myapps/
        "xero": {
            "auth_type": "oauth2",
            "oauth2": {
                "api_base_url": "https://api.xero.com/{domain}.xro/2.0",
                "api_status_resource": "connections",
                "authorization_base_url": "https://login.xero.com/identity/connect/authorize",
                "token_url": "https://identity.xero.com/connect/token",
                "refresh_url": "https://identity.xero.com/connect/token",
                "redirect_uri": "/xero-callback",
                "headers": {"all": {"Xero-tenant-id": "{tenant_id}"}},
                "client_id": getenv("XERO_CLIENT_ID"),
                "client_secret": getenv("XERO_SECRET"),
                "username": getenv("XERO_USERNAME"),
                "password": getenv("XERO_PASSWORD"),
                "param_map": {"start": "dateAfterUtc", "end": "dateBeforeUtc"},
                "attrs": {"domain": "projects"},
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
                "headless_elements": [
                    {
                        "selector": "#xl-form-email",
                        "description": "xero username",
                        "content": getenv("XERO_USERNAME"),
                    },
                    {
                        "selector": "#xl-form-password",
                        "description": "xero password",
                        "content": getenv("XERO_PASSWORD"),
                    },
                    {
                        "selector": "#xl-form-submit",
                        "description": "xero sign in",
                        "action": "click",
                    },
                    {
                        "selector": '[placeholder="Authentication code"]',
                        "description": "xero 2fa code",
                        "prompt": True,
                    },
                    {
                        "selector": '[type="submit"]',
                        "description": "xero confirm",
                        "action": "click",
                    },
                    {
                        "selector": "#approveButton",
                        "description": "xero connect",
                        "action": "click",
                    },
                    {
                        "selector": "#approveButton",
                        "description": "xero allow access",
                        "action": "click",
                        "wait": 5,
                    },
                    {
                        "selector": "#approveButton",
                        "description": "xero select org",
                        "action": "click",
                        "wait": 5,
                    },
                ],
            },
        },
    }

    OPTIONAL_SETTINGS += [
        "XERO_USERNAME",
        "XERO_PASSWORD",
    ]

    # Mailgun
    REQUIRED_PROD_SETTINGS += [
        "MAILGUN_API_KEY",
    ]
    OPTIONAL_SETTINGS += [
        "MAILGUN_LIST_PREFIX",
        "MAILGUN_PUBLIC_KEY",
    ]

    # Postmark
    REQUIRED_PROD_SETTINGS += [
        "POSTMARK_SERVER_TOKEN",
    ]
    OPTIONAL_SETTINGS += [
        "POSTMARK_ACCOUNT_TOKEN",
        "POSTMARK_TEMPLATE_ID",
    ]

    # AWS
    REQUIRED_PROD_SETTINGS += [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_REGION",
        "CLOUDFRONT_DISTRIBUTION_ID",
    ]

    # Webhooks
    WEBHOOKS = {
        "xero": {
            "signature_header": "x-xero-signature",
            "webhook_secret": getenv("XERO_WEBHOOK_SECRET"),
            "digest": "sha256",
            "b64_encode": True,
            "payload_key": "events",
            "activities": [],
        },
        "heroku": {
            "signature_header": "Heroku-Webhook-Hmac-SHA256",
            "webhook_secret": getenv("HEROKU_WEBHOOK_SECRET"),
            "digest": "sha256",
            "b64_encode": True,
            "payload_key": "action",
            "ignore_signature": True,
            "activities": [{"name": "update", "action": "invalidate_cf_distribution"}],
        },
        "timely": {"activities": [{"name": "new_event", "action": "add_xero_time"}]},
        "gsheets": {"activities": [{"name": "new_row", "action": "add_xero_time"}]},
        "nerevu": {
            "payload_key": "resourceId",
            "ignore_signature": True,
            "activities": [
                {
                    "name": "new_invoice",
                    "action": "send_invoice_notification",
                    "kwargs": {
                        "sender_email": "billing@nerevu.com",
                        "sender_name": "Nerevu Billing Team",
                        "recipient_email": "rcummings@nerevu.com",
                        "recipient_name": "Reuben Cummings",
                        "copied_email": None,
                        "blind_copied_email": "billing@nerevu.com",
                        "template_id": 12058975,
                        "debug": True,
                        "dry_run": False,
                        "prompt": True,
                    },
                },
                {
                    "name": "new_charge",
                    "action": "send_invoice_notification",
                    "kwargs": {
                        "sender_email": "billing@nerevu.com",
                        "sender_name": "Nerevu Billing Team",
                        "recipient_email": "rcummings@nerevu.com",
                        "recipient_name": "Reuben Cummings",
                        "copied_email": None,
                        "blind_copied_email": "billing@nerevu.com",
                        "template_id": 16342429,
                        "debug": True,
                        "dry_run": False,
                        "prompt": True,
                    },
                },
                {
                    "name": "new_payment",
                    "action": "send_payment_notification",
                    "kwargs": {
                        "sender_email": "billing@nerevu.com",
                        "sender_name": "Nerevu Billing Team",
                        "recipient_email": "rcummings@nerevu.com",
                        "recipient_name": "Reuben Cummings",
                        "copied_email": None,
                        "blind_copied_email": "billing@nerevu.com",
                        "template_id": 9956182,
                        "debug": True,
                        "dry_run": False,
                        "prompt": True,
                    },
                },
            ],
        },
    }

    REQUIRED_PROD_SETTINGS += [
        "XERO_WEBHOOK_SECRET",
        "HEROKU_WEBHOOK_SECRET",
    ]

    # RQ
    REQUIRED_PROD_SETTINGS += ["RQ_DASHBOARD_USERNAME", "RQ_DASHBOARD_PASSWORD"]
    RQ_DASHBOARD_REDIS_URL = redis_config.get("CACHE_REDIS_URL")
    RQ_DASHBOARD_DEBUG = False

    APP_CONFIG_WHITELIST.update(REQUIRED_SETTINGS)
    APP_CONFIG_WHITELIST.update(REQUIRED_PROD_SETTINGS)
    APP_CONFIG_WHITELIST.update(OPTIONAL_SETTINGS)

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
    server_name = get_server_name(True)
    API_URL = f"https://{server_name}{Config.API_URL_PREFIX}"

    if __PROD_SERVER__:
        SERVER_NAME = server_name


class Custom(Production):
    server_name = get_server_name()
    API_URL = f"https://{server_name}{Config.API_URL_PREFIX}"

    if __PROD_SERVER__:
        SERVER_NAME = server_name


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
    server_name = "nerevu-api.ngrok.io"
    API_URL = f"https://{server_name}{Config.API_URL_PREFIX}"


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

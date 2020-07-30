# -*- coding: utf-8 -*-
"""
    app.helpers
    ~~~~~~~~~~~

    Provides misc helper functions
"""
from inspect import getmembers, isclass
from importlib import import_module
from os import getenv

import inflect
import pygogo as gogo
import config

from config import Config, __APP_NAME__

p = inflect.engine()
singularize = p.singular_noun

ADMIN = Config.ADMIN
MAILGUN_DOMAIN = Config.MAILGUN_DOMAIN
MAILGUN_SMTP_PASSWORD = Config.MAILGUN_SMTP_PASSWORD

hkwargs = {"subject": f"{__APP_NAME__} notification", "recipients": [ADMIN.email]}

if MAILGUN_DOMAIN and MAILGUN_SMTP_PASSWORD:
    # NOTE: Sandbox domains are restricted to authorized recipients only.
    # https://help.mailgun.com/hc/en-us/articles/217531258
    mkwargs = {
        "host": getenv("MAILGUN_SMTP_SERVER", "smtp.mailgun.org"),
        "port": getenv("MAILGUN_SMTP_PORT", 587),
        "sender": f"notifications@{MAILGUN_DOMAIN}",
        "username": getenv("MAILGUN_SMTP_LOGIN", f"postmaster@{MAILGUN_DOMAIN}"),
        "password": MAILGUN_SMTP_PASSWORD,
    }

    hkwargs.update(mkwargs)

email_hdlr = gogo.handlers.email_hdlr(**hkwargs)


def configure(flask_config, **kwargs):
    if kwargs.get("config_file"):
        flask_config.from_pyfile(kwargs["config_file"])
    elif kwargs.get("config_envvar"):
        flask_config.from_envvar(kwargs["config_envvar"])
    elif kwargs.get("config_mode"):
        obj = getattr(config, kwargs["config_mode"])
        flask_config.from_object(obj)
    else:
        flask_config.from_envvar("APP_SETTINGS", silent=True)


def get_member(module, member_name, classes_only=True):
    predicate = isclass if classes_only else None

    for member in getmembers(module, predicate):
        if member[0].lower() == member_name.lower():
            return member[1]


def get_provider(prefix):
    provider_name = prefix.lower() if prefix else ""

    try:
        provider = import_module(f"app.providers.{provider_name}")
    except (ModuleNotFoundError, ValueError):
        provider = None

    return provider


def get_collection(prefix, collection="", **kwargs):
    if collection:
        provider = get_provider(prefix)
        Collection = get_member(provider, collection)
    else:
        Collection = None

    return Collection

# -*- coding: utf-8 -*-
"""
    app.helpers
    ~~~~~~~~~~~

    Provides misc helper functions
"""
import pdb

from inspect import getmembers, isclass
from importlib import import_module
from os import getenv
from traceback import format_exception
from json.decoder import JSONDecodeError
from logging import Formatter

import inflect
import pygogo as gogo
import config

from flask import current_app as app, has_request_context, request
from config import Config, __APP_NAME__
from pygogo.formatters import DATEFMT

p = inflect.engine()
singularize = p.singular_noun
logger = gogo.Gogo(__name__, monolog=True).logger
logger.propagate = False

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


def handleLoggingError(record=None, message=None, reason="Logging error."):
    message = message or record.getMessage()
    print(f"{reason} Make sure an SMTP server is running.")
    print("Try running `sudo postfix start`.")
    # # if this still doesn't work, try sending test email
    # echo "Postfix test" | mail -s "Test  Postfix" rcummings@nerevu.com
    # # check mail queue
    # mailq
    # # make sure postfix is correctly configured, clear queue, and try again
    # # see ~/dotfiles/fastmail.cf
    # postsuper -d ALL


email_hdlr = gogo.handlers.email_hdlr(**hkwargs)
email_hdlr.handleError = handleLoggingError


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


def log(message=None, ok=True, r=None, exit_on_completion=False, **kwargs):
    _logger = app.logger if has_request_context() else logger

    if r is not None:
        ok = r.ok

        try:
            message = r.json().get("message")
        except JSONDecodeError:
            message = r.text

    if message and ok:
        _logger.info(message)
    elif message:
        try:
            _logger.error(message)
        except ConnectionRefusedError:
            handleLoggingError(message=message, reason="SMTP connect refused.")

    if exit_on_completion:
        exit(0 if ok else 1)
    else:
        return ok


def exception_hook(etype, value, tb, debug=False, callback=None, **kwargs):
    exception = format_exception(etype, value, tb)

    try:
        info, error = exception[-2:]
    except ValueError:
        info, error = "", exception[0]

    message = f"Exception in:\n{info}\n{error}"
    log(message, ok=False)

    if debug:
        pdb.post_mortem(tb)

    callback() if callback else None


# https://flask.palletsprojects.com/en/1.1.x/logging/#injecting-request-information
class RequestFormatter(Formatter):
    def format(self, record):
        record.url = request.url if has_request_context() else "n/a"
        return super().format(record)


flask_format = (
    "[%(levelname)s %(asctime)s] via %(url)s in %(module)s:%(lineno)s: %(message)s"
)
flask_formatter = RequestFormatter(flask_format, datefmt=DATEFMT)
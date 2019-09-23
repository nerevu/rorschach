#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: sw=4:ts=4:expandtab

""" A script to manage development tasks """
from os import path as p
from subprocess import call, check_call, CalledProcessError
from urllib.parse import urlsplit, urlencode, parse_qs
from datetime import datetime as dt, timedelta

import pygogo as gogo

from flask import current_app as app, url_for
from flask_script import Server, Manager
from requests.exceptions import ConnectionError

from app import create_app, cache

BASEDIR = p.dirname(__file__)
DEF_PORT = 5000

manager = Manager(create_app)
manager.add_option("-m", "--cfgmode", dest="config_mode", default="Development")
manager.add_option("-f", "--cfgfile", dest="config_file", type=p.abspath)
manager.main = manager.run  # Needed to do `manage <command>` from the cli

logger = gogo.Gogo(__name__, monolog=True).logger
get_logger = lambda ok: logger.info if ok else logger.error


def log_resp(r, prefix):
    msg = r.json().get("message")
    message = "{}{}".format(prefix, msg) if prefix else msg

    if message:
        get_logger(r.ok)(message)


def notify_or_log(ok, message):
    get_logger(ok)(message)


@manager.option("-h", "--host", help="The server host")
@manager.option("-p", "--port", help="The server port")
@manager.option("-t", "--threaded", help="Run multiple threads", action="store_true")
def runserver(**kwargs):
    # Overriding the built-in `runserver` behavior
    """Runs the flask development server"""
    with app.app_context():
        kwargs["threaded"] = app.config["PARALLEL"]

        if app.config.get("SERVER"):
            parsed = urlsplit(app.config["SERVER"])
            host, port = parsed.netloc, parsed.port or DEF_PORT
        else:
            host, port = app.config["HOST"], DEF_PORT

        kwargs.setdefault("host", host)
        kwargs.setdefault("port", port)

        server = Server(**kwargs)
        args = [
            app,
            server.host,
            server.port,
            server.use_debugger,
            server.use_reloader,
            server.threaded,
            server.processes,
            server.passthrough_errors,
        ]

        server(*args)


@manager.option("-h", "--host", help="The server host")
@manager.option("-p", "--port", help="The server port")
@manager.option("-t", "--threaded", help="Run multiple threads", action="store_true")
def serve(**kwargs):
    # Alias for `runserver`
    """Runs the flask development server"""
    runserver(**kwargs)


@manager.command
def check():
    """Check staged changes for lint errors"""
    exit(call(p.join(BASEDIR, "helpers", "check-stage")))


@manager.option("-w", "--where", help="Modules to check")
def prettify(where):
    """Prettify code with black"""
    def_where = ["app", "manage.py", "config.py"]
    extra = where.split(" ") if where else def_where

    try:
        check_call(["black"] + extra)
    except CalledProcessError as e:
        exit(e.returncode)


@manager.option("-w", "--where", help="Modules to check")
@manager.option("-s", "--strict", help="Check with pylint", action="store_true")
def lint(where, strict):
    """Check style with linters"""
    def_where = ["app", "tests", "manage.py", "config.py"]
    extra = where.split(" ") if where else def_where

    args = ["pylint", "--rcfile=tests/standard.rc", "-rn", "-fparseable", "app"]

    try:
        check_call(["flake8"] + extra)
        check_call(args) if strict else None
    except CalledProcessError as e:
        exit(e.returncode)


@manager.option("-r", "--remote", help="the heroku branch", default="staging")
def add_keys(remote):
    """Deploy staging app"""
    cmd = "heroku keys:add ~/.ssh/id_rsa.pub --remote {}"
    check_call(cmd.format(remote).split(" "))


@manager.option("-r", "--remote", help="the heroku branch", default="staging")
def deploy(remote):
    """Deploy staging app"""
    branch = "master" if remote == "production" else "features"
    cmd = "git push origin {}"
    check_call(cmd.format(branch).split(" "))


@manager.command
def require():
    """Create requirements.txt"""
    cmd = "pip freeze -l | grep -vxFf dev-requirements.txt "
    cmd += "| grep -vxFf requirements.txt "
    cmd += "> base-requirements.txt"
    call(cmd.split(" "))


if __name__ == "__main__":
    manager.run()

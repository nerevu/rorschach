#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: sw=4:ts=4:expandtab

""" A script to manage development tasks """
import sys

from functools import partial
from glob import glob
from itertools import chain
from os import environ, path as p
from subprocess import CalledProcessError, call, check_call
from sys import exit
from urllib.parse import urlparse

import click
import pygogo as gogo

from click import Choice
from flask import current_app as app
from flask.cli import FlaskGroup, pass_script_info, with_appcontext
from flask.config import Config as FlaskConfig

from app import check_settings, create_app
from app.authclient import get_auth_client, get_json_response
from app.helpers import configure, email_hdlr, exception_hook
from config import Config


BASEDIR = p.dirname(__file__)
AUTHENTICATION = Config.AUTHENTICATION
CONFIG_MODES = ["Test", "Development", "Production", "Ngrok", "Custom", "Heroku"]
DEF_PY_WHERE = "app *.py"

logger = gogo.Gogo(__name__, high_hdlr=email_hdlr).logger
logger.propagate = False

sys.excepthook = partial(exception_hook, debug=True)


@click.group(cls=FlaskGroup, create_app=create_app)
@click.option(
    "-m",
    "--config-mode",
    type=Choice(CONFIG_MODES, case_sensitive=False),
    default="Development",
)
@click.option("-f", "--config-file", type=p.abspath)
@click.option("-e", "--config-envvar")
@pass_script_info
def manager(script_info, **kwargs):
    flask_config = FlaskConfig(BASEDIR)
    configure(flask_config, **kwargs)
    script_info.flask_config = flask_config

    if flask_config.get("ENV"):
        environ["FLASK_ENV"] = flask_config["ENV"]

    if flask_config.get("DEBUG"):
        environ["FLASK_DEBUG"] = str(flask_config["DEBUG"]).lower()


@manager.command()
@click.pass_context
def serve(ctx):
    """Runs the Flask server"""
    print("Deprecated. Use `manage run` instead.")
    # manager.get_command(ctx, 'run')()


@manager.command()
@click.pass_context
def help(ctx):
    """Shows the help message"""
    commands = "\n          ".join(manager.list_commands(ctx))
    print("Usage: manage <command> [OPTIONS]")
    print(f"commands: {commands}")


@manager.command()
@click.option("-m", "--method", help="The HTTP method", default="get")
@click.option(
    "-p",
    "--project-id",
    help="The Xero Project ID",
    default="f9d0e04b-f07c-423d-8975-418159180dab",
)
@click.option("-r", "--resource", help="The API Resource", default="time")
def test_oauth(method=None, resource=None, project_id=None, **kwargs):
    time_data = {
        "userId": "3f7626f2-5064-4499-a96c-e73653e5aa01",
        "taskId": "ed9d0041-3680-4011-a24a-a20e72210864",
        "dateUtc": "2019-12-05T12:00:00Z",
        "duration": 130,
        "description": "Billy Bobby Tables",
    }

    task_data = {
        "name": "Deep Fryer",
        "rate": {"currency": "USD", "value": 99.99},
        "chargeType": "TIME",
        "estimateMinutes": 120,
    }

    project_data = {
        "contactId": "566f4750-b349-490d-af8f-c13b0f5ee6fd",
        "name": "New Kitchen",
        "deadlineUtc": "2017-04-23T18:25:43.511Z",
        "estimateAmount": 99.99,
    }

    xero = get_auth_client("xero", **app.config)
    accept = ("Accept", "application/json")
    content_type = ("Content-Type", "application/x-www-form-urlencoded")

    try:
        tenant_id = ("Xero-tenant-id", xero.tenant_id)
    except AttributeError:
        tenant_id = ("Xero-tenant-id", "")

    DATA = {
        "time": time_data,
        "task": task_data,
        "project": project_data,
        "contact": {"Name": "ABC Limited"},
    }

    HEADERS = {
        (1, "post", "projects"): [accept, content_type],
        (1, "get", "projects"): [accept],
        (1, "post", "api"): [accept, content_type],
        (1, "get", "api"): [accept],
        (2, "post", "projects"): [accept, tenant_id],
        (2, "get", "projects"): [accept, tenant_id],
        (2, "post", "api"): [],
        (2, "get", "api"): [accept],
    }

    PAYLOAD = {
        (1, "post", "projects"): "json",
        (1, "post", "api"): "json",
        (2, "post", "projects"): "json",
        (2, "post", "api"): "json",
    }

    URLS = {
        "time": f"https://api.xero.com/projects.xro/2.0/projects/{project_id}/time",
        "task": f"https://api.xero.com/projects.xro/2.0/projects/{project_id}/tasks",
        "project": "https://api.xero.com/projects.xro/2.0/Projects",
        "contact": "https://api.xero.com/api.xro/2.0/Contacts",
        "invoice": "https://api.xero.com/api.xro/2.0/Invoices",
    }

    url = URLS[resource]
    data = DATA[resource]
    domain = urlparse(url).path.split("/")[1].split(".")[0]
    key = (app.config["XERO_OAUTH_VERSION"], method, domain)
    kwargs = {"method": method, "headers": dict(HEADERS[key])}

    if method == "post":
        kwargs[PAYLOAD[key]] = data

    json = get_json_response(url, xero, **kwargs)

    if json.get("message"):
        print(json["message"])

    if json.get("result"):
        print(json["result"])


def _lint_py(where, strict):
    """Check Python style with flake8"""
    where = where or DEF_PY_WHERE
    paths = list(chain(*map(glob, where.split(" "))))
    check_call(["flake8"] + paths)

    if strict:
        cmd_args = ["pylint", "--rcfile=tests/standard.rc", "-rn", "-fparseable", "app"]
        check_call(cmd_args)


def _black(where):
    """Prettify code with black"""
    where = where or DEF_PY_WHERE
    paths = list(chain(*map(glob, where.split(" "))))
    check_call(["black"] + paths)


def _isort(where):
    """Prettify imports with isort"""
    where = where or DEF_PY_WHERE
    paths = list(chain(*map(glob, where.split(" "))))
    check_call(["isort"] + paths)


@manager.command()
def check():
    """Check staged changes for lint errors"""
    exit(call(p.join(BASEDIR, "helpers", "check-stage")))


@manager.command()
@click.option("-w", "--where", help="Locations to check (space separated)")
@with_appcontext
def test(where):
    """Run nose tests"""
    exit("Not implemented!")


@manager.command()
@click.option("-w", "--where", help="Locations to check (space separated)")
def prettify(where):
    """Prettify code with black"""
    errors = []

    try:
        _black(where)
    except CalledProcessError as e:
        errors += [e]

    try:
        _isort(where)
    except CalledProcessError as e:
        errors += [e]

    exit(len(errors))


@manager.command()
@click.option("-w", "--where", help="Locations to check (space separated)")
@click.option(
    "-s", "--strict/--no-strict", help="Check Python files with pylint", default=False
)
def lint(where, strict):
    """Check style with linters"""
    errors = []

    try:
        _lint_py(where, strict)
    except CalledProcessError as e:
        errors += [e]

    exit(len(errors))


@manager.command()
@click.option("-r", "--remote", help="the heroku branch", default="staging")
def add_keys(remote):
    """Deploy staging app"""
    command = f"heroku keys:add ~/.ssh/id_rsa.pub --remote {remote}"
    exit(call(command.split(" ")))


@manager.command()
@click.option("-r", "--remote", help="the heroku branch", default="staging")
def deploy(remote):
    """Deploy staging app"""
    branch = "master" if remote == "production" else "features"
    command = f"git push origin {branch}"
    exit(call(command.split(" ")))


@manager.command()
def require():
    """Create requirements.txt"""
    command = "pip freeze -l | grep -vxFf dev-requirements.txt "
    command += "| grep -vxFf requirements.txt "
    command += "> base-requirements.txt"
    exit(call(command.split(" ")))


if __name__ == "__main__":
    manager.run()

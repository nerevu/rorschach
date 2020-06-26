#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: sw=4:ts=4:expandtab

""" A script to manage development tasks """
import sys

from os import path as p, getenv, environ
from subprocess import call, check_call, CalledProcessError
from urllib.parse import urlparse
from itertools import count, chain
from json.decoder import JSONDecodeError
from sys import exit
from traceback import print_exception

import pygogo as gogo
import click

from flask import current_app as app
from click import Choice
from flask.cli import FlaskGroup, pass_script_info
from flask.config import Config

from config import __APP_NAME__, __AUTHOR_EMAIL__

from app import create_app, services
from app.helpers import configure
from app.authclient import get_auth_client, get_response
from app.routes.auth import store as _store

from app.api import (
    Contacts,
    Inventory,
    Projects,
    ProjectTasks,
    ProjectTime,
    Tasks,
    Time,
    Users,
)

# collections
timely_users = Users("TIMELY", dictify=True, dry_run=True)
timely_events = Time("TIMELY", dictify=True, dry_run=True)
timely_projects = Projects("TIMELY", dictify=True, dry_run=True)
timely_tasks = Tasks("TIMELY", dictify=True, dry_run=True)
timely_project_tasks = ProjectTasks("TIMELY", dictify=True, dry_run=True)
xero_project_tasks = ProjectTasks("XERO", dictify=True, dry_run=True)
xero_project_time = ProjectTime("XERO", dictify=True, dry_run=True)

# data

BASEDIR = p.dirname(__file__)
DEF_WHERE = ["app", "manage.py", "config.py"]
COLLECTIONS = {
    "users": Users,
    "tasks": Tasks,
    "contacts": Contacts,
    "inventory": Inventory,
    "time": Time,
    "projects": Projects,
    "projecttasks": ProjectTasks,
    "projecttime": ProjectTime,
}

hdlr_kwargs = {
    "subject": f"{__APP_NAME__} notification",
    "recipients": [__AUTHOR_EMAIL__],
}

# mappings
sync_results = xero_project_time.results
added_events = set()
skipped_events = set()
patched_events = set()
unpatched_events = set()

if getenv("MAILGUN_SMTP_PASSWORD"):
    # NOTE: Sandbox domains are restricted to authorized recipients only.
    # https://help.mailgun.com/hc/en-us/articles/217531258
    def_username = f"postmaster@{getenv('MAILGUN_DOMAIN')}"
    mailgun_kwargs = {
        "host": getenv("MAILGUN_SMTP_SERVER", "smtp.mailgun.org"),
        "port": getenv("MAILGUN_SMTP_PORT", 587),
        "sender": f"notifications@{getenv('MAILGUN_DOMAIN')}",
        "username": getenv("MAILGUN_SMTP_LOGIN", def_username),
        "password": getenv("MAILGUN_SMTP_PASSWORD"),
    }

    hdlr_kwargs.update(mailgun_kwargs)

high_hdlr = gogo.handlers.email_hdlr(**hdlr_kwargs)
logger = gogo.Gogo(__name__, high_hdlr=high_hdlr).logger


def save_results(dry_run=False, **kwargs):
    if not dry_run:
        logger.debug("Saving results…\n")
        all_events = set(
            chain(added_events, skipped_events, patched_events, unpatched_events)
        )

        for event in all_events:
            sync_results[str(event)] = {
                "added": event in added_events,
                "patched": event in patched_events,
            }

        xero_project_time.results = sync_results


def info(_type, value, tb):
    print_exception(_type, value, tb)
    save_results()


sys.excepthook = info


def log(message=None, ok=True, r=None, **kwargs):
    if r is not None:
        ok = r.ok

        try:
            message = r.json().get("message")
        except JSONDecodeError:
            message = r.text

    if message and ok:
        logger.info(message)
    elif message:
        try:
            logger.error(message)
        except ConnectionRefusedError:
            logger.info("Connect refused. Make sure an SMTP server is running.")
            logger.info("Try running `sudo postfix start`.")
            logger.info(message)


@click.group(cls=FlaskGroup, create_app=create_app)
@click.option("-m", "--config-mode", default="Development")
@click.option("-f", "--config-file", type=p.abspath)
@click.option("-e", "--config-envvar")
@pass_script_info
def manager(script_info, **kwargs):
    flask_config = Config(BASEDIR)
    configure(flask_config, **kwargs)
    script_info.flask_config = flask_config

    if flask_config.get("ENV"):
        environ["FLASK_ENV"] = flask_config["ENV"]

    if flask_config.get("DEBUG"):
        environ["FLASK_DEBUG"] = str(flask_config["DEBUG"]).lower()


@manager.command()
@click.pass_context
def serve(ctx):
    """Check staged changes for lint errors"""
    print("Deprecated. Use `manage run` instead.")
    # manager.get_command(ctx, 'run')()


@manager.command()
@click.pass_context
def help(ctx):
    """Check staged changes for lint errors"""
    commands = ", ".join(manager.list_commands(ctx))
    print(f"Usage: manage <command> [OPTIONS]")
    print(f"commands: {commands}")


@manager.command()
@click.option(
    "-c",
    "--collection",
    type=Choice(COLLECTIONS, case_sensitive=False),
    default="users",
)
def prune(collection, **kwargs):
    """Remove duplicated and outdated mappings entries"""
    added_names = set()
    item_names = ["XERO", "TIMELY"]
    is_tasks = collection == "projecttasks"
    Collection = COLLECTIONS[collection.lower()]
    mappings = Collection("XERO", dictify=True, dry_run=True).mappings

    def gen_items():
        # if there are dupes, keep the most recent
        for item in reversed(mappings):
            if is_tasks:
                timely_project_id = str(item["timely"]["project"])
                timely_task_id = int(item["timely"]["task"])
                timely_project_tasks.rid = timely_project_id
                has_timely_task = timely_task_id in timely_project_tasks.data

                if not has_timely_task:
                    continue

                xero_project_id = item["xero"]["project"]
                xero_project_tasks.rid = xero_project_id
                xero_task_ids = {t["taskId"] for t in xero_project_tasks}
                valid = item["xero"]["task"] in xero_task_ids
            else:
                for name in item_names:
                    data = Collection(name, dictify=True, dry_run=True).data
                    valid = str(item[name.lower()]) in data

                    if not valid:
                        continue

            if valid:
                to_check = item["xero"]

                if is_tasks:
                    to_check = (to_check["task"], to_check["project"])

                if to_check not in added_names:
                    added_names.add(to_check)
                    yield item

    mappings = list(reversed(list(gen_items())))


@manager.command()
@click.option(
    "-p",
    "--prefix",
    type=Choice(["timely", "xero"], case_sensitive=False),
    default="xero",
)
@click.option(
    "-c",
    "--collection",
    type=Choice(COLLECTIONS, case_sensitive=False),
    default="users",
)
@click.option("-i", "--rid", help="resource ID")
@click.option("-d", "--dictify/--no-dictify", default=False)
def store(prefix, collection, **kwargs):
    """Save user info to cache"""
    Collection = COLLECTIONS[collection.lower()]
    _store(prefix.upper(), Collection, **kwargs)


@manager.command()
@click.option("-m", "--method", help="The HTTP method", default="get")
@click.option("-p", "--project-id", help="The Xero Project ID", default="f9d0e04b-f07c-423d-8975-418159180dab")
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
        "isChargeable": True,
        "chargeType": "TIME",
        "estimateMinutes": 120,
    }

    project_data = {
        "contactId": "566f4750-b349-490d-af8f-c13b0f5ee6fd",
        "name": "New Kitchen",
        "deadlineUtc": "2017-04-23T18:25:43.511Z",
        "estimateAmount": 99.99,
    }

    xero = get_auth_client("XERO", **app.config)
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
        (1, "post", "projects"): "data",
        (1, "post", "api"): "json",
        (2, "post", "projects"): "data",
        (2, "post", "api"): "data",
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

    response = get_response(url, xero, **kwargs)

    if response.get("message"):
        print(response["message"])

    if response.get("result"):
        print(response["result"])


@manager.command()
@click.option("-p", "--project-id", help="The Timely Project ID", default=2389295)
@click.option(
    "-s", "--start", help="The Timely event start position", type=int, default=0
)
@click.option("-e", "--end", help="The Timely event end position", type=int)
@click.option("-d", "--dry-run/--no-dry-run", help="Perform a dry run", default=False)
def sync(**kwargs):
    """Sync Timely events with Xero time entries"""
    logger.info(f"\nTimely Project {kwargs['project_id']}")
    logger.info("——————————————————————")

    if kwargs["end"]:
        _range = range(kwargs["start"], kwargs["end"])
    else:
        _range = count(kwargs["start"])

    logger.info("Adding events…")
    for pos in _range:
        result = services.add_xero_time(position=pos, **kwargs)
        event_id = result.get("event_id")

        if result["ok"] or result["conflict"]:
            added_events.add(str(event_id))
            message = result.get("message") or f"Added Timely event {event_id}"
            logger.info(f"- {message}")
        else:
            message = result.get("message") or "Unknown error!"

            if result["eof"]:
                break
            elif event_id:
                skipped_events.add(event_id)

            logger.info(f"- {message}")

    num_added_events = len(added_events)
    num_skipped_events = len(skipped_events)
    num_total_events = num_added_events + num_skipped_events

    if added_events:
        logger.info("\nPatching events…")

    for event_id in added_events:
        result = services.mark_billed(event_id, **kwargs)
        message = result.get("message")

        if result["ok"] or result["conflict"]:
            patched_events.add(event_id)
            event = timely_events.extract_model(int(event_id))

            if message:
                logger.info(f"- {message}")
            elif event:
                user_id = int(event["user.id"])
                project_id = int(event["project.id"])
                label_id = int(event["label_id"])
                task = timely_tasks.extract_model(label_id)
                user_name = timely_users.extract_model(user_id).get("name", "Unknown")
                event_time = event["duration.total_minutes"]
                task_name = task.get("name", "Unknown").split(" ")[0]
                event_day = event["day"]
                project_name = timely_projects.extract_model(project_id).get(
                    "name", "Unknown"
                )
                msg = f"- {user_name} did {event_time}m of {task_name} on {event_day} "
                msg += f"for {project_name}"
                logger.debug(msg)
            else:
                msg = f"- Event {event_id} patched, but not found in "
                msg += f"{timely_events.data_p}."
                logger.info(msg)
        else:
            unpatched_events.add(event_id)
            logger.info(f"- {message or 'Unknown error!'}")

    num_patched_events = len(patched_events)

    logger.info("------------------------------------")
    msg = f"Of {num_total_events} events: {num_added_events} added and "
    msg += f"{num_patched_events} patched"
    logger.info(msg)
    logger.info("------------------------------------")
    num_errors = len(skipped_events) + len(unpatched_events)
    save_results(**kwargs)
    exit(num_errors)


@manager.command()
def check():
    """Check staged changes for lint errors"""
    exit(call(p.join(BASEDIR, "helpers", "check-stage")))


@manager.command()
@click.option("-w", "--where", help="Requirement file", default=None)
def test(where):
    """Run nose tests"""
    cmd = "nosetests -xvw %s" % where if where else "nosetests -xv"
    return call(cmd, shell=True)


@manager.command()
@click.option("-w", "--where", help="Modules to check")
def prettify(where):
    """Prettify code with black"""
    extra = where.split(" ") if where else DEF_WHERE

    try:
        check_call(["black"] + extra)
    except CalledProcessError as e:
        exit(e.returncode)


@manager.command()
@click.option("-w", "--where", help="Modules to check")
@click.option("-s", "--strict/--no-strict", help="Check with pylint", default=False)
def lint(where, strict):
    """Check style with linters"""
    extra = where.split(" ") if where else DEF_WHERE

    args = ["pylint", "--rcfile=tests/standard.rc", "-rn", "-fparseable", "app"]

    try:
        check_call(["flake8"] + extra)
        check_call(args) if strict else None
    except CalledProcessError as e:
        exit(e.returncode)


@manager.command()
@click.option("-r", "--remote", help="the heroku branch", default="staging")
def add_keys(remote):
    """Deploy staging app"""
    cmd = "heroku keys:add ~/.ssh/id_rsa.pub --remote {}"
    check_call(cmd.format(remote).split(" "))


@manager.command()
@click.option("-r", "--remote", help="the heroku branch", default="staging")
def deploy(remote):
    """Deploy staging app"""
    branch = "master" if remote == "production" else "features"
    cmd = "git push origin {}"
    check_call(cmd.format(branch).split(" "))


@manager.command()
def require():
    """Create requirements.txt"""
    cmd = "pip freeze -l | grep -vxFf dev-requirements.txt "
    cmd += "| grep -vxFf requirements.txt "
    cmd += "> base-requirements.txt"
    call(cmd.split(" "))


if __name__ == "__main__":
    manager.run()

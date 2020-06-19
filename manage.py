#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: sw=4:ts=4:expandtab

""" A script to manage development tasks """
from os import path as p, getenv, environ
from subprocess import call, check_call, CalledProcessError
from urllib.parse import urlparse
from itertools import count, chain
from json import load, dump
from json.decoder import JSONDecodeError
from sys import exit

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
    sync_results_p,
    timely_users_p,
    timely_events_p,
    timely_projects_p,
    timely_tasks_p,
    xero_users_p,
    xero_projects_p,
    projects_p,
    users_p,
    tasks_p,
    HEADERS,
    get_auth_client,
    get_realtime_response,
)

from app.utils import load_path

BASEDIR = p.dirname(__file__)
DEF_WHERE = ["app", "manage.py", "config.py"]

hdlr_kwargs = {
    "subject": f"{__APP_NAME__} notification",
    "recipients": [__AUTHOR_EMAIL__],
}

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


# data
timely_users = load_path(timely_users_p, {})
timely_events = load_path(timely_events_p, {})
timely_projects = load_path(timely_projects_p, {})
timely_tasks = load_path(timely_tasks_p, {})
xero_users = load_path(xero_users_p, {})
xero_projects = load_path(xero_projects_p, {})

# mappings
projects = load(projects_p.open())
users = load(users_p.open())
tasks = load(tasks_p.open())

PRUNINGS = {
    "users": {
        "mapping": users,
        "save": users_p,
        "timely": timely_users,
        "xero": xero_users,
    },
    "projects": {
        "mapping": projects,
        "save": projects_p,
        "timely": timely_projects,
        "xero": xero_projects,
    },
    "tasks": {"mapping": tasks, "save": tasks_p},
}


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
@click.option("-f", "--file", help="The mapping file to prune", default="users")
def prune(**kwargs):
    """Remove duplicated and outdated mapping entries"""
    item_names = ["xero", "timely"]
    checking_name = item_names[0]
    added_names = set()
    _file = kwargs["file"]
    is_tasks = _file == "tasks"
    pruning = PRUNINGS[_file]

    def gen_items():
        # if there are dupes, keep the most recent
        for item in reversed(pruning["mapping"]):
            if is_tasks:
                timely_project_id = str(item["timely"]["project"])
                timely_task_id = str(item["timely"]["task"])
                timely_proj_tasks_p = Path(
                    f"app/data/timely_{timely_project_id}_tasks.json"
                )
                timely_proj_tasks = load_path(timely_proj_tasks_p, [])
                timely_task_ids = {str(t["id"]) for t in timely_proj_tasks}
                has_timely_task = timely_task_id in timely_task_ids

                if not has_timely_task:
                    continue

                xero_project_id = item["xero"]["project"]
                trunc_id = xero_project_id.split("-")[0]
                xero_task_id = item["xero"]["task"]
                xero_proj_tasks_p = Path(f"app/data/xero_{trunc_id}_tasks.json")
                xero_proj_tasks = load_path(xero_proj_tasks_p, [])
                xero_task_ids = {t["taskId"] for t in xero_proj_tasks}
                valid = xero_task_id in xero_task_ids
            else:
                valid = all(
                    str(item[name]) in str(pruning[name]) for name in item_names
                )

            if valid:
                to_check = item[checking_name]

                if is_tasks:
                    to_check = (to_check["task"], to_check["project"])

                if to_check not in added_names:
                    added_names.add(to_check)
                    yield item

    results = list(reversed(list(gen_items())))
    dump(results, pruning["save"].open(mode="w"), indent=2)


@manager.command()
@click.option("-m", "--method", help="The HTTP method", default="get")
@click.option("-r", "--resource", help="The API Resource", default="time")
def test_oauth(method=None, resource=None, **kwargs):
    project_id = "f9d0e04b-f07c-423d-8975-418159180dab"

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
    sync_results = load(sync_results_p.open())
    added_events = set()
    skipped_events = set()
    patched_events = set()
    unpatched_events = set()

    logger.info(f"Project ID {kwargs['project_id']}")
    logger.info("——————————————————")

    if kwargs["end"]:
        _range = range(kwargs["start"], kwargs["end"])
    else:
        _range = count(kwargs["start"])

    logger.info("Adding events…")
    for pos in _range:
        result = services.add_xero_time(position=pos, **kwargs)

        if result["eof"]:
            break
        elif result["ok"] or result["conflict"]:
            added_events.add(str(result["event_id"]))
            message = result["message"] or f"Added event {result['event_id']}"
            logger.info(f"- {message}")
        elif result.get("event_id"):
            skipped_events.add(result["event_id"])
            message = result["message"] or "Unknown error!"
            logger.info(f"- {message}")

    num_added_events = len(added_events)
    num_skipped_events = len(skipped_events)
    num_total_events = num_added_events + num_skipped_events

    if added_events:
        logger.info("\nPatching events…")

    for event_id in added_events:
        result = services.mark_billed(event_id, **kwargs)

        if result["ok"] or result["conflict"]:
            patched_events.add(event_id)
            event = timely_events.get(event_id)

            if result["message"]:
                logger.info(f"- {result['message']}")
            elif event:
                user_name = timely_users.get(str(event["user.id"]), {}).get(
                    "name", "Unknown"
                )
                project_name = timely_projects.get(str(event["project.id"]), {}).get(
                    "name", "Unknown"
                )
                task = timely_tasks.get(str(event["label_ids[0]"]), {})
                task_name = task.get("name", "Unknown").split(" ")[0]
                event_time = event["duration.total_minutes"]
                event_day = event["day"]
                logger.debug(
                    f"- {user_name} did {event_time}m of {task_name} on {event_day} for {project_name}"
                )
            else:
                logger.info(
                    f"- Event {event_id} patched, but not found in {timely_events_p}."
                )
        else:
            unpatched_events.add(event_id)
            message = result["message"] or "Unknown error!"
            logger.info(f"- {message}")

    num_patched_events = len(patched_events)
    all_events = set(
        chain(added_events, skipped_events, patched_events, unpatched_events)
    )

    if not kwargs["dry_run"]:
        for event in all_events:
            sync_results[event] = {
                "added": event in added_events,
                "patched": event in patched_events,
            }

    logger.info("------------------------------------")
    logger.info(
        f"Of {num_total_events} events: {num_added_events} added and {num_patched_events} patched"
    )
    logger.info("------------------------------------")
    dump(sync_results, sync_results_p.open(mode="w"), indent=2)
    exit(len(skipped_events) + len(unpatched_events))


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

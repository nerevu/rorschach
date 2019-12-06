#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: sw=4:ts=4:expandtab

""" A script to manage development tasks """
from os import path as p
from subprocess import call, check_call, CalledProcessError
from urllib.parse import urlsplit, urlencode, parse_qs
from datetime import datetime as dt, timedelta
from itertools import count, chain
from json import load, dump
from json.decoder import JSONDecodeError
from pathlib import Path
from sys import exit

import pygogo as gogo

from flask import current_app as app, url_for
from flask_script import Server, Manager
from requests.exceptions import ConnectionError

from app import create_app, cache, services
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
)

from app.utils import load_path

BASEDIR = p.dirname(__file__)
DEF_PORT = 5000

manager = Manager(create_app)
manager.add_option("-m", "--cfgmode", dest="config_mode", default="Development")
manager.add_option("-f", "--cfgfile", dest="config_file", type=p.abspath)
manager.main = manager.run  # Needed to do `manage <command>` from the cli

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


@manager.option("-f", "--file", help="The mapping file to prune", default="users")
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


@manager.option("-p", "--project-id", help="The Timely Project ID", default=2389295)
@manager.option(
    "-s", "--start", help="The Timely event start position", type=int, default=0
)
@manager.option("-e", "--end", help="The Timely event end position", type=int)
@manager.option("-d", "--dry-run", help="Perform a dry run", action="store_true")
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

        if result["ok"] or result["conflict"]:
            added_events.add(str(result["event_id"]))
            message = result["message"] or f"Added event {result['event_id']}"
            logger.info(f"- {message}")
        elif result["eof"]:
            break
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

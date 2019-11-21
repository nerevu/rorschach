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
from pathlib import Path
from sys import exit

import pygogo as gogo

from flask import current_app as app, url_for
from flask_script import Server, Manager
from requests.exceptions import ConnectionError

from app import create_app, cache, services
from app.api import (
    timely_users,
    timely_events,
    timely_events_p,
    timely_projects,
    timely_tasks,
    sync_results_p,
)


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


@manager.option("-p", "--project-id", help="The Timely Project ID", default=2389295)
@manager.option(
    "-s",
    "--start",
    help="The Timely event start position",
    type=int,
    default=0,
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

    logger.info("Adding events...")
    for pos in _range:
        result = services.add_xero_time(position=pos, **kwargs)

        if result["ok"] or result["conflict"]:
            added_events.add(str(result["event_id"]))
            message = result["message"] or f"Added Event {result['event_id']}"
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
        logger.info("\nPatching events...")

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

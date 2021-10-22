#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: sw=4:ts=4:expandtab

""" A script to manage development tasks """
import sys

from datetime import date, timedelta
from os import path as p, environ
from subprocess import call, check_call, CalledProcessError
from urllib.parse import urlparse
from itertools import count, chain
from sys import exit
from inspect import getmembers, isclass
from functools import partial

import pygogo as gogo
import click

from flask import current_app as app
from click import Choice, DateTime
from flask.cli import FlaskGroup, pass_script_info, with_appcontext
from flask.config import Config as FlaskConfig

from config import Config
from worker import initialize

from app import create_app, actions, check_settings
from app.helpers import (
    configure,
    get_collection,
    get_provider,
    email_hdlr,
    exception_hook,
    log,
)
from app.authclient import get_auth_client, get_json_response
from app.routes.auth import store as _store
from app.providers.xero import ProjectTime, ProjectTasks

# collections
xero_project_tasks = ProjectTasks(dictify=True, dry_run=True)
xero_project_time = ProjectTime(dictify=True, dry_run=True)

BASEDIR = p.dirname(__file__)
DEF_WHERE = ["app", "manage.py", "config.py"]
AUTHENTICATION = Config.AUTHENTICATION
ACTIONS = {
    "invoice": actions.send_invoice_notification,
    "charge": actions.send_invoice_notification,
    "payment": actions.send_invoice_notification,
}

DEF_END = date.today().strftime("%Y-%m-%d")
DEF_START = (date.today() - timedelta(days=Config.REPORT_DAYS)).strftime("%Y-%m-%d")


def gen_collection_names(prefixes):
    for prefix in prefixes:
        provider = get_provider(prefix)

        for member in getmembers(provider, isclass):
            yield member[0]


COLLECTION_NAMES = set(gen_collection_names(AUTHENTICATION))


# mappings
sync_results = xero_project_time.results
added_events = set()
skipped_events = set()
patched_events = set()
unpatched_events = set()

logger = gogo.Gogo(__name__, high_hdlr=email_hdlr).logger
logger.propagate = False


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


sys.excepthook = partial(exception_hook, debug=True)


def gen_collections(collection):
    for prefix in AUTHENTICATION:
        Collection = get_collection(prefix, collection)

        if Collection:
            yield (prefix, Collection)


@click.group(cls=FlaskGroup, create_app=create_app)
@click.option("-m", "--config-mode", default="Development")
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
    """Check staged changes for lint errors"""
    print("Deprecated. Use `manage run` instead.")
    # manager.get_command(ctx, 'run')()


@manager.command()
@click.pass_context
def help(ctx):
    """Check staged changes for lint errors"""
    commands = ", ".join(manager.list_commands(ctx))
    print("Usage: manage <command> [OPTIONS]")
    print(f"commands: {commands}")


@manager.command()
@click.option(
    "-P",
    "--source-prefix",
    type=Choice(["timely", "gsheets"], case_sensitive=False),
    default="timely",
)
@click.option(
    "-c",
    "--collection-name",
    type=Choice(COLLECTION_NAMES, case_sensitive=False),
    default="users",
)
def prune(source_prefix, collection_name, **kwargs):
    """Remove duplicated and outdated mappings entries"""
    provider = get_provider(source_prefix)
    added_names = set()
    collection_name = collection_name.lower()
    is_tasks = collection_name == "projecttasks"

    project_tasks = provider.ProjectTasks(dictify=True, dry_run=True)
    XeroCollection = get_collection("xero", collection_name)
    mappings = XeroCollection(dictify=True, dry_run=True).mappings
    COLLECTIONS = dict(gen_collections(collection_name))

    def gen_items():
        # if there are dupes, keep the most recent
        for item in reversed(mappings):
            if is_tasks:
                if source_prefix not in item:
                    continue

                project_id = item[source_prefix]["project"]
                task_id = item[source_prefix]["task"]
                project_tasks.rid = project_id
                has_task = task_id in project_tasks.data

                if not has_task:
                    continue

                xero_project_id = item["xero"]["project"]
                xero_project_tasks.rid = xero_project_id
                xero_task_ids = {t["taskId"] for t in xero_project_tasks}
                valid = item["xero"]["task"] in xero_task_ids
            else:
                for prefix in AUTHENTICATION:
                    if prefix not in COLLECTIONS:
                        continue

                    Collection = COLLECTIONS[prefix]
                    data = Collection(prefix, dictify=True, dry_run=True).data

                    if prefix.lower() not in item:
                        continue

                    valid = str(item[prefix.lower()]) in data

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
    "-P",
    "--prefix",
    type=Choice(["timely", "xero", "gsheets"], case_sensitive=False),
    default="xero",
)
@click.option(
    "-c",
    "--collection-name",
    type=Choice(COLLECTION_NAMES, case_sensitive=False),
    default="users",
)
@click.option("-i", "--rid", help="resource ID")
@click.option("-d", "--dictify/--no-dictify", default=False)
@click.option("-e", "--debug", help="Debug mode", is_flag=True)
@click.option("-h", "--headless/--no-headless", default=False)
@click.option(
    "-s",
    "--start",
    help="the start date",
    type=DateTime(["%Y-%m-%d", "%m/%d/%y"]),
    default=DEF_START,
)
@click.option(
    "-E",
    "--end",
    help="the end date",
    type=DateTime(["%Y-%m-%d", "%m/%d/%y"]),
    default=DEF_END,
)
def store(prefix, collection_name, **kwargs):
    """Save user info to cache"""
    _store(prefix, collection_name, **kwargs)


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


@manager.command()
@click.option(
    "-P",
    "--source-prefix",
    type=Choice(["timely", "gsheets"], case_sensitive=False),
    default="timely",
)
@click.option("-p", "--project-id", help="The Timely Project ID", default="2389295")
@click.option(
    "-S", "--start-pos", help="The Timely event start position", type=int, default=0
)
@click.option("-D", "--end-pos", help="The Timely event end position", type=int)
@click.option("-e", "--debug", help="Debug mode", is_flag=True)
@click.option("-d", "--dry-run/--no-dry-run", help="Perform a dry run", default=False)
@click.option(
    "-s",
    "--start",
    help="the start date",
    type=DateTime(["%Y-%m-%d", "%m/%d/%y"]),
    default=DEF_START,
)
@click.option(
    "-E",
    "--end",
    help="the end date",
    type=DateTime(["%Y-%m-%d", "%m/%d/%y"]),
    default=DEF_END,
)
def sync(source_prefix, **kwargs):
    """Sync Timely/GSheets events with Xero time entries"""
    sys.excepthook = partial(exception_hook, debug=True, callback=save_results)
    provider = get_provider(source_prefix)
    message = f"{source_prefix} Project {kwargs['project_id']}"
    logger.info(f"\n{message}")
    logger.info("—" * len(message))

    if kwargs["end_pos"]:
        _range = range(kwargs["start_pos"], kwargs["end_pos"])
    else:
        _range = count(kwargs["start_pos"])

    logger.info("Adding events…")

    for pos in _range:
        result = actions.add_xero_time(source_prefix, position=pos, **kwargs)
        event_id = result.get("event_id")

        if result["ok"] or result["conflict"]:
            added_events.add(str(event_id))
            message = result.get("message") or f"Added {source_prefix} event {event_id}"
            logger.info(f"- {message}")
        else:
            message = result.get("message") or "Unknown error!"

            if result["eof"]:
                break
            elif event_id:
                skipped_events.add(event_id)

            logger.info(f"- {message}")

            if result["status_code"] == 401:
                exit(1)

    num_added_events = len(added_events)
    num_skipped_events = len(skipped_events)
    num_total_events = num_added_events + num_skipped_events

    if added_events:
        logger.info("\nPatching events…")

    events = provider.Time(dictify=True, dry_run=True)
    tasks = provider.Tasks(dictify=True, dry_run=True)
    users = provider.Users(dictify=True, dry_run=True)
    projects = provider.Projects(dictify=True, dry_run=True)

    for event_id in added_events:
        result = actions.mark_billed(source_prefix, event_id, **kwargs)
        message = result.get("message")

        if result["ok"] or result["conflict"]:
            patched_events.add(event_id)
            event = events.extract_model(event_id)

            if message:
                logger.info(f"- {message}")
            elif event:
                user_id = event["user.id"]
                user = users.extract_model(user_id)
                user_name = user.get(users.name_field, "Unknown")

                project_id = event["project.id"]
                project = projects.extract_model(project_id)
                project_name = project.get(projects.name_field, "Unknown")

                label_id = event["label_id"]
                task = tasks.extract_model(label_id)
                task_name = task.get(tasks.name_field, "Unknown").split(" ")[0]

                event_time = event["duration.total_minutes"]
                event_day = event["day"]
                msg = f"- {user_name} did {event_time}m of {task_name} on {event_day} "
                msg += f"for {project_name}"
                logger.debug(msg)
            else:
                msg = f"- Event {event_id} patched, but not found in {events.data_p}."
                logger.info(msg)
        else:
            unpatched_events.add(event_id)
            logger.info(f"- {message or 'Unknown error!'}")

    num_patched_events = len(patched_events)

    msg = f"Of {num_total_events} events: {num_added_events} added and "
    msg += f"{num_patched_events} patched"
    logger.info("-" * len(msg))
    logger.info(msg)
    logger.info("-" * len(msg))
    num_errors = len(skipped_events) + len(unpatched_events)
    save_results(**kwargs)
    exit(num_errors)


@manager.command()
@click.argument("resource-id")
@click.option(
    "-a",
    "--activity",
    type=Choice(["invoice", "charge", "payment"], case_sensitive=False),
    help="The activity to perform.",
    default="invoice",
)
@click.option(
    "-e",
    "--sender-email",
    help="The sender's email address",
    default="billing@nerevu.com",
)
@click.option(
    "-n", "--sender-name", help="The sender's name", default="Nerevu Billing Team"
)
@click.option("-r", "--recipient-email", help="The recipient's email address")
@click.option("-m", "--recipient-name", help="The recipient's name")
@click.option("-c", "--copied-email", help="The cc'd email address")
@click.option("-t", "--template-id", help="The Postmark template ID")
@click.option("-e", "--debug", help="Debug mode", is_flag=True)
@click.option("-d", "--dry-run/--no-dry-run", help="Perform a dry run", default=False)
@click.option(
    "-p", "--prompt/--no-prompt", help="Prompt before sending email", default=False
)
def notify(resource_id, activity, **kwargs):
    """Send Xero invoice notification"""
    action = ACTIONS[activity]
    json = action(resource_id, **kwargs)

    try:
        log(**json, exit_on_completion=True)
    except Exception:
        pass


@manager.command()
def check():
    """Check staged changes for lint errors"""
    exit(call(p.join(BASEDIR, "helpers", "check-stage")))


@manager.command()
@click.option("-w", "--where", help="Requirement file", default=None)
@with_appcontext
def test(where):
    """Run nose tests"""
    extra = where.split(" ") if where else DEF_WHERE
    return_code = 0

    try:
        check_call(["black"] + extra)
    except CalledProcessError as e:
        return_code = e.returncode
    else:
        return_code = 1 if check_settings(app) else 0

    exit(return_code)


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
@click.option(
    "-l",
    "--listen",
    help="priorities to listen to",
    multiple=True,
    type=Choice(["high", "default", "low"]),
    default=["high", "default", "low"],
)
def work(listen):
    """Starts rq listening for work requests"""
    initialize(listen)


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

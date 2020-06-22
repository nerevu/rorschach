# -*- coding: utf-8 -*-
"""
    app.api
    ~~~~~~~

    Provides additional api endpoints
"""
from itertools import chain
from functools import wraps, partial
from subprocess import call
from json import load

import pygogo as gogo

from flask import Blueprint, request, current_app as app
from faker import Faker
from flask.views import MethodView

from config import Config

from app import cache
from app.utils import (
    jsonify,
    parse_request,
    parse_kwargs,
    cache_header,
    make_cache_key,
    get_links,
)

from app.routes import auth
from app.routes.auth import Resource, process_result, DATA_DIR
from app.mappings import USERS, NAMES, POSITIONS, gen_task_mapping

logger = gogo.Gogo(__name__, monolog=True).logger
blueprint = Blueprint("API", __name__)
fake = Faker()

ROUTE_TIMEOUT = Config.ROUTE_TIMEOUT
PREFIX = Config.API_URL_PREFIX
BILLABLE = 1344430
NONBILLABLE = 1339635

sync_results_p = DATA_DIR.joinpath("sync_results.json")
sync_results = load(sync_results_p.open())
timely_tasks_filterer = lambda item: not (item.get("billed") or item.get("deleted"))


def get_request_base():
    return request.base_url.split("/")[-1].split("?")[0]


def timely_tasks_processor(result, fields, **kwargs):
    _billable = (r["children"] for r in result if str(r["id"]) == str(BILLABLE))
    _non_billable = (r["children"] for r in result if str(r["id"]) == str(NONBILLABLE))

    try:
        billable_args = (next(_billable), fields)
    except StopIteration:
        billable = []
    else:
        billable = process_result(*billable_args, billable=True)

    try:
        non_billable_args = (next(_non_billable), fields)
    except StopIteration:
        non_billable = []
    else:
        non_billable = process_result(*non_billable_args, billable=False)

    return chain(billable, non_billable)


def timely_project_tasks_processor(result, fields, timely_tasks=None, **kwargs):
    result = map(str, result)
    timely_project_tasks = kwargs.pop("timely_project_tasks")
    project_id = timely_project_tasks.rid
    result = (timely_tasks[item] for item in result if timely_tasks.data.get(item))
    return process_result(result, fields, projectId=project_id, **kwargs)


def xero_events_processor(result, fields, **kwargs):
    result = process_result(result, fields, **kwargs)
    return ({**item, "day": item["dateUtc"].split("T")[0]} for item in result)


def fetch_choice(choices):
    call(["say", "enter a value"])
    pos = None

    while pos is None:
        answer = input(f"{choices}: ")

        try:
            pos = int(answer or "0")
        except ValueError:
            logger.error(f"Invalid selection: {answer}.")

    return pos


def fetch_bool(message):
    call(["say", "enter a value"])
    invalid = True

    while invalid:
        answer = input(f"{message} [y/n]: ")

        if answer in {"y", "n"}:
            invalid = False
        else:
            logger.error(f"Invalid selection: {answer}.")

    return answer


def get_task_entry(rid, mapped_rid, **kwargs):
    timely_tasks = kwargs["timely_tasks"]
    timely_project = kwargs["timely_project"]
    xero_project = kwargs["xero_project"]
    timely_task = timely_tasks.data.get(mapped_rid)

    return {
        "timely": {
            "task": mapped_rid,
            "project": timely_project["id"],
            "users": USERS[timely_task["user.id"]],
        },
        "xero": {"task": rid, "project": xero_project["id"]},
    }


def get_position_user_ids(timely_task, field="name"):
    timely_task_name = timely_task[field]
    position_name = timely_task_name.split("(")[1][:-1]

    if position_name in POSITIONS:
        user_ids = POSITIONS[position_name]
    else:
        logger.debug(f"Position map doesn't contain position '{position_name}'!")
        user_ids = []

    return user_ids


def get_timely_task_patch_data(timely_tasks, **kwargs):
    # data = get_timely_task_patch_data(timely_tasks)
    # timely_tasks.patch(**data)
    data = {}

    if sync_results.get(timely_tasks.rid, {}).get("patched"):
        logger.error(f"Event {timely_tasks.rid} already patched!")
        # response = {"status_code": 409}
    elif kwargs.get("billed"):
        logger.error(f"Event {timely_tasks.rid} already billed!")
        # response = {"status_code": 409}
    else:
        total_minutes = kwargs["duration.total_minutes"]

        data = {
            "id": timely_tasks.rid,
            "day": kwargs["day"],
            "hours": total_minutes // 60,
            "minutes": total_minutes % 60,
            "billed": True,
            "user_id": kwargs["user.id"],
        }

    return data


def get_xero_project_data(timely_project, xero_contact):
    if xero_contact:
        project_data = {
            "contactId": xero_contact["ContactID"],
            "name": timely_project["name"],
        }

        if timely_project.get("budget"):
            project_data["estimateAmount"] = timely_project["budget"]
    else:
        # logger.debug(f"Manually add {client_name}.")
        project_data = {}

    return project_data


def get_matching_xero_postions(uid, names, resource, field="name", **kwargs):
    timely_user = kwargs["timely_user"]
    user_name = timely_user["name"]
    logger.debug(f"Loading {resource} choices for {user_name}:{names}…")
    matching_tasks = [r for r in resource if any(n in r[field] for n in names)]
    return [t for t in matching_tasks if uid in get_position_user_ids(t, field=field)]


def get_xero_task_data(xero_project_tasks, timely_task, **kwargs):
    xero_inventory = kwargs["xero_inventory"]
    uid = timely_task["user.id"]
    timely_task_name = timely_task["name"]
    task_name = timely_task_name.split("(")[1][:-1]
    names = NAMES[task_name]
    args = (uid, names, xero_project_tasks)
    matching_task_positions = get_matching_xero_postions(*args, **kwargs)

    if kwargs.get("use_inventory"):
        task_position_names = {t["name"] for t in matching_task_positions}
        matching_inventory_positions = get_matching_xero_postions(
            uid, names, xero_inventory, field="Name"
        )
        matching_positions = [
            m
            for m in matching_inventory_positions
            if m["Name"] not in task_position_names
        ]

        matching = list(
            enumerate(
                f"{m['Name']} - {m['SalesDetails']['UnitPrice']}"
                for m in matching_positions
            )
        )
    else:
        matching = list(enumerate(m["name"] for m in matching_task_positions))
        # TODO: why is there a dupe task?
        # Loading task choices for Open Peoria:Reuben Cummings:Development…
        # [
        #     (0, '1 Hour Development (Pro-Bono)'),
        #     (1, '1 Hour Internal Work (Non-Billable)'),
        #     (2, '1 Hour Internal Work (Non-Billable)'),
        #     (3, 'None of the previous tasks')
        # ]

    none_of_prev = [(len(matching), "None of the previous tasks")]
    choices = matching + none_of_prev
    pos = fetch_choice(choices) if choices else None

    try:
        item = matching_positions[pos]
    except (IndexError, TypeError):
        # logger.error(f"Task {trunc_name} not found!.")
        task_data = {}
    else:
        rate = item["SalesDetails"]["UnitPrice"]
        task_data = {
            "name": item["Name"],
            "rate": {"currency": "USD", "value": rate},
            "chargeType": "TIME" if rate else "NON_CHARGEABLE",
            "isChargeable": bool(rate),
        }

    return task_data


def convertor(rid_field="id", name_field="name"):
    def decorator(after_create):
        @wraps(after_create)
        def wrapper(dest_resource, mapped_item, mapped_rid=None, **kwargs):
            error_msg = ""
            name = mapped_item[name_field]

            if mapped_rid:
                name += f" ({mapped_rid})"
            else:
                mapped_rid = mapped_item[rid_field]

            dry_run, dest_resource.dry_run = dest_resource.dry_run, True

            dest_item = extract_model(
                dest_resource, mapped_rid=mapped_rid, mapped_name=name
            )
            dest_resource.dry_run = dry_run

            if not (dest_item or dest_resource.rid):
                error_msg = f"No ID found for project {name}. "
            else:
                message = f"Project {name} not found in {dest_resource} cache. "

                if dry_run:
                    message += "Not searching online because 'dry_run' mode is on."
                else:
                    message += "Searching online for it…"
                    logger.debug(message)
                    dest_item = extract_model(dest_resource, update_cache=True)

                    if dest_item:
                        dest_resource.update_mappings(mapped_rid)

            if not (dest_item or dry_run):
                message = f"Project {name} not found in {dest_resource}. "
                message += f"Do you want to create it?"
                answer = fetch_bool(message)

                if answer == "y":
                    dest_item = after_create(mapped_item, dest_resource, name)

            if error_msg:
                logger.error(error_msg)

            if dry_run:
                error_msg = f"Disable dry_run mode to create {dest_resource} mapping."
            else:
                error_msg = f"Manually add {name} to {dest_resource}."

            assert dest_item, (error_msg, 404)
            return dest_item

        return wrapper

    return decorator


@convertor()
def timely_client_to_xero_contact(xero_contacts, timely_client):
    name = timely_client["Name"]
    response = xero_contacts.post(Name=name)
    json = response.json

    if response["ok"]:
        xero_contact = json["result"]["Contacts"][0]
    else:
        logger.error(json.get("message"))
        xero_contact = {}

    return xero_contact


@convertor()
def timely_project_to_xero_project(xero_projects, timely_project, **kwargs):
    xero_contact = kwargs["xero_contact"]
    project_data = get_xero_project_data(timely_project, xero_contact)

    if project_data:
        response = xero_projects.post(**project_data)
        json = response.json

        if response["ok"]:
            xero_project = json["result"]
        else:
            logger.error(json.get("message"))
            xero_project = {}

    return xero_project


@convertor()
def timely_task_to_xero_task(xero_project_tasks, timely_task, **kwargs):
    task_data = get_xero_task_data(xero_project_tasks, timely_task, **kwargs)

    if task_data:
        response = xero_project_tasks.post(**task_data)
        json = response.json

        if response["ok"]:
            xero_task = json["result"]
        else:
            logger.error(json.get("message"))
            xero_task = {}

    return xero_task


@convertor()
def timely_user_to_xero_user(xero_users, timely_user):
    name = timely_user["Name"]
    response = xero_users.post(Name=name)
    json = response.json

    if response["ok"]:
        xero_user = json["result"]["Contacts"][0]
    else:
        logger.error(json.get("message"))
        xero_user = {}

    return xero_user


def extract_model(collection, rid=None, pos=None, strict=False, *args, **kwargs):
    response = collection.get(rid, *args, **kwargs)
    json = response.json
    result = json["result"]

    try:
        model = result[pos or 0]
    except (IndexError, TypeError):
        model = {}

    if json["ok"]:
        error = (f"{collection} doesn't exist!", 404)
    else:
        message = json.get("message") or json["status"]
        error = (message, response.status_code)

    if strict:
        assert model, error
        assert model.get(collection.id_field), (f"{collection} has no ID!", 500)

    return model


###########################################################################
# ROUTES
###########################################################################
@blueprint.route("/")
@blueprint.route(PREFIX)
@cache_header(ROUTE_TIMEOUT, key_prefix=make_cache_key)
def home():
    response = {
        "description": "Returns API documentation",
        "message": f"Welcome to the Timero API!",
        "links": get_links(app.url_map.iter_rules()),
    }

    return jsonify(**response)


@blueprint.route(f"{PREFIX}/ipsum")
@cache_header(ROUTE_TIMEOUT, key_prefix=make_cache_key)
def ipsum():
    response = {
        "description": "Displays a random sentence",
        "links": get_links(app.url_map.iter_rules()),
        "result": fake.sentence(),
    }

    return jsonify(**response)


###########################################################################
# METHODVIEW ROUTES
###########################################################################
class Projects(Resource):
    def __init__(self, prefix, **kwargs):
        if prefix == "TIMELY":
            fields = ["id", "name", "active", "billable", "client", "budget"]
        elif prefix == "XERO":
            fields = ["projectId", "name", "status"]
            kwargs.update({"subkey": "items"})

        super().__init__(prefix, "projects", fields=fields, **kwargs)


class Users(Resource):
    def __init__(self, prefix, **kwargs):
        if prefix == "TIMELY":
            fields = ["id", "name"]
            resource = "users"
        elif prefix == "XERO":
            fields = ["userId", "name"]
            resource = "projectsusers"
            kwargs.update({"subkey": "items"})

        super().__init__(prefix, resource, fields=fields, **kwargs)


class Contacts(Resource):
    def __init__(self, prefix, **kwargs):
        if prefix == "XERO":
            fields = ["ContactID", "Name", "FirstName", "LastName"]
            kwargs.update({"subkey": "Contacts", "domain": "api"})

        super().__init__(prefix, "Contacts", fields=fields, **kwargs)


class Inventory(Resource):
    def __init__(self, prefix, **kwargs):
        if prefix == "XERO":
            fields = ["ItemID", "Name", "Code", "Description", "SalesDetails"]
            kwargs.update({"subkey": "Items", "domain": "api"})

        super().__init__(prefix, "Items", fields=fields, **kwargs)


class Tasks(Resource):
    def __init__(self, prefix, **kwargs):
        if prefix == "TIMELY":
            fields = ["id", "name"]
            resource = "labels"
            kwargs.update(
                {"processor": timely_tasks_processor, "filterer": timely_tasks_filterer}
            )

        super().__init__(prefix, resource, fields=fields, **kwargs)


class Time(Resource):
    def __init__(self, prefix, **kwargs):
        self.event_pos = int(kwargs.pop("event_pos", 0))

        if prefix == "TIMELY":
            fields = [
                "id",
                "day",
                "duration.total_minutes",
                "label_ids[0]",
                "project.id",
                "user.id",
                "note",
                "billed",
            ]

        super().__init__(prefix, "events", fields=fields, **kwargs)

    def _patch(self):
        assert self.prefix == "TIMELY", (
            f"PATCH is not yet configured for {self.prefix}",
            404,
        )
        assert self.rid, ("No 'rid' given!", 500)

        patched = self.results.get(self.rid, {}).get("patched")
        assert not patched, (f"{self} already added!", 409)

        self.timely_event = extract_model(self, update_cache=True, strict=True)
        assert not self.timely_event["billed"], (f"{self} already billed!", 409)

    def patch(self):
        # url = 'http://localhost:5000/v1/timely-time'
        # r = requests.patch(url, data={"rid": 165829339, "dryRun": True})
        if self.prefix == "TIMELY":
            try:
                self._patch()
            except AssertionError as err:
                self.error_msg, status_code = err.args[0]
                response = {"status_code": status_code, "ok": False}
            else:
                total_minutes = self.timely_event["duration.total_minutes"]

                data = {
                    "id": self.id,
                    "day": self.timely_event["day"],
                    "hours": total_minutes // 60,
                    "minutes": total_minutes % 60,
                    "billed": True,
                    "user_id": self.timely_event["user.id"],
                }

                _response = super().patch(**data)
                response = _response.json

            response.update(
                {"eof": False, "event_id": self.rid, "event_pos": self.event_pos,}
            )

            if self.error_msg:
                response["message"] = self.error_msg

        return jsonify(**response)


class ProjectTasks(Resource):
    def __init__(self, prefix, **kwargs):
        if prefix == "TIMELY":
            fields = ["id", "name"]
            subresource = ""
            kwargs.update(
                {"subkey": "label_ids", "processor": None, "id_hook": self.hook}
            )
        elif prefix == "XERO":
            # TODO: filter by active xero tasks
            fields = ["taskId", "name", "status", "rate.value", "projectId"]
            subresource = "tasks"
            kwargs.update(
                {
                    "subkey": "items",
                    "map_factory": None,
                    "entry_factory": None,
                    "rid_hook": self.hook,
                }
            )

        super().__init__(
            prefix, "projects", subresource=subresource, fields=fields, **kwargs
        )

    def hook(self):
        if self.prefix == "TIMELY" and self.id:
            timely_tasks = Tasks("TIMELY", dictify=True)
            timely_tasks.get(update_cache=True)
            self.processor = partial(
                timely_project_tasks_processor,
                timely_tasks=timely_tasks,
                timely_project_tasks=self,
            )

        elif self.prefix == "XERO" and self.rid:
            xero_users = Users("XERO", dry_run=self.dry_run)
            xero_contacts = Contacts("XERO", dry_run=self.dry_run)
            timely_tasks = Tasks("TIMELY", dry_run=self.dry_run)
            timely_projects = Projects("TIMELY", use_default=True, dry_run=self.dry_run)
            timely_project = extract_model(
                timely_projects, update_cache=True, strict=True
            )

            xero_projects = Projects("XERO", dry_run=True)
            xero_project = extract_model(xero_projects, self.rid, strict=True)

            gkwargs = {
                "xero_project": xero_project,
                "timely_tasks": timely_tasks,
                "xero_contacts": xero_contacts,
                "timely_project": timely_project,
            }

            self.entry_factory = partial(get_task_entry, **gkwargs)
            self.map_factory = partial(
                gen_task_mapping,
                user_mappings=xero_users.mappings,
                project_mappings=xero_projects.mappings,
            )


class ProjectTime(Resource):
    def __init__(self, prefix, **kwargs):
        self.event_pos = int(kwargs.pop("event_pos", 0))
        self.event_id = kwargs.pop("event_id", None)
        self.timely_event = None
        self.eof = False

        if prefix == "TIMELY":
            fields = [
                "id",
                "day",
                "duration.total_minutes",
                "label_ids[0]",
                "project.id",
                "user.id",
                "note",
                "billed",
            ]
            kwargs.update({"subresource": "events"})
        elif prefix == "XERO":
            self.timely_project_id = kwargs.pop("timely_project_id", None)
            fields = []
            kwargs.update(
                {
                    "subkey": "items",
                    "subresource": "time",
                    "processor": xero_events_processor,
                }
            )

        super().__init__(prefix, "projects", fields=fields, **kwargs)

    def _post(self):
        assert self.prefix == "XERO", (
            f"POST is not yet configured for {self.prefix}",
            404,
        )

        timely_projects = Projects("TIMELY", use_default=True, dry_run=self.dry_run)
        self.timely_project_id = self.values.get(
            "timelyProjectId", self.timely_project_id
        )
        self.event_pos = int(self.values.get("eventPos", self.event_pos))

        if self.timely_project_id:
            timely_projects.rid = self.timely_project_id

        timely_project = extract_model(timely_projects, update_cache=True, strict=True)
        xero_users = Users("XERO", dry_run=self.dry_run)

        self.timely_project_id = timely_project["id"]

        timely_project_events = ProjectTime(
            "TIMELY", rid=self.timely_project_id, dry_run=self.dry_run
        )
        timely_tasks = Tasks("TIMELY", dry_run=self.dry_run)
        self.timely_event = extract_model(timely_project_events, pos=self.event_pos, update_cache=True)

        if not self.timely_event:
            self.eof = True
            error = (f"{timely_project_events} doesn't exist!", 404)
            assert self.timely_event, error

        self.event_id = self.timely_event["id"]

        added = self.results.get(self.event_id, {}).get("added")
        assert not added, (f"{timely_project_events} already added!", 409)

        try:
            label_id = int(self.timely_event.get("label_ids[0]", 0))
        except TypeError:
            label_id = 0

        assert label_id, (f"{timely_project_events} missing label!", 500)
        self.timely_event["label_id"] = label_id

        unbilled = self.timely_event["id"] and not self.timely_event["billed"]
        assert unbilled, (f"{timely_project_events} is already billed!", 409)

        self.day = self.timely_event["day"]
        assert self.day, (f"{timely_project_events} has no day!", 500)

        self.duration = self.timely_event["duration.total_minutes"]
        assert self.duration, (f"{timely_project_events} has no duration!", 500)

        xero_projects = Projects("XERO", dry_run=self.dry_run)
        xero_contacts = Contacts("XERO", dry_run=self.dry_run)
        timely_client = timely_project["client"]
        xero_contact = timely_client_to_xero_contact(xero_contacts, timely_client)
        xero_project = timely_project_to_xero_project(
            xero_projects, timely_project, xero_contact=xero_contact
        )
        self.rid = xero_project["projectId"]
        xero_project_tasks = ProjectTasks("XERO", rid=self.rid, dry_run=self.dry_run)

        timely_task = extract_model(
            timely_tasks, label_id, update_cache=True, strict=True
        )
        trunc_name = timely_task["name"].split(" ")[0]
        mapped_names = NAMES.get(trunc_name, ["Unknown"])
        timely_task.update({"trunc_name": trunc_name, "mapped_names": mapped_names})

        timely_user_id = self.timely_event["user.id"]
        timely_users = Users("TIMELY", dry_run=self.dry_run, rid=timely_user_id)
        timely_user = extract_model(timely_users, update_cache=True, strict=True)
        timely_user_name = timely_user["name"]
        xero_inventory = Inventory("XERO", dry_run=self.dry_run)
        mapped_rid = (self.timely_project_id, timely_user_id, label_id)

        tkwargs = {"xero_inventory": xero_inventory, "mapped_rid": mapped_rid}
        xero_user = timely_user_to_xero_user(xero_users, timely_user)
        xero_task = timely_task_to_xero_task(xero_project_tasks, timely_task, **tkwargs)
        assert xero_user, (
            f"User {timely_user_name} doesn't exist in {xero_users}!",
            404,
        )
        assert xero_task, (
            f"Task {mapped_rid} doesn't exist in {xero_project_tasks}!",
            404,
        )

        self.xero_user_id = xero_user["userId"]
        self.xero_task_id = xero_task["taskId"]

        xero_tunc_user_id = self.xero_user_id.split("-")[0]
        xero_trunc_task_id = self.xero_task_id.split("-")[0]

        key = (self.day, self.duration, self.xero_user_id, self.xero_task_id)
        truncated_key = (self.day, self.duration, xero_tunc_user_id, xero_trunc_task_id)

        fields = ["day", "duration", "userId", "taskId"]
        event_keys = {tuple(event[f] for f in fields) for event in self}
        error = (f"Xero time entry {truncated_key} already exists!", 409)
        assert key not in event_keys, error

    def post(self):
        # url = 'http://localhost:5000/v1/xero-time'
        # r = requests.post(url, data={"timelyProjectId": 2389295, "dryRun": True})
        if self.prefix == "XERO":
            try:
                self._post()
            except AssertionError as err:
                self.error_msg, status_code = err.args[0]
                response = {"status_code": status_code, "ok": False}
            else:
                date_utc = f"{self.day}T12:00:00Z"
                note = self.timely_event["note"]
                description = f"{note[:64]}…" if len(note) > 64 else note

                data = {
                    "userId": self.xero_user_id,
                    "taskId": self.xero_task_id,
                    "dateUtc": date_utc,
                    "duration": self.duration,
                    "description": description,
                }

                _response = super().post(**data)
                response = _response.json

            response.update(
                {
                    "eof": self.eof,
                    "event_id": self.event_id,
                    "event_pos": self.event_pos,
                }
            )

            if self.error_msg:
                response["message"] = self.error_msg

        return jsonify(**response)


class Memoization(MethodView):
    def __init__(self):
        self.kwargs = parse_kwargs(app)
        self.values = parse_request()

    def get(self):
        base_url = get_request_base()

        response = {
            "description": "Deletes a cache url",
            "links": get_links(app.url_map.iter_rules()),
            "message": f"The {request.method}:{base_url} route is not yet complete.",
        }

        return jsonify(**response)

    def delete(self, path=None):
        if path:
            url = f"{PREFIX}/{path}"
            cache.delete(url)
            message = f"Deleted cache for {url}"
        else:
            cache.clear()
            message = "Caches cleared!"

        response = {"links": get_links(app.url_map.iter_rules()), "message": message}
        return jsonify(**response)


add_rule = blueprint.add_url_rule

method_views = {
    "memoization": {
        "view": Memoization,
        "param": "string:path",
        "methods": ["GET", "DELETE"],
    },
    "callback": {"view": auth.Callback, "add_prefixes": True},
    "auth": {"view": auth.Auth, "add_prefixes": True},
    "projects": {"view": Projects, "add_prefixes": True},
    "contacts": {"view": Contacts, "add_prefixes": True},
    "users": {"view": Users, "add_prefixes": True},
    "inventory": {"view": Inventory, "add_prefixes": True},
    "tasks": {"view": Tasks, "add_prefixes": True},
    "time": {"view": Time, "add_prefixes": True},
    "projecttasks": {"view": ProjectTasks, "add_prefixes": True},
    "projecttime": {"view": ProjectTime, "add_prefixes": True},
}

for name, options in method_views.items():
    if options.get("add_prefixes"):
        prefixes = Config.API_PREFIXES
    else:
        prefixes = [None]

    for prefix in prefixes:
        if prefix:
            route_name = f"{prefix}-{name}".lower()
            view_func = options["view"].as_view(route_name, prefix)
        else:
            route_name = name
            view_func = options["view"].as_view(route_name)

        methods = options.get("methods")
        url = f"{PREFIX}/{route_name}"

        if options.get("param"):
            param = options["param"]
            url += f"/<{param}>"

        add_rule(url, view_func=view_func, methods=methods)

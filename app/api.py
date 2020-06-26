# -*- coding: utf-8 -*-
"""
    app.api
    ~~~~~~~

    Provides additional api endpoints
"""
from itertools import chain
from functools import partial

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
from app.utils import fetch_choice
from app.routes.auth import Resource, process_result
from app.mappings import USERS, NAMES, POSITIONS, gen_task_mapping

logger = gogo.Gogo(__name__, monolog=True).logger
blueprint = Blueprint("API", __name__)
fake = Faker()

ROUTE_TIMEOUT = Config.ROUTE_TIMEOUT
PREFIX = Config.API_URL_PREFIX
BILLABLE = 1344430
NONBILLABLE = 1339635

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


def xero_events_processor(result, fields, **kwargs):
    result = process_result(result, fields, **kwargs)
    return ({**item, "day": item["dateUtc"].split("T")[0]} for item in result)


def get_label_id(label_ids):
    try:
        return next(
            label for label in label_ids if label not in {BILLABLE, NONBILLABLE}
        )
    except StopIteration:
        return 0


def timely_events_processor(result, fields, **kwargs):
    result = ({**item, "label_id": get_label_id(item["label_ids"])} for item in result)
    return process_result(result, fields, **kwargs)


def get_position_user_ids(xero_task_name):
    position_name = xero_task_name.split("(")[1][:-1]

    try:
        user_ids = POSITIONS[position_name]
    except KeyError:
        logger.debug(f"Position map doesn't contain position '{position_name}'!")
        user_ids = []

    return user_ids


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
class Status(Resource):
    def __init__(self, prefix, **kwargs):
        super().__init__(prefix, "status", **kwargs)


class Projects(Resource):
    def __init__(self, prefix, **kwargs):
        if prefix == "TIMELY":
            fields = ["id", "name", "active", "billable", "client", "budget"]
        elif prefix == "XERO":
            fields = ["projectId", "name", "status"]
            kwargs.update({"subkey": "items"})

        super().__init__(prefix, "projects", fields=fields, **kwargs)

    def get_post_data(self, timely_project, timely_project_name, source_rid):
        timely_client = timely_project["client"]
        xero_contact = Contacts.xero_from_timely(timely_client, dry_run=self.dry_run)

        if xero_contact:
            project_data = {
                "contactId": xero_contact["ContactID"],
                "name": timely_project_name,
            }

            if timely_project.get("budget"):
                project_data["estimateAmount"] = timely_project["budget"]
        else:
            project_data = {}

        return project_data


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
            kwargs.update({"subkey": "Items", "domain": "api", "name_field": "Name"})

        super().__init__(prefix, "Items", fields=fields, **kwargs)

    def get_matching_xero_postions(self, timely_user_id, timely_task_name):
        timely_users = Users("TIMELY", dry_run=True, rid=timely_user_id)
        timely_user = timely_users.extract_model(update_cache=True, strict=True)
        user_name = timely_user["name"]
        trunc_name = timely_task_name.split(" ")[0]
        names = NAMES[trunc_name]
        logger.debug(f"Loading {self} choices for {user_name}…")
        matching_tasks = [
            r for r in self if any(n in r[self.name_field] for n in names)
        ]
        return [
            t
            for t in matching_tasks
            if timely_user_id in get_position_user_ids(t[self.name_field])
        ]


class Tasks(Resource):
    def __init__(self, prefix, **kwargs):
        if prefix == "TIMELY":
            fields = ["id", "name"]
            resource = "labels"
            kwargs.update(
                {
                    "processor": timely_tasks_processor,
                    "filterer": timely_tasks_filterer,
                    "rid_hook": self.hook,
                }
            )

        super().__init__(prefix, resource, fields=fields, **kwargs)

    def hook(self):
        if self.prefix == "TIMELY" and self.rid:
            self.processor = process_result


class Time(Resource):
    def __init__(self, prefix, **kwargs):
        self.event_pos = int(kwargs.pop("event_pos", 0))

        if prefix == "TIMELY":
            fields = [
                "id",
                "day",
                "duration.total_minutes",
                "label_id",
                "project.id",
                "user.id",
                "note",
                "billed",
            ]

            kwargs["processor"] = timely_events_processor

        super().__init__(prefix, "events", fields=fields, **kwargs)

    def _get_patch_data(self):
        assert self.prefix == "TIMELY", (
            f"PATCH is not yet configured for {self.prefix}",
            404,
        )
        assert self.rid, ("No 'rid' given!", 500)

        patched = self.results.get(str(self.rid), {}).get("patched")
        assert not patched, (f"{self} already patched!", 409)

        self.timely_event = self.extract_model(update_cache=True, strict=True)
        assert not self.timely_event["billed"], (f"{self} already billed!", 409)

    def get_patch_data(self):
        # url = 'http://localhost:5000/v1/timely-time'
        # r = requests.patch(url, data={"rid": 165829339, "dryRun": True})
        if self.prefix == "TIMELY":
            try:
                self._get_patch_data()
            except AssertionError as err:
                self.error_msg, self.status_code = err.args[0]
                data = {}
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

        return data


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

    def get_task_entry(self, rid, source_rid):
        (timely_project_id, timely_user_id, label_id) = source_rid

        return {
            "timely": {
                "task": label_id,
                "project": timely_project_id,
                "users": USERS[timely_user_id],
            },
            "xero": {"task": rid, "project": self.rid},
        }

    def timely_project_tasks_processor(self, result, fields, **kwargs):
        timely_tasks = Tasks("TIMELY", dictify=True)
        timely_tasks.get(update_cache=True)
        result = map(str, result)
        result = (timely_tasks[item] for item in result if timely_tasks.data.get(item))
        return process_result(result, fields, projectId=self.rid, **kwargs)

    def hook(self):
        if self.prefix == "TIMELY" and self.id:
            self.processor = self.timely_project_tasks_processor

        elif self.prefix == "XERO" and self.rid:
            xero_users = Users("XERO", dry_run=self.dry_run)
            xero_projects = Projects("XERO", dry_run=True)

            self.entry_factory = self.get_task_entry
            self.map_factory = partial(
                gen_task_mapping,
                user_mappings=xero_users.mappings,
                project_mappings=xero_projects.mappings,
            )

    def get_matching_xero_postions(self, timely_user_id, timely_task_name):
        timely_users = Users("TIMELY", dry_run=True, rid=timely_user_id)
        timely_user = timely_users.extract_model(update_cache=True, strict=True)
        user_name = timely_user["name"]
        trunc_name = timely_task_name.split(" ")[0]
        names = NAMES[trunc_name]
        logger.debug(f"Loading {self} choices for {user_name}…")
        matching_tasks = [
            r for r in self if any(n in r[self.name_field] for n in names)
        ]

        return [
            t
            for t in matching_tasks
            if timely_user_id in get_position_user_ids(t[self.name_field])
        ]

    def get_post_data(self, timely_task, timely_task_name, source_rid):
        (timely_project_id, timely_user_id, label_id) = source_rid
        matching_task_positions = self.get_matching_xero_postions(
            timely_user_id, timely_task_name
        )
        xero_inventory = Inventory("XERO", dry_run=self.dry_run)
        task_position_names = {t["name"] for t in matching_task_positions}
        matching_inventory_positions = xero_inventory.get_matching_xero_postions(
            timely_user_id, timely_task_name
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

        none_of_prev = [(len(matching), "None of the previous tasks")]
        choices = matching + none_of_prev
        pos = fetch_choice(choices) if choices else None

        try:
            item = matching_task_positions[pos]
        except (IndexError, TypeError):
            item = {}

        try:
            rate = item["SalesDetails"]["UnitPrice"]
        except KeyError:
            task_data = {}
        else:
            task_data = {
                "name": item["Name"],
                "rate": {"currency": "USD", "value": rate},
                "chargeType": "TIME" if rate else "NON_CHARGEABLE",
                "isChargeable": bool(rate),
            }

        return task_data

    def id_func(self, timely_task, timely_task_name, source_rid):
        (timely_project_id, timely_user_id, label_id) = source_rid
        matching_task_positions = self.get_matching_xero_postions(
            timely_user_id, timely_task_name
        )
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
            item = matching_task_positions[pos]
        except (IndexError, TypeError):
            # logger.error(f"Task {timely_task['trunc_name']} not found!.")
            xero_task_id = None
        else:
            xero_task_id = item["taskId"]

        return xero_task_id


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
                "label_id",
                "project.id",
                "user.id",
                "note",
                "billed",
            ]
            kwargs.update(
                {"subresource": "events", "processor": timely_events_processor}
            )
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

    def _get_post_data(self):
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

        timely_project = timely_projects.extract_model(update_cache=True, strict=True)
        self.timely_project_id = timely_project["id"]

        timely_project_events = ProjectTime(
            "TIMELY",
            use_default=True,
            rid=self.timely_project_id,
            pos=self.event_pos,
            dry_run=self.dry_run,
        )
        self.timely_event = timely_project_events.extract_model(update_cache=True)
        self.eof = timely_project_events.eof
        assert self.timely_event, (f"{timely_project_events} doesn't exist!", 404)

        self.event_id = self.timely_event["id"]
        added = self.results.get(self.event_id, {}).get("added")
        assert not added, (f"{timely_project_events} already added!", 409)

        try:
            label_id = int(self.timely_event.get("label_id", 0))
        except TypeError:
            label_id = 0

        assert label_id, (f"{timely_project_events} missing label!", 500)
        self.timely_event["label_id"] = label_id

        unbilled = not self.timely_event["billed"]
        assert unbilled, (f"{timely_project_events} is already billed!", 409)

        self.day = self.timely_event["day"]
        assert self.day, (f"{timely_project_events} has no day!", 500)

        self.duration = self.timely_event["duration.total_minutes"]
        assert self.duration, (f"{timely_project_events} has no duration!", 500)
        xero_project = Projects.xero_from_timely(timely_project, dry_run=self.dry_run)
        self.rid = xero_project["projectId"]

        timely_user_id = self.timely_event["user.id"]
        timely_users = Users("TIMELY", dry_run=self.dry_run, rid=timely_user_id)
        timely_user = timely_users.extract_model(update_cache=True, strict=True)
        timely_user_name = timely_user["name"]
        xero_user = Users.xero_from_timely(timely_user, dry_run=self.dry_run)
        assert xero_user, (f"User {timely_user_name} doesn't exist in Xero!", 404)

        timely_tasks = Tasks("TIMELY", dry_run=self.dry_run)
        timely_task = timely_tasks.extract_model(
            label_id, update_cache=True, strict=True
        )
        source_rid = (self.timely_project_id, timely_user_id, label_id)
        xero_task = ProjectTasks.xero_from_timely(
            timely_task, rid=self.rid, source_rid=source_rid, dry_run=self.dry_run
        )
        assert xero_task, (f"Task {source_rid} doesn't exist in Xero!", 404)

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

    def get_post_data(self, *args):
        # url = 'http://localhost:5000/v1/xero-time'
        # r = requests.post(url, data={"timelyProjectId": 2389295, "dryRun": True})
        if self.prefix == "XERO":
            try:
                self._get_post_data()
            except AssertionError as err:
                self.error_msg, self.status_code = err.args[0]
                data = {}
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

        return data


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
    "status": {"view": Status, "add_prefixes": True,"methods": ["GET"]},
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

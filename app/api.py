# -*- coding: utf-8 -*-
"""
    app.api
    ~~~~~~~

    Provides additional api endpoints
"""
from itertools import chain
from functools import partial
from datetime import date

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
    parse,
    cache_header,
    make_cache_key,
    get_links,
)

from app.routes import auth
from app.routes.auth import GSheets
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

timely_events_filterer = lambda item: not (item.get("billed") or item.get("deleted"))


def slugify(text):
    return text.lower().strip().replace(" ", "-")


def parse_date(date_str):
    try:
        month, day, year = map(int, date_str.split('/'))
    except ValueError:
        parsed = ''
    else:
        parsed = date(year, month, day).isoformat()

    return parsed


def select_by_id(_result, _id, id_field):
    try:
        result = next(r for r in _result if _id == r[id_field])
    except StopIteration:
        result = {}

    return result


def gsheets_events_filterer(item):
    has_time = item.get("duration.total_minutes")
    has_date = item.get("day")
    unbilled = not item.get("billed")
    return has_time and has_date and unbilled


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


def gsheets_events_processor(result, fields, **kwargs):
    result = (
        {
            **r,
            "billed": parse(r["billed"]),
            "id": f"{r['user.id']}-{r['row']}",
            "day": parse_date(r["date"]),
            "duration.total_minutes": r["total minutes"],
            "label_id": slugify(r["task"]),
            "project.id": slugify(r["project"].split("(")[0]),
            "note": r["description"],
        }
        for r in result
    )
    return process_result(result, fields, **kwargs)


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


def get_user_name(user_id, prefix=None):
    users = Users(prefix, dry_run=True, rid=user_id)
    user = users.extract_model(update_cache=True, strict=True)
    return user[users.name_field]


###########################################################################
# ROUTES
###########################################################################
@blueprint.route("/")
@blueprint.route(PREFIX)
@cache_header(ROUTE_TIMEOUT, key_prefix=make_cache_key)
def home():
    response = {
        "description": "Returns API documentation",
        "message": "Welcome to the Timero API!",
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
            kwargs.update({"id_field": "projectId", "subkey": "items"})
        elif prefix == "GSHEETS":
            fields = []
            self.gsheet = GSheets()
            self.worksheet = self.gsheet.worksheet

        super().__init__(prefix, "projects", fields=fields, **kwargs)

    def get_post_data(self, project, project_name, rid, **kwargs):
        client = project["client"]
        kwargs.update({"dry_run": self.dry_run, "dest_prefix": self.prefix})
        xero_contact = Contacts.from_source(client, **kwargs)

        if xero_contact:
            project_data = {
                "contactId": xero_contact["ContactID"],
                "name": project_name,
            }

            if project.get("budget"):
                project_data["estimateAmount"] = project["budget"]
        else:
            project_data = {}

        return project_data

    def get_response(self):
        self.gsheet.worksheet_name = "client projects"
        records = self.gsheet.worksheet.get_all_records()

        result = [
            {
                "id": slugify(r["project"]),
                "name": r["project"],
                "client": {"id": slugify(r["client"]), "name": r["client"]},
                "row": pos + 2,
            }
            for (pos, r) in enumerate(records)
        ]

        if self.id:
            result = select_by_id(result, self.id, self.id_field)

        return {"result": result}


class Users(Resource):
    def __init__(self, prefix, **kwargs):
        resource = "users"

        if prefix == "TIMELY":
            fields = ["id", "name"]
        elif prefix == "XERO":
            fields = ["userId", "name"]
            resource = "projectsusers"
            kwargs.update({"id_field": "userId", "subkey": "items"})
        elif prefix == "GSHEETS":
            fields = []

        super().__init__(prefix, resource, fields=fields, **kwargs)

    def get_response(self):
        result = [
            {"id": "austin", "name": "Austin Dial"},
            {"id": "mitchell", "name": "Mitchell Sotto"},
        ]

        if self.id:
            result = select_by_id(result, self.id, self.id_field)

        return {"result": result}


    def id_func(self, user, user_name, rid, prefix=None):
        matching = list(enumerate(x["name"] for x in self))
        none_of_prev = [(len(matching), "None of the previous users")]
        choices = matching + none_of_prev
        pos = fetch_choice(choices) if choices else None

        try:
            item = self[pos]
        except (IndexError, TypeError):
            xero_user_id = None
        else:
            xero_user_id = item["userId"]

        return xero_user_id


class Contacts(Resource):
    def __init__(self, prefix, **kwargs):
        if prefix == "XERO":
            fields = ["ContactID", "Name", "FirstName", "LastName"]
            kwargs.update(
                {"id_field": "ContactID", "subkey": "Contacts", "domain": "api"}
            )
        elif prefix == "GSHEETS":
            fields = []
            self.gsheet = GSheets()
            self.worksheet = self.gsheet.worksheet

        super().__init__(prefix, "Contacts", fields=fields, **kwargs)

    def get_response(self):
        result = self.worksheet.col_values(1)[1:]

        if self.id:
            result = select_by_id(result, self.id, self.id_field)

        return {"result": result}


class Inventory(Resource):
    def __init__(self, prefix, **kwargs):
        if prefix == "XERO":
            fields = ["ItemID", "Name", "Code", "Description", "SalesDetails"]
            kwargs.update(
                {
                    "id_field": "ItemID",
                    "subkey": "Items",
                    "domain": "api",
                    "name_field": "Name",
                }
            )

        super().__init__(prefix, "Items", fields=fields, **kwargs)

    def get_matching_xero_postions(self, user_id, task_name, user_name=None):
        trunc_name = task_name.split(" ")[0]
        names = NAMES[trunc_name]
        logger.debug(f"Loading {self} choices for {user_name}…")
        matching_tasks = [
            r for r in self if any(n in r[self.name_field] for n in names)
        ]
        return [
            t
            for t in matching_tasks
            if user_id in get_position_user_ids(t[self.name_field])
        ]


class Tasks(Resource):
    def __init__(self, prefix, **kwargs):
        if prefix == "TIMELY":
            fields = ["id", "name"]
            resource = "labels"
            kwargs.update({"processor": timely_tasks_processor, "rid_hook": self.hook})
        elif prefix == "GSHEETS":
            fields = []
            resource = "tasks"
            self.gsheet = GSheets()
            self.worksheet = self.gsheet.worksheet

        super().__init__(prefix, resource, fields=fields, **kwargs)

    def hook(self):
        if self.prefix == "TIMELY" and self.rid:
            self.processor = process_result

    def get_response(self):
        result = [
            {"name": v, "row": pos + 2, "id": slugify(v)}
            for (pos, v) in enumerate(self.worksheet.col_values(3)[1:])
        ]

        if self.id:
            result = select_by_id(result, self.id, self.id_field)

        return {"result": result}


class Time(Resource):
    def __init__(self, prefix, **kwargs):
        self.event_pos = int(kwargs.pop("event_pos", 0))
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

        if prefix == "TIMELY":
            processor = timely_events_processor
            filterer = timely_events_filterer
        elif prefix == "GSHEETS":
            self.gsheet = GSheets()
            processor = gsheets_events_processor
            filterer = gsheets_events_filterer

        kwargs.update({"processor": processor, "filterer": filterer})
        super().__init__(prefix, "events", fields=fields, **kwargs)

    def _get_patch_data(self):
        assert self.prefix == "TIMELY", (
            f"PATCH is not yet configured for {self.prefix}",
            404,
        )
        assert self.rid, ("No 'rid' given!", 500)

        patched = self.results.get(str(self.rid), {}).get("patched")
        assert not patched, (f"{self} already patched!", 409)

        self.source_event = self.extract_model(update_cache=True, strict=True)
        assert not self.source_event["billed"], (f"{self} already billed!", 409)

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
                total_minutes = self.source_event["duration.total_minutes"]

                data = {
                    "id": self.id,
                    "day": self.source_event["day"],
                    "hours": total_minutes // 60,
                    "minutes": total_minutes % 60,
                    "billed": True,
                    "user_id": self.source_event["user.id"],
                }

        return data

    def get_response(self):
        self.gsheet.worksheet_name = "austin (time)"
        austin_records = self.gsheet.worksheet.get_all_records()
        austin_time = [
            {**r, "user.id": "austin", "row": pos + 2}
            for (pos, r) in enumerate(austin_records)
        ]

        self.gsheet.worksheet_name = "mitchell (time)"
        mitchell_records = self.gsheet.worksheet.get_all_records()
        mitchell_time = [
            {**r, "user.id": "mitchell", "row": pos + 2}
            for (pos, r) in enumerate(mitchell_records)
        ]

        result = austin_time + mitchell_time

        if self.id:
            result = select_by_id(result, self.id, self.id_field)

        return {"result": result}


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
                    "id_field": "taskId",
                    "subkey": "items",
                    "map_factory": None,
                    "entry_factory": None,
                    "rid_hook": self.hook,
                }
            )
        elif prefix == "GSHEETS":
            fields = ["id", "name"]
            subresource = ""
            self.get_response = Tasks(prefix).get_response

        super().__init__(
            prefix, "projects", subresource=subresource, fields=fields, **kwargs
        )

    def get_task_entry(self, rid, source_rid, prefix=None):
        (project_id, user_id, label_id) = source_rid
        entry = {}
        entry[prefix.lower()] = {
            "task": label_id,
            "project": project_id,
            "users": USERS[user_id],
        }
        entry[self.lowered] = {"task": rid, "project": self.rid}
        return entry

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

    def get_matching_xero_postions(self, user_id, task_name, user_name=None):
        trunc_name = task_name.split(" ")[0]
        names = NAMES[trunc_name]
        logger.debug(f"Loading {self} choices for {user_name}…")
        matching_tasks = [
            r for r in self if any(n in r[self.name_field] for n in names)
        ]
        return [
            t
            for t in matching_tasks
            if user_id in get_position_user_ids(t[self.name_field])
        ]

    def get_post_data(self, task, task_name, rid, prefix=None):
        (project_id, user_id, label_id) = rid
        args = (user_id, task_name, get_user_name(user_id, prefix=prefix))
        matching_task_positions = self.get_matching_xero_postions(*args)
        task_position_names = {t["name"] for t in matching_task_positions}

        xero_inventory = Inventory("XERO", dry_run=self.dry_run)
        matching_inventory_positions = xero_inventory.get_matching_xero_postions(*args)
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
            item = matching_positions[pos]
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
            }

        return task_data

    def id_func(self, task, task_name, rid, prefix=None):
        (project_id, user_id, label_id) = rid
        args = (user_id, task_name, get_user_name(user_id, prefix=prefix))
        matching_task_positions = self.get_matching_xero_postions(*args)
        matching = list(enumerate(m["name"] for m in matching_task_positions))
        none_of_prev = [(len(matching), "None of the previous tasks")]
        choices = matching + none_of_prev
        pos = fetch_choice(choices) if choices else None

        try:
            item = matching_task_positions[pos]
        except (IndexError, TypeError):
            xero_task_id = None
        else:
            xero_task_id = item["taskId"]

        return xero_task_id


class ProjectTime(Resource):
    def __init__(self, prefix, source_prefix="TIMELY", **kwargs):
        self.source_prefix = source_prefix
        self.event_pos = int(kwargs.pop("event_pos", 0))
        self.event_id = kwargs.pop("event_id", None)
        self.source_event = None
        self.eof = False
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

        if prefix == "TIMELY":
            kwargs.update(
                {"subresource": "events", "processor": timely_events_processor}
            )
        elif prefix == "XERO":
            self.source_project_id = kwargs.pop("source_project_id", None)
            fields = []
            kwargs.update(
                {
                    "id_field": "timeEntryId",
                    "subkey": "items",
                    "subresource": "time",
                    "processor": xero_events_processor,
                }
            )
        elif prefix == "GSHEETS":
            self.gsheet = GSheets()
            kwargs.update(
                {
                    "subresource": "events",
                    "processor": gsheets_events_processor,
                    "filterer": gsheets_events_filterer,
                }
            )

        super().__init__(prefix, "projects", fields=fields, **kwargs)

    def _get_post_data(self):
        assert self.prefix == "XERO", (
            f"POST is not yet configured for {self.prefix}",
            404,
        )

        prefix = self.source_prefix
        self.source_project_id = self.values.get(
            "sourceProjectId", self.source_project_id
        )
        source_projects = Projects(
            prefix, rid=self.source_project_id, use_default=True, dry_run=self.dry_run
        )
        ekwargs = {"update_cache": True, "strict": True}
        source_project = source_projects.extract_model(**ekwargs)
        self.source_project_id = source_project[source_projects.id_field]

        self.event_pos = int(self.values.get("eventPos", self.event_pos))
        source_project_events = ProjectTime(
            prefix,
            use_default=True,
            rid=self.source_project_id,
            pos=self.event_pos,
            dry_run=self.dry_run,
        )
        self.source_event = source_project_events.extract_model(update_cache=True)
        self.eof = source_project_events.eof
        assert self.source_event, (f"{source_project_events} doesn't exist!", 404)
        self.event_id = self.source_event[source_project_events.id_field]
        added = self.results.get(self.event_id, {}).get("added")
        assert not added, (f"{source_project_events} already added!", 409)

        label_id = self.source_event.get("label_id")
        assert label_id, (f"{source_project_events} missing label!", 500)
        self.source_event["label_id"] = label_id

        unbilled = not self.source_event["billed"]
        assert unbilled, (f"{source_project_events} is already billed!", 409)

        self.day = self.source_event["day"]
        assert self.day, (f"{source_project_events} has no day!", 500)

        self.duration = self.source_event["duration.total_minutes"]
        assert self.duration, (f"{source_project_events} has no duration!", 500)
        skwargs = {
            "dry_run": self.dry_run,
            "dest_prefix": self.prefix,
            "source_prefix": prefix,
        }
        xero_project = Projects.from_source(source_project, **skwargs)
        self.rid = xero_project["projectId"]

        source_user_id = self.source_event["user.id"]
        source_users = Users(prefix, dry_run=self.dry_run, rid=source_user_id)
        source_user = source_users.extract_model(**ekwargs)
        source_user_name = source_user["name"]
        xero_user = Users.from_source(source_user, **skwargs)
        assert xero_user, (f"User {source_user_name} doesn't exist in Xero!", 404)

        source_tasks = Tasks(prefix, dry_run=self.dry_run)
        source_task = source_tasks.extract_model(label_id, **ekwargs)
        source_rid = (self.source_project_id, source_user_id, label_id)
        xero_task = ProjectTasks.from_source(
            source_task, rid=self.rid, source_rid=source_rid, **skwargs,
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

    def get_post_data(self, *args, **kwargs):
        # url = 'http://localhost:5000/v1/xero-time'
        # r = requests.post(url, data={"sourceProjectId": 2389295, "dryRun": True})
        if self.prefix == "XERO":
            try:
                self._get_post_data()
            except AssertionError as err:
                self.error_msg, self.status_code = err.args[0]
                data = {}
            else:
                date_utc = f"{self.day}T12:00:00Z"
                note = self.source_event["note"]
                description = f"{note[:64]}…" if len(note) > 64 else note

                data = {
                    "userId": self.xero_user_id,
                    "taskId": self.xero_task_id,
                    "dateUtc": date_utc,
                    "duration": self.duration,
                    "description": description,
                }

        return data

    def get_response(self):
        if self.is_gsheets and self.rid:
            self.gsheet.worksheet_name = "austin (time)"
            austin_records = self.gsheet.worksheet.get_all_records()
            austin_time = [
                {**r, "user.id": "austin", "row": pos + 2}
                for (pos, r) in enumerate(austin_records)
                if self.rid == slugify(r["project"].split("(")[0])
            ]

            self.gsheet.worksheet_name = "mitchell (time)"
            mitchell_records = self.gsheet.worksheet.get_all_records()
            mitchell_time = [
                {**r, "user.id": "mitchell", "row": pos + 2}
                for (pos, r) in enumerate(mitchell_records)
                if self.rid == slugify(r["project"].split("(")[0])
            ]
            response = {"result": austin_time + mitchell_time}
        elif self.is_gsheets:
            response = {
                "result": [],
                "message": f"No {self} {self.resource} id provided!",
                "status_code": 404,
            }

        return response


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
    "status": {"view": Status, "add_prefixes": True, "methods": ["GET"]},
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

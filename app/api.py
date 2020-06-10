# -*- coding: utf-8 -*-
"""
    app.api
    ~~~~~~~

    Provides additional api endpoints
"""
import time

from json.decoder import JSONDecodeError
from json import load, dump, dumps
from itertools import chain, islice
from datetime import date, timedelta, datetime as dt
from pathlib import Path
from urllib.parse import urlencode, parse_qs
from base64 import b64encode

import pygogo as gogo
import platform

from flask import (
    Blueprint, request, redirect, session, url_for, g,
    current_app as app, after_this_request
)

from flask.views import MethodView
from faker import Faker

from riko.dotdict import DotDict

from config import Config, __APP_TITLE__ as APP_TITLE

from app import cache, __version__, mappings
from app.utils import (
    responsify,
    jsonify,
    parse,
    cache_header,
    make_cache_key,
    uncache_header,
    load_path,
    get_links,
)

from app.routes import auth
from app.mappings import MAPPINGS_DIR, USERS, tasks_p, gen_task_mapping, reg_mapper

logger = gogo.Gogo(__name__, monolog=True).logger
blueprint = Blueprint("API", __name__)
fake = Faker()

ROUTE_TIMEOUT = Config.ROUTE_TIMEOUT
PREFIX = Config.API_URL_PREFIX
CHROME_DRIVER_VERSIONS = Config.CHROME_DRIVER_VERSIONS
HEADERS = {"Accept": "application/json"}
BILLABLE = 1344430
NONBILLABLE = 1339635
DATA_DIR = Path("app/data")

timely_events_p = DATA_DIR.joinpath("timely_events.json")
timely_users_p = DATA_DIR.joinpath("timely_users.json")
timely_projects_p = DATA_DIR.joinpath("timely_projects.json")
timely_tasks_p = DATA_DIR.joinpath("timely_tasks.json")
sync_results_p = DATA_DIR.joinpath("sync_results.json")
xero_users_p = DATA_DIR.joinpath("xero_users.json")
xero_projects_p = DATA_DIR.joinpath("xero_projects.json")
xero_inventory_p = DATA_DIR.joinpath("xero_inventory.json")

position_users_p = MAPPINGS_DIR.joinpath("position-users.json")
projects_p = MAPPINGS_DIR.joinpath("projects.json")
users_p = MAPPINGS_DIR.joinpath("users.json")
task_names_p = MAPPINGS_DIR.joinpath("task-names.json")


def get_request_base():
    return request.base_url.split("/")[-1].split("?")[0]


def extract_fields(record, fields, **kwargs):
    item = DotDict(record)

    for field in fields:
        if "[" in field:
            split_field = field.split("[")
            real_field = split_field[0]
            pos = int(split_field[1].split("]")[0])

            if real_field == "label_ids":
                values = [
                    label
                    for label in item[real_field]
                    if label not in {BILLABLE, NONBILLABLE}
                ]
            else:
                values = item[real_field]

            try:
                value = values[pos]
            except IndexError:
                value = None
        else:
            value = item.get(field)

        yield (field, value)

    if kwargs:
        yield from kwargs.items()


def remove_fields(record, black_list):
    for key, value in record.items():
        if key not in black_list:
            yield (key, value)


def process_result(result, fields=None, black_list=None, **kwargs):
    for item in result:
        if not (item.get("billed") or item.get("deleted")):
            if black_list:
                yield dict(remove_fields(item, black_list))
            else:
                yield dict(extract_fields(item, fields, **kwargs))


def add_day(item):
    day = item["dateUtc"].split("T")[0]
    return {**item, "day": day}


def fetch_choice(choices):
    call(['say', 'enter a value'])
    pos = None

    while pos == None:
        answer = input(f"{choices}: ")

        try:
            pos = int(answer or "0")
        except ValueError:
            logger.error(f"Invalid selection: {answer}.")

    return pos


def fetch_bool(message):
    call(['say', 'enter a value'])
    invalid = True

    while invalid:
        answer = input(f"{message} [y/n]: ")

        if answer in {"y", "n"}:
            invalid = False
        else:
            logger.error(f"Invalid selection: {answer}.")

    return answer


###########################################################################
# ROUTES
###########################################################################
@blueprint.route("/")
@blueprint.route(PREFIX)
@cache_header(ROUTE_TIMEOUT, key_prefix=make_cache_key)
def home():
    response = {
        "description": "Returns API documentation",
        "message": f"Welcome to the {APP_TITLE}!",
        "links": get_links(app.url_map.iter_rules()),
    }

    return jsonify(**response)


@blueprint.route(f"{PREFIX}/timely-callback")
def timely_callback():
    return callback("TIMELY")


@blueprint.route(f"{PREFIX}/xero-callback")
def xero_callback():
    return callback("XERO")


@blueprint.route(f"{PREFIX}/timely-status")
def timely_status():
    # TODO: Timely Headless Auth returns an error message
    # saying "invalid_grant", but it also returns the valid
    # credentials with the error message. Authentication is
    # working fine I guess, but we should really look into
    # making this work a little smoother.
    timely = get_auth_client("TIMELY", **app.config)
    api_url = f"{timely.api_base_url}/accounts"
    response = get_response(api_url, timely, **app.config)
    response["result"] = timely.token
    return jsonify(**response)


@blueprint.route(f"{PREFIX}/xero-status")
def xero_status():
    xero = get_auth_client("XERO", **app.config)

    if xero.oauth1:
        api_url = f"{xero.api_base_url}/projects.xro/2.0/projectsusers"
        message = ""
    else:
        api_url = f"{xero.api_base_url}/connections"

    response = get_response(api_url, xero, **app.config)

    if xero.oauth2:
        if response["ok"]:
            result = response["result"]

            if result and result[0].get("tenantId"):
                xero.tenant_id = result[0]["tenantId"]
                xero.save()
                message = f"Set Xero tenantId to {xero.tenant_id}."
            else:
                message = "No tenantId found."

            logger.info(message)
        else:
            message = "Failed to set Xero tenantId!"
            logger.error(message)

    # TODO: we are overwriting the result value from the Xero api by doing this (no harm done).
    # Maybe think about changing it eventually
    response["result"] = xero.token

    if message and response.get("message"):
        response["message"] += f" {message}"
    elif message:
        response.update({"message": message})

    return jsonify(**response)


@blueprint.route(f"{PREFIX}/connections")
def connections():
    xero = get_auth_client("XERO", **app.config)
    api_url = f"{xero.api_base_url}/connections"
    response = get_response(api_url, xero, **app.config)
    return jsonify(**response)


@blueprint.route(f"{PREFIX}/accounts")
def accounts():
    timely = get_auth_client("TIMELY", **app.config)
    api_url = f"{timely.api_base_url}/accounts"
    response = get_response(api_url, timely, **app.config)
    return jsonify(**response)


@blueprint.route(f"{PREFIX}/ipsum")
@cache_header(ROUTE_TIMEOUT, key_prefix="%s")
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
class Auth(MethodView):
    def __init__(self, prefix):
        super().__init__(prefix)

        self.status_urls = {
            # TODO: Timely Headless Auth returns an error message
            # saying "invalid_grant", but it also returns the valid
            # credentials with the error message. Authentication is
            # working fine I guess, but we should really look into
            # making this work a little smoother.
            "TIMELY": f"{self.client.api_base_url}/accounts"
            "XERO": f"{self.client.api_base_url}/projects.xro/2.0/projectsusers"
            "QB": f"{self.client.api_base_url}/company/{self.client.realm_id}/companyinfo/{self.client.realm_id}"
        }

    def get(self):
        """Step 1: User Authorization.

        Redirect the user/resource owner to the OAuth provider (i.e. Github)
        using an URL with a few key OAuth parameters.
        """
        cache.set(f"{self.prefix}_callback_url") = request.args.get("callback_url")

        # https://gist.github.com/ib-lundgren/6507798#gistcomment-1006218
        # State is used to prevent CSRF, keep this for later.
        authorization_url, state = self.client.authorization_url
        self.client.state = session[f"{self.prefix}_state"] = state
        self.client.save()

        # Step 2: User authorization, this happens on the provider.
        if self.client.verified and not self.client.expired:
            status_url = self.status_urls[self.prefix]
            response = get_response(status_url, self.client, **app.config)
            response.update(
                {
                    "token": self.client.token,
                    "state": self.client.state,
                    "realm_id": self.client.realm_id,
                    "tenant_id": self.client.tenant_id,
                }
            )

            result = jsonify(**response)
        else:
            if self.client.oauth1:
                # clear previously cached token
                self.client.renew_token()
                authorization_url = self.client.authorization_url[0]

            redirect_url = authorization_url
            logger.info("redirecting to %s", redirect_url)
            result = redirect(redirect_url)

        return result

    def patch(self):
        self.client.renew_token()
        return redirect(url_for(f".{self.prefix}_auth".lower()))


    def delete(self, base=None):
        # TODO: find out where this was implemented
        response = {"status_code": 200, "message": self.client.revoke_token()}
        return jsonify(**response)


class APIBase(MethodView):
    def __init__(self, prefix, **kwargs):
        self.prefix = prefix
        def_subkey = "items" if self.prefix == "XERO" else ""

        self._domain = kwargs.get("domain", "projects")
        self._subkey = kwargs.get("subkey", def_subkey)
        self._headers = kwargs.get("headers", HEADERS)
        self.lowered = self.prefix.lower()
        self.black_list = set()
        self.params = {}
        self.add_day = False
        self.client = None

        values = request.values or {}
        json = request.json or {}
        self.values = {**values, **json}
        self.project_pos = int(self.values.get("projectPos", 0))
        self.event_pos = int(self.values.get("eventPos", 0))
        self.event_id = str(self.values.get("eventId", ""))

        self.dry_run = self.values.pop("dryRun", "").lower() == "true"
        self.use_default = self.values.pop("useDefault", "").lower() == "true"
        self.error_msg = ""

        # mappings
        self.projects = load(projects_p.open())
        self.position_users = load(position_users_p.open())
        self.users = load(users_p.open())
        self.tasks = load(tasks_p.open())
        self.task_names = load(task_names_p.open())

        # data
        self.sync_results = load_path(sync_results_p, {})
        self.timely_projects = load_path(timely_projects_p, {})
        self.timely_tasks = load_path(timely_tasks_p, {})
        self.timely_events = load_path(timely_events_p, {})
        self.timely_users = load_path(timely_users_p, {})
        self.xero_projects = load_path(xero_projects_p, {})
        self.xero_inventory = load_path(xero_inventory_p, [])

        project_ids = (p[self.lowered] for p in self.projects if p.get(self.lowered))

        try:
            self.def_project_id = next(islice(project_ids, self.project_pos, None))
        except StopIteration:
            self.def_project_id = 0

        self.timely_project_id = self.values.get("timelyProjectId")
        self.xero_project_id = self.values.get("xeroProjectId")
        self._project_id = None

        self.is_timely = self.prefix == "TIMELY"
        self.is_xero = self.prefix == "XERO"

        # HACK: call for side-effect of setting self.timely_project_id
        # and self.xero_project_id
        self.project_id

        if not self.dry_run:
            self.client = get_auth_client(self.prefix, **app.config)

    @property
    def fields(self):
        return []

    @property
    def populate(self):
        return False

    @property
    def all(self):
        return self.values.get("all", "").lower() == "true"

    @property
    def process(self):
        return self.values.get("process", "").lower() == "true"

    @property
    def dictify(self):
        return self.values.get("dictify", "").lower() == "true"

    @property
    def domain(self):
        return self._domain

    @property
    def subkey(self):
        return self._subkey

    @property
    def headers(self):
        headers = self._headers

        if self.is_xero and self.client.oauth2:
            headers["Xero-tenant-id"] = self.client.tenant_id

        return headers

    @property
    def api_base_url(self):
        if self.dry_run:
            api_base_url = ""
        elif self.is_timely:
            api_base_url = f"{self.client.api_base_url}/{self.client.account_id}"
        elif self.is_xero:
            api_base_url = f"{self.client.api_base_url}/{self.domain}.xro/2.0"

        return api_base_url

    @property
    def project_id(self):
        if not self._project_id:
            if self.is_timely and self.timely_project_id:
                project_id = self.timely_project_id
            elif self.is_xero and self.xero_project_id:
                project_id = self.xero_project_id
            elif self.values.get("id"):
                project_id = self.values["id"]
            elif self.use_default:
                project_id = self.def_project_id
            else:
                project_id = 0

            if project_id and self.is_timely:
                self.timely_project_id = self._project_id = int(project_id)
            elif project_id and self.is_xero:
                self.xero_project_id = self._project_id = project_id

        return self._project_id

    def get(self):
        if self.dry_run:
            response = {"result": []}
        else:
            response = get_response(
                self.api_url,
                self.client,
                headers=self.headers,
                params=self.params,
                **app.config,
            )

        result = response.get("result")

        if self.subkey and result:
            result = result[self.subkey]

        if self.black_list and result:
            result = process_result(result, black_list=self.black_list)

        if self.populate and result:
            # populate result (list of ids) with mapping info
            mapped = (
                self.timely_tasks[str(r)]
                for r in result
                if self.timely_tasks.get(str(r))
            )
            result = process_result(mapped, self.fields, projectId=self.project_id)
        elif self.fields and self.process and result:
            if "timely-tasks" in request.url:
                _billable = (r["children"] for r in result if r["id"] == BILLABLE)
                _non_billable = (
                    r["children"] for r in result if r["id"] == NONBILLABLE
                )
                billable_args = (next(_billable), self.fields)
                non_billable_args = (next(_non_billable), self.fields)

                billable = process_result(*billable_args, billable=True)
                non_billable = process_result(*non_billable_args, billable=False)
                result = chain(billable, non_billable)
            else:
                result = process_result(result, self.fields)

        if self.add_day and result:
            result = (add_day(item) for item in result)

        if self.dictify and result:
            if self.fields:
                id_field = next(f for f in self.fields if "id" in f.lower())
            else:
                id_field = "id"

            result = ((item.get(id_field), item) for item in result)
            response["result"] = dict(result)
        else:
            response["result"] = list(result or [])

        return jsonify(**response)

    def post(self):
        if self.is_xero:
            if self.dry_run:
                response = {"result": {}}
            else:
                kwargs = {
                    **app.config,
                    "headers": self.headers,
                    "method": "post",
                }

                props = {"dictify", "process", "contacts"}
                values = {k: v for k, v in self.values.items() if k not in props}

                if self.domain == "api":
                    kwargs["json"] = values
                else:
                    kwargs["data"] = values

                response = get_response(self.api_url, self.client, **kwargs)
        else:
            base_url = get_request_base()
            self.error_msg = (
                f"The {request.method}:{base_url} route is not yet enabled."
            )
            response = {"status_code": 404}

        response["links"] = get_links(app.url_map.iter_rules())

        if self.error_msg:
            response["message"] = self.error_msg

        return jsonify(**response)


class Projects(APIBase):
    def __init__(self, prefix):
        super().__init__(prefix)

        if not self.dry_run:
            self.api_url = f"{self.api_base_url}/projects"

    @property
    def fields(self):
        if self.is_timely:
            fields = ["active", "billable", "id", "name", "client", "budget"]
        elif self.is_xero:
            fields = ["name", "projectId", "status"]

        return fields


class Users(APIBase):
    def __init__(self, prefix):
        super().__init__(prefix)

    @property
    def domain(self):
        if self.is_xero and self.contacts:
            domain = "api"
        else:
            domain = super().domain

        return domain

    @property
    def subkey(self):
        if self.is_xero and self.contacts:
            subkey = "Contacts"
        else:
            subkey = super().subkey

        return subkey

    @property
    def contacts(self):
        return self.values.get("contacts", "").lower() == "true"

    @property
    def fields(self):
        if self.is_timely:
            fields = ["name", "id"]
        elif self.is_xero and self.contacts:
            fields = ["Name", "ContactID", "FirstName", "LastName"]
        elif self.is_xero:
            fields = ["name", "userId"]

        return fields

    @property
    def api_url(self):
        if self.dry_run:
            api_url = None
        elif self.is_timely:
            api_url = f"{self.api_base_url}/users"
        elif self.is_xero and self.contacts:
            api_url = f"{self.api_base_url}/Contacts"
        elif self.is_xero:
            api_url = f"{self.api_base_url}/projectsusers"

        return api_url

    @property
    def headers(self):
        if self.is_xero and self.contacts and not self.client.oauth2:
            headers = HEADERS
        else:
            headers = super().headers

        return headers


class Inventory(APIBase):
    def __init__(self, prefix):
        super().__init__(prefix, subkey="Items", domain="api")

        if self.is_xero and not self.dry_run:
            self.api_url = f"{self.api_base_url}/Items"

    @property
    def fields(self):
        if self.is_xero:
            fields = ["Code", "Description", "ItemID", "Name", "SalesDetails"]
        else:
            fields = []

        return fields


class Tasks(APIBase):
    def __init__(self, prefix):
        super().__init__(prefix)

    @property
    def populate(self):
        return self.is_timely and not self.all

    @property
    def subkey(self):
        if self.is_timely and not self.all:
            subkey = "label_ids"
        else:
            subkey = super().subkey

        return subkey

    @property
    def fields(self):
        if self.is_timely:
            fields = ["id", "name"]
        elif self.is_xero:
            fields = ["name", "taskId", "status", "rate.value", "projectId"]

        return fields

    @property
    def api_url(self):
        if self.is_timely and not self.dry_run:
            if self.all:
                api_url = f"{self.api_base_url}/labels"
            else:
                api_url = f"{self.api_base_url}/projects/{self.project_id}"

        elif self.is_xero and not self.dry_run:
            api_url = f"{self.api_base_url}/projects/{self.project_id}/tasks"

        return api_url

    def post(self):
        # url = 'http://localhost:5000/v1/timely-tasks'
        # r = requests.post(url, data={"name": "Test task", "dryRun": True})
        if self.is_timely:
            if self.dry_run:
                response = {"result": {"label": self.values}}
            else:
                kwargs = {
                    **app.config,
                    "headers": self.headers,
                    "method": "post",
                    "json": {"label": self.values},
                }

                response = get_response(self.api_url, self.client, **kwargs)
        else:
            if self.dry_run:
                response = {"result": {}}
            else:
                kwargs = {
                    **app.config,
                    "headers": self.headers,
                    "method": "post",
                    "json": self.values,
                }

                response = get_response(self.api_url, self.client, **kwargs)

        response["links"] = get_links(app.url_map.iter_rules())

        if self.error_msg:
            response["message"] = self.error_msg

        return jsonify(**response)


class Time(APIBase):
    def __init__(self, prefix):
        super().__init__(prefix)

        def_end = date.today()
        def_start = def_end - timedelta(days=app.config["REPORT_DAYS"])
        end = self.values.get("end", def_end.strftime("%Y-%m-%d"))
        start = self.values.get("start", def_start.strftime("%Y-%m-%d"))

        self.eof = False
        self.new_project = False
        self._timely_event = None
        self._xero_task_id = None
        self._xero_user_id = None

        self.project_mapping = dict(reg_mapper(self.projects, "timely", "xero"))
        self.user_mapping = dict(reg_mapper(self.users, "timely", "xero"))

        self.projects_api = Projects(prefix)
        self.tasks_api = Tasks(prefix)
        self.users_api = Users(prefix)

        def_timely_project = {"id": self.timely_project_id, "name": "Unknown"}
        self.timely_project = self.timely_projects.get(
            str(self.timely_project_id), def_timely_project
        )

        if self.timely_project_id and not self.xero_project_id:
            self.xero_project_id = self.project_mapping.get(int(self.timely_project_id))

        if self.is_timely:
            self.params = {"since": start, "upto": end}
        elif self.is_xero:
            self.add_day = True
            self.params = {"dateAfterUtc": start, "dateBeforeUtc": end}

    @property
    def fields(self):
        if self.is_timely:
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
        else:
            fields = super().fields

        return fields

    @property
    def api_url(self):
        if self.is_timely and not self.dry_run:
            if self.all:
                api_url = f"{self.api_base_url}/events"
            elif request.method in {"PATCH", "PUT"}:
                api_url = f"{self.api_base_url}/events/{self.event_id}"
            else:
                api_url = f"{self.api_base_url}/projects/{self.project_id}/events"

        elif self.is_xero and not self.dry_run:
            api_url = f"{self.api_base_url}/projects/{self.project_id}/time"

        return api_url

    @property
    def timely_proj_events(self):
        if self.timely_project_id:
            proj_events_p = Path(
                f"app/data/timely_{self.timely_project_id}_events.json"
            )
        else:
            proj_events_p = None

        if proj_events_p:
            try:
                timely_proj_events = load(proj_events_p.open())
            except FileNotFoundError:
                timely_proj_events = []
                self.error_msg = f"{proj_events_p} not found!"
                logger.error(self.error_msg)
            else:
                logger.debug(f"{proj_events_p} found!")
        else:
            timely_proj_events = []
            self.error_msg = "No 'timelyProjectId' given!"
            logger.error(self.error_msg)

        return timely_proj_events

    @property
    def timely_event(self):
        if not self._timely_event:
            timely_event = {"id": "", "user.id": None, "billed": None}

            if self.event_id:
                try:
                    timely_event = self.timely_events[self.event_id]
                except IndexError:
                    if not self.error_msg:
                        self.error_msg = f"Event ID {self.event_id} not found!"
                        logger.error(self.error_msg)
                else:
                    logger.debug(f"Event ID {self.event_id} found!")

                event_id = self.event_id
            else:
                try:
                    timely_event = self.timely_proj_events[self.event_pos]
                except IndexError:
                    self.eof = True

                    if not self.error_msg:
                        self.error_msg = (
                            f"Event at position {self.event_pos} not found!"
                        )
                        logger.error(self.error_msg)
                else:
                    logger.debug(f"Event at position {self.event_pos} found!")

                event_id = str(timely_event["id"])

            try:
                label_id = int(timely_event.get("label_ids[0]", 0))
            except TypeError:
                label_id = 0

            updates = {
                "id": event_id,
                "label_id": label_id,
                "added": self.sync_results.get(event_id, {}).get("added"),
                "unbilled": event_id and not timely_event["billed"],
            }

            self._timely_event = {**timely_event, **updates}

        return self._timely_event

    @property
    def timely_task(self):
        default = {"name": "Unknown"}
        timely_task = self.timely_tasks.get(str(self.timely_event["label_id"]), default)
        trunc_name = timely_task["name"].split(" ")[0]
        mapped_names = self.task_names.get(trunc_name, ["Unknown"])
        timely_task.update({"trunc_name": trunc_name, "mapped_names": mapped_names})
        return timely_task

    @property
    def timely_user(self):
        default = {"name": "Unknown"}
        return self.timely_users.get(str(self.timely_event["user.id"]), default)

    @property
    def xero_event(self):
        if not self._xero_user_id:
            user_id = self.timely_event["user.id"] or 0
            self._xero_user_id = self.user_mapping.get(int(user_id))

        if not self._xero_task_id:
            task_mapping_args = (
                self.project_mapping,
                self.user_mapping.keys(),
                "timely",
                "xero",
            )
            task_mapping = gen_task_mapping(*task_mapping_args)
            key = (self.timely_project["id"], self.timely_event["user.id"])
            timely_tasks_to_xero = {
                (key, user): proj_tasks for key, user, proj_tasks in task_mapping
            }

            self._xero_task_id = timely_tasks_to_xero.get(key, {}).get(
                self.timely_event["label_id"], {}
            )

        return {"user_id": self._xero_user_id, "task_id": self._xero_task_id}

    @xero_event.setter
    def xero_event(self, value):
        if value.get("user_id"):
            self._xero_user_id = value["user_id"]

        if value.get("task_id"):
            self._xero_task_id = value["task_id"]

    @property
    def task_entry(self):
        return {
            "timely": {
                "task": self.timely_event["label_id"],
                "project": self.timely_project["id"],
                "users": USERS[self.timely_event["user.id"]],
            },
            "xero": {
                "task": self.xero_event["task_id"],
                "project": self.xero_project_id,
            },
        }

    def get_position_user_ids(self, task, field="name"):
        task_name = task[field]
        position_name = task_name.split("(")[1][:-1]

        if position_name in self.position_users:
            user_ids = self.position_users[position_name]
        else:
            logger.debug(
                f"{position_users_p} doesn't contain position '{position_name}'!"
            )
            user_ids = []

        return user_ids

    def update_project_map(self, projects=None):
        _projects = projects or self.xero_projects
        project_id = None

        try:
            project_id = next(
                k
                for k, v in _projects.items()
                if self.timely_project["name"] == v["name"]
            )
        except StopIteration:
            message = f"Project {self.timely_project['name']} not found in mapping. "

            if projects is None:
                message += "Searching Xero for it…"
                print(message)
                self.projects_api.values = {"dictify": "true", "process": "true"}
                projects = self.projects_api.get().json["result"]
                return self.update_project_map(projects)
            else:
                message += "Do you want to create this project in Xero?"
                answer = fetch_bool(message)
                project_data = self.create_project_data() if answer == "y" else {}

                if project_data:
                    response = self.create_project(project_data)
                    json = response.json

                    if json["ok"]:
                        project_id = json["result"]["projectId"]
                        self.new_project = True
                    else:
                        self.error_msg = json.get("message")
                        logger.error(self.error_msg)
                        logger.debug(f"Manually add {self.timely_project['name']}.")

        if project_id:
            self.xero_project_id = project_id
            mapped_id = self.project_mapping.get(int(self.timely_project["id"]))

            if mapped_id != self.xero_project_id:
                project_entry = {
                    "timely": self.timely_project["id"],
                    "xero": self.xero_project_id,
                }
                self.projects.append(project_entry)
                logger.debug(f"Updating {projects_p}…")
                dump(self.projects, projects_p.open(mode="w"), indent=2)
        elif not self.error_msg:
            self.error_msg = f"No project matching {self.timely_project['name']} found!"
            logger.error(self.error_msg)

    def update_task_map(self):
        self.tasks.append(self.task_entry)
        logger.debug(f"Updating {tasks_p}…")
        return dump(self.tasks, tasks_p.open(mode="w"), indent=2)

    def get_matching_xero_postions(self, use_inventory=False):
        if use_inventory:
            mapped_names = self.timely_task["mapped_names"]
            matching_inventory = [
                i
                for i in self.xero_inventory
                if any(name in i["Name"] for name in mapped_names)
            ]
            matching_positions = [
                i
                for i in matching_inventory
                if self.timely_event["user.id"]
                in self.get_position_user_ids(i, field="Name")
            ]
        elif self.xero_project_id:
            xero_tasks_filename = (
                f"xero_{self.xero_project_id.split('-')[0]}_tasks.json"
            )
            xero_tasks_p = DATA_DIR.joinpath(xero_tasks_filename)
            mapped_names = self.timely_task["mapped_names"]

            # TODO: filter by active tasks
            xero_tasks = load_path(xero_tasks_p, [])

            matching_tasks = [
                t for t in xero_tasks if any(name in t["name"] for name in mapped_names)
            ]
            matching_positions = [
                t
                for t in matching_tasks
                if self.timely_event["user.id"] in self.get_position_user_ids(t)
            ]
        else:
            logger.debug("No xero_project_id!")
            matching_positions = []

        return matching_positions

    def find_matching_xero_task_id(self):
        xero_task_id = None
        matching_positions = self.get_matching_xero_postions()

        if matching_positions:
            logger.debug(
                f"Loading task choices for {self.timely_project['name']}:{self.timely_user['name']}:{self.timely_task['trunc_name']}…"
            )
            matching = list(enumerate(m["name"] for m in matching_positions))
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
                xero_task_id = matching_positions[pos]["taskId"]
            except (IndexError, TypeError):
                pass

        if not xero_task_id:
            message = (
                f"Task {self.timely_task['trunc_name']} not found in {task_names_p}."
            )
            logger.debug(message)

        return xero_task_id

    def create_task_data(self):
        logger.debug(
            f"Loading inventory choices for {self.timely_project['name']}:{self.timely_user['name']}:{self.timely_task['trunc_name']}…"
        )

        matching_task_positions = self.get_matching_xero_postions()
        task_position_names = {t["name"] for t in matching_task_positions}
        matching_inventory_positions = self.get_matching_xero_postions(True)
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
            self.error_msg = "No inventory match found!"
            logger.error(self.error_msg)
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

    def create_client_data(self):
        return {"Name": self.timely_project["client"]["name"]}

    def create_project_data(self):
        timely_client_name = self.timely_project["client"]["name"]
        self.users_api.values = {"contacts": "true", "process": "true"}
        users = self.users_api.get().json["result"]

        try:
            matching_user = next(u for u in users if timely_client_name == u["Name"])
        except StopIteration:
            message = f"No client matching {timely_client_name} found!"
            message += " Do you want to create this client in Xero?"
            answer = fetch_bool(message)
            client_data = self.create_client_data() if answer == "y" else {}

            if client_data:
                response = self.create_client(client_data)
                json = response.json

                if json["ok"]:
                    matching_user = json["result"]["Contacts"][0]
                else:
                    matching_user = {}
                    self.error_msg = json.get("message")
                    logger.error(self.error_msg)
                    logger.debug(f"Manually add {timely_client_name}.")
            else:
                matching_user = {}
                self.error_msg = message
                logger.error(self.error_msg)

        if matching_user:
            project_data = {
                "contactId": matching_user["ContactID"],
                "name": self.timely_project["name"],
            }

            if self.timely_project.get("budget"):
                project_data["estimateAmount"] = self.timely_project["budget"]
        else:
            project_data = {}

        return project_data

    def create_task(self, task_data):
        self.tasks_api.xero_project_id = self.xero_project_id
        self.tasks_api.project_id
        self.tasks_api.values = task_data
        return self.tasks_api.post()

    def create_project(self, project_data):
        self.projects_api.values = project_data
        return self.projects_api.post()

    def create_client(self, client_data):
        client_data.update({"contacts": "true", "process": "true"})
        self.users_api.values = client_data
        return self.users_api.post()

    def patch(self):
        # url = 'http://localhost:5000/v1/timely-time'
        # r = requests.patch(url, data={"eventId": 165829339, "dryRun": True})
        if self.is_timely:
            patched = self.sync_results.get(self.event_id, {}).get("patched")

            if not self.event_id:
                self.error_msg = "No 'eventId' given!"
                logger.error(self.error_msg)
            elif patched:
                self.error_msg = f"Event {self.event_id} already patched!"

            if patched:
                response = {"status_code": 409}
            elif self.timely_event["id"]:
                total_minutes = self.timely_event["duration.total_minutes"]
                billed = self.timely_event["billed"]

                if billed:
                    self.error_msg = f"Event {self.event_id} already billed!"
                    response = {"status_code": 409}
                else:
                    data = {
                        "id": self.event_id,
                        "day": self.timely_event["day"],
                        "hours": total_minutes // 60,
                        "minutes": total_minutes % 60,
                        "billed": True,
                        "user_id": self.timely_event["user.id"],
                    }

                    if self.dry_run:
                        response = {"result": {"event": data}}
                    else:
                        kwargs = {
                            **app.config,
                            "headers": self.headers,
                            "method": "put",
                            "json": {"event": data},
                        }
                        response = get_response(
                            self.api_url, self.client, **kwargs
                        )
            else:
                response = {"status_code": 404}
        else:
            base_url = get_request_base()
            self.error_msg = (
                f"The {request.method}:{base_url} route is not yet enabled."
            )
            response = {"status_code": 404}

        response.update(
            {
                "links": get_links(app.url_map.iter_rules()),
                "message": self.error_msg,
                "event_id": self.event_id,
            }
        )
        return jsonify(**response)

    def post(self):
        # url = 'http://localhost:5000/v1/xero-time'
        # r = requests.post(url, data={"timelyProjectId": 2389295, "dryRun": True})
        if self.is_xero:
            if not (self.xero_project_id or self.error_msg):
                message = f"No Xero project ID found for Timely project {self.timely_project['name']}!"
                logger.debug(message)
                self.update_project_map()

            if self.timely_event["added"] and not self.error_msg:
                self.error_msg = f"Event {self.timely_event['id']} already added!"

            if not (self.timely_event["label_id"] or self.error_msg):
                self.error_msg = (
                    f"Event {self.timely_event['id']} missing label!"
                )
                logger.error(self.error_msg)

            if self.timely_event["unbilled"]:
                logger.debug(f"Event {self.timely_event['id']} is unbilled!")
            elif not self.error_msg:
                self.error_msg = f"Event {self.timely_event['id']} is already billed!"
                logger.error(self.error_msg)

            if self.xero_event["user_id"]:
                logger.debug(
                    f"Timely user {self.timely_event['user.id']} found in Xero mapping!"
                )
            elif not self.error_msg:
                self.error_msg = f"Timely user {self.timely_event['user.id']} not found in Xero mapping!"
                logger.error(self.error_msg)

            if self.xero_event["task_id"]:
                logger.debug(
                    f"Timely task {self.timely_event['label_id']} found in Xero mapping!"
                )
            elif not self.error_msg:
                xero_task_id = self.find_matching_xero_task_id()

                if not xero_task_id:
                    message = f"No Xero {self.timely_project['name']} project tasks matching {self.timely_task['trunc_name']} for {self.timely_user['name']} found!"
                    logger.debug(message)
                    task_data = self.create_task_data()

                    if task_data:
                        response = self.create_task(task_data)
                        json = response.json

                        if json["ok"]:
                            xero_task_id = json["result"]["taskId"]
                        else:
                            self.error_msg = json.get("message")
                            logger.error(self.error_msg)
                            logger.debug(
                                f"Manually add {task_data['name']} to {self.timely_project['name']}."
                            )

                if xero_task_id:
                    self.xero_event = {"task_id": xero_task_id}
                    self.update_task_map()

            if self.xero_event["user_id"] and self.xero_event["task_id"]:
                day = self.timely_event["day"]
                date_utc = f"{day}T12:00:00Z"
                duration = self.timely_event["duration.total_minutes"]

                if len(self.timely_event["note"]) > 64:
                    description = f"{self.timely_event['note'][:64]}…"
                else:
                    description = self.timely_event["note"]

                data = {
                    "userId": self.xero_event["user_id"],
                    "taskId": self.xero_event["task_id"],
                    "dateUtc": date_utc,
                    "duration": duration,
                    "description": description,
                    # "description": description.replace("/", "|"),
                }

                logger.debug("Created data!")
            else:
                day = None
                duration = 0
                data = {}

            ready = self.xero_project_id and data and not self.error_msg

            if ready and self.new_project:
                xero_events = []
            elif ready:
                trunc_id = self.xero_project_id.split("-")[0]
                events_p = Path(f"app/data/xero_{trunc_id}_events.json")

                try:
                    xero_events = load(events_p.open())
                except FileNotFoundError:
                    xero_events = []
                    self.error_msg = f"{events_p} not found!"
                    logger.error(self.error_msg)
                else:
                    logger.debug(f"{events_p} found!")
            else:
                xero_events = []

                if not self.error_msg:
                    self.error_msg = "Xero project_id or data missing!"
                    logger.error(self.error_msg)

            if day and not self.error_msg:
                key = (
                    day,
                    duration,
                    self.xero_event["user_id"],
                    self.xero_event["task_id"],
                )
                truncated_key = (
                    day,
                    duration,
                    self.xero_event["user_id"].split("-")[0],
                    self.xero_event["task_id"].split("-")[0],
                )
                fields = ["day", "duration", "userId", "taskId"]
                event_keys = {tuple(xe[f] for f in fields) for xe in xero_events}
                exists = (key in event_keys) or not duration
                logger.debug("Day and duration found!")
            else:
                truncated_key = ()
                exists = False

                if not self.error_msg:
                    self.error_msg = "Task day is empty!"
                    logger.error(self.error_msg)

            if exists or self.timely_event["added"]:
                response = {"result": {}, "status_code": 409}

                if not self.error_msg:
                    self.error_msg = f"Xero time entry {truncated_key} already exists!"
                    logger.error(self.error_msg)
            elif data and not self.error_msg:
                logger.debug(f"Xero time entry {truncated_key} is available!")

                if self.dry_run:
                    response = {"result": data}
                else:
                    kwargs = {
                        **app.config,
                        "headers": self.headers,
                        "method": "post",
                        "data": data,
                        "event_id": self.timely_event["id"],
                    }

                    url = f"{self.api_base_url}/projects/{self.xero_project_id}/time"
                    response = get_response(url, self.client, **kwargs)
            else:
                response = {"result": data, "status_code": 400}

                if not self.error_msg:
                    self.error_msg = "No data to add!"
                    logger.error(self.error_msg)
        else:
            base_url = get_request_base()
            self.error_msg = (
                f"The {request.method}:{base_url} route is not yet enabled."
            )
            response = {"status_code": 404}

        response.update(
            {
                "links": get_links(app.url_map.iter_rules()),
                "eof": self.eof,
                "event_id": self.timely_event["id"],
            }
        )

        if self.error_msg:
            response["message"] = self.error_msg

        return jsonify(**response)


class Memoization(MethodView):
    def __init__(self):
        self.kwargs = parse_kwargs(app)

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
    "callback": {"view": auth.Callback},
    "auth": {"view": auth.Auth},
    "resource": {"view": auth.Resource}
    "projects": Projects,
    "users": Users,
    "tasks": Tasks,
    "time": Time,
    "inventory": Inventory,
}

for name, options in method_views.items():
    if options.get("add_prefixes"):
        prefixes = Config.API_PREFIXES
    else:
        prefixes = [None]

    for prefix in prefixes:
        if prefix:
            route_name = f"{prefix}-{name}".lower()
        else:
            route_name = name

        view_func = options["view"].as_view(route_name)
        methods = options.get("methods")
        url = f"{PREFIX}/{route_name}"

        if options.get("param"):
            param = options["param"]
            url += f"/<{param}>"

        add_rule(url, view_func=view_func, methods=methods)

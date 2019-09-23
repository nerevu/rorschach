# -*- coding: utf-8 -*-
"""
    app.api
    ~~~~~~~

    Provides additional api endpoints
"""
from json.decoder import JSONDecodeError
from itertools import chain, islice
from datetime import date, timedelta

from flask import Blueprint, request, redirect, session, url_for, g, current_app as app
from flask import after_this_request
from flask.views import MethodView
from faker import Faker

from config import Config, __APP_TITLE__ as APP_TITLE

from app import cache, __version__, mappings
from app.utils import (
    responsify,
    jsonify,
    parse,
    cache_header,
    make_cache_key,
    uncache_header,
)

from app.mappings import projects, timely_to_xero, timely_events


from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import TokenExpiredError
from riko.dotdict import DotDict

import pygogo as gogo

logger = gogo.Gogo(__name__).logger
blueprint = Blueprint("API", __name__)
fake = Faker()

ROUTE_TIMEOUT = Config.ROUTE_TIMEOUT
SET_TIMEOUT = Config.SET_TIMEOUT
PREFIX = Config.API_URL_PREFIX
HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}


class MyAuthClient(object):
    def __init__(self, prefix, client_id, client_secret, **kwargs):
        self.prefix = prefix
        self.client_id = client_id
        self.client_secret = client_secret
        self.authorization_base_url = kwargs["authorization_base_url"]
        self.token_url = kwargs["token_url"]
        self.refresh_url = kwargs["refresh_url"]
        self.redirect_uri = kwargs["redirect_uri"]
        self.api_base_url = kwargs["api_base_url"]
        self.account_id = kwargs["account_id"]
        self.scope = kwargs.get("scope", "")
        self.tenant_id = kwargs.get("tenant_id", "")
        self.extra = {"client_id": self.client_id, "client_secret": self.client_secret}
        self.error = ""

        if kwargs.get("state"):
            self.state = kwargs["state"]

        self.restore()

        if self.state and self.access_token:
            try:
                self.oauth_session = OAuth2Session(
                    self.client_id,
                    redirect_uri=self.redirect_uri,
                    scope=self.scope,
                    token=self.token,
                    state=self.state,
                    auto_refresh_kwargs=self.extra,
                    auto_refresh_url=self.refresh_url,
                    token_updater=self.update_token,
                )
            except TokenExpiredError:
                # this path shouldn't be reached...
                logger.info("Token expired. Attempting to renew...")
                self.renew_token()
            except Exception as e:
                self.oauth_session = None
                self.error = str(e)
                logger.error(f"Error authenticating: {str(e)}")
            else:
                # this path is reached even for expired xero tokens
                logger.info("Successfully authenticated!")
        elif self.state:
            self.oauth_session = OAuth2Session(
                self.client_id,
                redirect_uri=self.redirect_uri,
                scope=self.scope,
                state=self.state,
            )
        else:
            self.oauth_session = OAuth2Session(
                self.client_id, redirect_uri=self.redirect_uri, scope=self.scope
            )

    def save(self):
        self.state = session.get(f"{self.prefix}_state") or self.state
        cache.set(f"{self.prefix}_state", self.state)
        cache.set(f"{self.prefix}_access_token", self.access_token)
        cache.set(f"{self.prefix}_refresh_token", self.refresh_token)
        cache.set(f"{self.prefix}_expires_in", self.expires_in, SET_TIMEOUT)
        cache.set(f"{self.prefix}_tenant_id", self.tenant_id)

    def restore(self):
        self.state = cache.get(f"{self.prefix}_state") or session.get(
            f"{self.prefix}_state"
        )
        self.access_token = cache.get(f"{self.prefix}_access_token")
        self.refresh_token = cache.get(f"{self.prefix}_refresh_token")
        self.expires_in = cache.get(f"{self.prefix}_expires_in") or SET_TIMEOUT
        self.tenant_id = cache.get(f"{self.prefix}_tenant_id")

    @property
    def token(self):
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_type": "Bearer",
            "expires_in": self.expires_in,
        }

    @token.setter
    def token(self, value):
        self.access_token = value["access_token"]
        self.refresh_token = value["refresh_token"]
        self.token_type = value["token_type"]
        self.expires_in = value.get("expires_in", SET_TIMEOUT)
        self.created_at = value.get("created_at")
        self.save()

    def get_authorization_url(self):
        return self.oauth_session.authorization_url(self.authorization_base_url)

    def fetch_token(self, **kwargs):
        return self.oauth_session.fetch_token(
            self.token_url, client_secret=self.client_secret, **kwargs
        )

    def update_token(self, token):
        self.token = token

    def renew_token(self):
        try:
            logger.info("Renewing token...")
            token = self.oauth_session.refresh_token(self.refresh_url, **self.extra)
        except Exception as e:
            logger.error(f"Client authentication error: {str(e)}")
            self.error = str(e)
        else:
            logger.info("Successfully renewed token!")
            self.token = token
            self.save()


def get_auth_client(prefix, state=None, **kwargs):
    auth_client_name = f"{prefix}_auth_client"

    if auth_client_name not in g:
        auth_kwargs = {
            "authorization_base_url": kwargs[f"{prefix}_AUTHORIZATION_BASE_URL"],
            "token_url": kwargs[f"{prefix}_TOKEN_URL"],
            "redirect_uri": kwargs[f"{prefix}_REDIRECT_URI"],
            "refresh_url": kwargs[f"{prefix}_REFRESH_URL"],
            "api_base_url": kwargs[f"{prefix}_API_BASE_URL"],
            "account_id": kwargs.get(f"{prefix}_ACCOUNT_ID"),
            "scope": kwargs.get(f"{prefix}_SCOPES"),
            "tenant_id": kwargs.get("tenant_id"),
            "state": state,
        }

        client_id = kwargs[f"{prefix}_CLIENT_ID"]
        client_secret = kwargs[f"{prefix}_SECRET"]
        client = MyAuthClient(prefix, client_id, client_secret, **auth_kwargs)
        setattr(g, auth_client_name, client)

    return g.get(auth_client_name)


def get_request_base():
    return request.base_url.split("/")[-1].split("?")[0]


def gen_links(**kwargs):
    url_root = request.url_root.rstrip("/")
    prefixed = f"{url_root}{PREFIX}"
    self_link = request.url

    links = [
        {"rel": "home", "href": prefixed, "method": "GET"},
        {"rel": "events", "href": f"{prefixed}/events", "method": "GET"},
        {"rel": "cached events", "href": f"{prefixed}/cached_events", "method": "GET"},
        {
            "rel": "authenticate timely",
            "href": f"{prefixed}/timely-auth",
            "method": "GET",
        },
        {"rel": "authenticate xero", "href": f"{prefixed}/xero-auth", "method": "GET"},
        {"rel": "refresh timely", "href": f"{prefixed}/timely-auth", "method": "PATCH"},
        {"rel": "refresh xero", "href": f"{prefixed}/xero-auth", "method": "PATCH"},
        {"rel": "timely status", "href": f"{prefixed}/timely-status", "method": "GET"},
        {"rel": "xero status", "href": f"{prefixed}/xero-status", "method": "GET"},
        {"rel": "accounts", "href": f"{prefixed}/accounts", "method": "GET"},
        {"rel": "ipsum", "href": f"{prefixed}/ipsum", "method": "GET"},
        {"rel": "memoize", "href": f"{prefixed}/memoization", "method": "GET"},
        {"rel": "reset", "href": f"{prefixed}/memoization", "method": "DELETE"},
    ]

    for link in links:
        if link["href"] == self_link and link["method"] == request.method:
            link["rel"] = "self"

        yield link


def extract_fields(record, fields, **kwargs):
    item = DotDict(record)

    for field in fields:
        if "[" in field:
            split_field = field.split("[")
            real_field = split_field[0]
            pos = int(split_field[1].split("]")[0])

            try:
                value = item[real_field][pos]
            except IndexError:
                value = None
        else:
            value = item[field]

        yield (field, value)

    if kwargs:
        yield from kwargs.items()


def process_result(result, fields=None, **kwargs):
    for item in result:
        if not (item.get("billed") or item.get("deleted")):
            yield dict(extract_fields(item, fields, **kwargs))


def get_realtime_response(url, client, params=None, **kwargs):
    if client.error:
        logger.error(client.error)
        response = {"status_code": 500, "message": client.error}
    else:
        params = params or {}
        data = kwargs.get("data", {})
        method = kwargs.get("method", "get")
        headers = kwargs.get("headers", HEADERS)
        verb = getattr(client.oauth_session, method)
        result = verb(url, params=params, data=data, headers=headers)

        try:
            json = result.json()
        except JSONDecodeError:
            response = {"message": result.text, "status_code": result.status_code}
        else:
            response = {"result": json}

            if not result.ok:
                response.update(
                    {"status_code": result.status_code, "message": json.get("detail")}
                )

    status_code = response.get("status_code", 200)

    if status_code != 200:

        @after_this_request
        def clear_cache(response):
            response = uncache_header(response)
            return response

    if status_code == 401 and not kwargs.get("renewed"):
        # Token expired
        client.renew_token()
        response = get_realtime_response(
            url, client, params=params, renewed=True, **kwargs
        )
    else:
        response["links"] = list(gen_links())

    return response


def get_redirect_url(prefix):
    """ Step 3: Retrieving an access token.

    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """
    state = request.args.get("state") or session.get(f"{prefix}_state")

    if state:
        client = get_auth_client(prefix, state=state, **app.config)
        client.save()

        if request.args.get("code"):
            token = client.fetch_token(code=request.args["code"])
        else:
            token = client.fetch_token(authorization_response=request.url)

        client.token = token
        client.save()
        redirect_url = url_for(f".{prefix}_status".lower())
    else:
        redirect_url = url_for(f".{prefix}_auth".lower())

    logger.info(token)
    return redirect_url


###########################################################################
# ROUTES
###########################################################################
@blueprint.route(PREFIX)
@cache_header(ROUTE_TIMEOUT, key_prefix=make_cache_key)
def home():
    response = {
        "description": "Returns API documentation",
        "message": f"Welcome to the {APP_TITLE}!",
        "links": list(gen_links()),
    }

    return jsonify(**response)


@blueprint.route(f"{PREFIX}/timely-callback")
def timely_callback():
    return redirect(get_redirect_url("TIMELY"))


@blueprint.route(f"{PREFIX}/xero-callback")
def xero_callback():
    return redirect(get_redirect_url("XERO"))


@blueprint.route(f"{PREFIX}/timely-status")
def timely_status():
    timely = get_auth_client("TIMELY", **app.config)
    api_url = f"{timely.api_base_url}/accounts"
    response = get_realtime_response(api_url, timely, **app.config)
    response["result"] = timely.token
    return jsonify(**response)


@blueprint.route(f"{PREFIX}/xero-status")
def xero_status():
    xero = get_auth_client("XERO", **app.config)
    api_url = f"{xero.api_base_url}/connections"
    response = get_realtime_response(api_url, xero, **app.config)

    if response.get("status_code", 200) == 200:
        result = response.get("result")

        if result and result[0].get("tenantId"):
            xero.tenant_id = result[0]["tenantId"]
            xero.save()
            message = f"Set Xero tenantId to {xero.tenant_id}."
        else:
            message = "No tenantId found."

        logger.info(message)
    else:
        logger.info(response["status_code"])
        message = "Failed to set Xero tenantId!"
        logger.error(message)

    response["result"] = xero.token

    if response.get("message"):
        response["message"] += f" {message}"
    else:
        response.update({"message": message})

    return jsonify(**response)


@blueprint.route(f"{PREFIX}/connections")
def connections():
    xero = get_auth_client("XERO", **app.config)
    api_url = f"{xero.api_base_url}/connections"
    response = get_realtime_response(api_url, xero, **app.config)
    return jsonify(**response)


@blueprint.route(f"{PREFIX}/accounts")
def accounts():
    timely = get_auth_client("TIMELY", **app.config)
    api_url = f"{timely.api_base_url}/accounts"
    response = get_realtime_response(api_url, timely, **app.config)
    return jsonify(**response)


@blueprint.route(f"{PREFIX}/labels")
def labels():
    timely = get_auth_client("TIMELY", **app.config)
    api_url = f"{timely.api_base_url}/{timely.account_id}/labels"
    response = get_realtime_response(api_url, timely, **app.config)
    fields = ["id", "name"]
    _billable = next(r["children"] for r in response["result"] if r["id"] == 1344430)
    _non_billable = next(
        r["children"] for r in response["result"] if r["id"] == 1339635
    )
    billable = process_result(_billable, fields, billable=True)
    non_billable = process_result(_non_billable, fields, billable=False)
    response["result"] = list(chain(billable, non_billable))
    return jsonify(**response)


@blueprint.route(f"{PREFIX}/ipsum")
@cache_header(ROUTE_TIMEOUT, key_prefix="%s")
def ipsum():
    response = {
        "description": "Displays a random sentence",
        "links": list(gen_links()),
        "result": fake.sentence(),
    }

    return jsonify(**response)


###########################################################################
# METHODVIEW ROUTES
###########################################################################
class Auth(MethodView):
    def __init__(self, prefix):
        self.prefix = prefix

    def get(self):
        """Step 1: User Authorization.

        Redirect the user/resource owner to the OAuth provider (i.e. Github)
        using an URL with a few key OAuth parameters.
        """
        client = get_auth_client(self.prefix, **app.config)
        authorization_url, state = client.get_authorization_url()

        # https://gist.github.com/ib-lundgren/6507798#gistcomment-1006218
        # State is used to prevent CSRF, keep this for later.
        client.state = session[f"{self.prefix}_state"] = state
        client.save()

        # Step 2: User authorization, this happens on the provider.
        logger.info("redirecting to %s", authorization_url)
        return redirect(authorization_url)

    def patch(self):
        client = get_auth_client(self.prefix, **app.config)
        client.renew_token()
        return redirect(url_for(f".{self.prefix}_status".lower()))


class ProjectBase(MethodView):
    def __init__(self, prefix):
        self.prefix = prefix
        self.lowered = self.prefix.lower()
        self.client = get_auth_client(self.prefix, **app.config)
        self.fields = []
        self.subkey = ""
        self.params = {}
        self.headers = {}
        self.post_process = False

        project_ids = (p[self.lowered]["id"] for p in projects if p.get(self.lowered))
        project_pos = int(request.args.get("pos", 0))
        def_project_id = next(islice(project_ids, project_pos, None))
        self.project_id = request.args.get("id", def_project_id)

        if self.prefix == "TIMELY":
            self.api_base_url = f"{self.client.api_base_url}/{self.client.account_id}"
        elif self.prefix == "XERO":
            self.headers = {**HEADERS, "Xero-tenant-id": self.client.tenant_id}
            self.api_base_url = f"{self.client.api_base_url}/projects.xro/2.0"
            self.subkey = "items"

    def get(self):
        response = get_realtime_response(
            self.api_url,
            self.client,
            headers=self.headers,
            params=self.params,
            **app.config,
        )

        result = response["result"]

        if self.subkey:
            response["result"] = result = result[self.subkey]

        if self.fields and request.args.get("process", "").lower() == "true":
            response["result"] = result = list(process_result(result, self.fields))

        if self.post_process:
            # populate result with mapping info
            mapping = getattr(mappings, self.__class__.__name__.lower())
            result = [
                m[self.lowered]
                for m in mapping
                if m.get(self.lowered) and m[self.lowered]["id"] in set(result)
            ]

            # populate result with projectId
            fields = ["billable", "id", "name"]
            response["result"] = list(
                process_result(result, fields, projectId=self.project_id)
            )

        return jsonify(**response)


class Projects(ProjectBase):
    def __init__(self, prefix):
        super().__init__(prefix)

        if self.prefix == "TIMELY":
            self.api_url = f"{self.api_base_url}/projects"
            self.fields = ["active", "billable", "id", "name"]
        elif self.prefix == "XERO":
            self.api_url = f"{self.api_base_url}/projects"
            self.fields = ["name", "projectId", "status"]


class Users(ProjectBase):
    def __init__(self, prefix):
        super().__init__(prefix)

        if self.prefix == "TIMELY":
            self.api_url = f"{self.api_base_url}/users"
            self.fields = ["name", "id"]
        elif self.prefix == "XERO":
            self.api_url = f"{self.api_base_url}/projectsusers"
            self.fields = ["name", "userId"]


class Tasks(ProjectBase):
    def __init__(self, prefix):
        super().__init__(prefix)

        if self.prefix == "TIMELY":
            self.api_url = f"{self.api_base_url}/projects/{self.project_id}"
            self.subkey = "label_ids"
            self.post_process = True
        elif self.prefix == "XERO":
            self.api_url = f"{self.api_base_url}/projects/{self.project_id}/tasks"
            self.fields = ["name", "taskId", "status", "rate.value", "projectId"]


class Time(ProjectBase):
    def __init__(self, prefix):
        super().__init__(prefix)

        def_end = date.today()
        def_start = def_end - timedelta(days=app.config["REPORT_DAYS"])
        end = request.args.get("end", def_end.strftime("%Y-%m-%d"))
        start = request.args.get("start", def_start.strftime("%Y-%m-%d"))

        if self.prefix == "TIMELY":
            self.params = {"since": start, "upto": end}
            self.api_url = f"{self.api_base_url}/projects/{self.project_id}/events"
            self.fields = [
                "id",
                "day",
                "duration.total_minutes",
                "label_ids[0]",
                "project.id",
                "user.id",
                "note",
                "billed",
            ]
        elif self.prefix == "XERO":
            self.params = {"dateAfterUtc": start, "dateBeforeUtc": end}
            self.api_url = f"{self.api_base_url}/projects/{self.project_id}/time"
            self.fields = []

    def post(self):
        # xero_project_id = "803591c3-72af-4475-888f-7c4c50044589"
        # data = {"timelyEventId":165829339}
        # r = requests.post(url, data=data, params={"id": xero_project_id})
        if self.prefix == "XERO":
            timely_event_id = request.form.get("timelyEventId")
            error_msg = ""

            if timely_event_id:
                event = timely_events.get(timely_event_id)
            else:
                error_msg = "No 'timelyEventId' given!"
                event = {}

            if event:
                project_match = (
                    timely_to_xero["projects"].get(event["project.id"])
                    == self.project_id
                )
            else:
                project_match = False
                error_msg = error_msg or f"Timely event {timely_event_id} not found!"

            if project_match:
                unbilled = not event["billed"]
            else:
                unbilled = False
                error_msg = (
                    error_msg or f"Timely project {event['project.id']} not found!"
                )

            if unbilled:
                user_id = timely_to_xero["users"].get(event["user.id"])
            else:
                user_id = ""
                error_msg = error_msg or "Timely task already billed!"

            if user_id:
                task_id = timely_to_xero["tasks"].get(event["label_ids[0]"])
            else:
                task_id = ""
                error_msg = error_msg or f"Timely user {event['user.id']} not found!"

            if task_id:
                data = {"userId": user_id, "taskId": task_id}
            else:
                data = {}
                error_msg = (
                    error_msg or f"Timely task {event['label_ids[0]']} not found!"
                )

            if data:
                data.update(
                    {
                        "dateUtc": event["day"],
                        "duration": event["duration.total_minutes"],
                        "description": event["note"],
                    }
                )

                kwargs = {
                    **app.config,
                    "headers": self.headers,
                    "method": "post",
                    "data": data,
                }
                response = {"result": data}
                # response = get_realtime_response(self.api_url, self.client, **kwargs)
            else:
                response = {
                    "result": data,
                    "status_code": 404,
                    "links": list(gen_links()),
                    "message": error_msg,
                }
        else:
            base_url = get_request_base()

            response = {
                "status_code": 404,
                "links": list(gen_links()),
                "message": f"The {request.method}:{base_url} route is not yet enabled.",
            }

        return jsonify(**response)


class Memoization(MethodView):
    def get(self):
        base_url = get_request_base()

        response = {
            "description": "Deletes a cache url",
            "links": list(gen_links()),
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

        response = {"links": list(gen_links()), "message": message}
        return jsonify(**response)


memo_view = Memoization.as_view("memoization")
memo_url = f"{PREFIX}/memoization"
memo_path_url = f"{memo_url}/<string:path>"

add_rule = blueprint.add_url_rule

method_views = {
    "auth": Auth,
    "projects": Projects,
    "users": Users,
    "tasks": Tasks,
    "time": Time,
}

for name, _cls in method_views.items():
    for prefix in ["TIMELY", "XERO"]:
        route_name = f"{prefix}-{name}".lower()
        add_rule(
            f"{PREFIX}/{route_name}", view_func=_cls.as_view(f"{route_name}", prefix)
        )

add_rule(memo_url, view_func=memo_view)
add_rule(memo_path_url, view_func=memo_view, methods=["DELETE"])

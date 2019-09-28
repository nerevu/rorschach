# -*- coding: utf-8 -*-
"""
    app.api
    ~~~~~~~

    Provides additional api endpoints
"""
from json.decoder import JSONDecodeError
from json import load
from itertools import chain, islice
from datetime import date, timedelta
from pathlib import Path
from datetime import timedelta, datetime as dt
from urllib.parse import urlencode, parse_qs, parse_qsl, unquote_plus

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

from app.mappings import projects, timely_to_xero

from requests_oauthlib import OAuth2Session, OAuth1Session, OAuth1
from requests_oauthlib.oauth1_session import TokenRequestDenied
from oauthlib.oauth2 import TokenExpiredError
from riko.dotdict import DotDict

import requests
import pygogo as gogo

logger = gogo.Gogo(__name__, monolog=True).logger
blueprint = Blueprint("API", __name__)
fake = Faker()

ROUTE_TIMEOUT = Config.ROUTE_TIMEOUT
SET_TIMEOUT = Config.SET_TIMEOUT
PREFIX = Config.API_URL_PREFIX
HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}
BILLABLE_LABEL_ID = 1344430
NONBILLABLE_LABEL_ID = 1339635
OAUTH_EXPIRY_SECONDS = 3600
EXPIRATION_BUFFER = 30
TOKEN_CACHE = {}


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
                if self.oauth_session.authorized:
                    logger.info("Successfully authenticated!")
                else:
                    logger.info("Not authorized. Attempting to renew...")
                    self.renew_token()
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
        if self.refresh_token:
            try:
                logger.info(f"Renewing token using {self.refresh_url}...")
                token = self.oauth_session.refresh_token(self.refresh_url, self.refresh_token)
            except Exception as e:
                logger.error(f"Failed to renew token: {str(e)}")
                self.error = str(e)
            else:
                if self.oauth_session.authorized:
                    logger.info("Successfully renewed token!")
                    self.token = token
                    self.save()
                else:
                    logger.error("Failed to renew token!")
        else:
            error = "No refresh token present. Please re-authenticate!"
            logger.error(error)
            self.error = error


class MyAuth1Client(object):
    def __init__(self, prefix, client_id, client_secret, **kwargs):
        self.request_url = kwargs["request_url"]
        self.authorization_base_url = kwargs["authorization_base_url"]
        self.token_url = kwargs["token_url"]
        self.client_id = client_id
        self.client_secret = client_secret
        self.api_base_url = kwargs["api_base_url"]
        self.redirect_uri = kwargs["redirect_uri"]
        self.error = ""
        self.oauth1 = True

        self.verified = False
        self.oauth_token = None
        self.oauth_token_secret = None
        self.oauth_expires_at = None
        self.oauth_authorization_expires_at = None
        self.restore()
        self._init_credentials()
        self.save()

    def restore(self):
        attrs = ['verified', 'oauth_token', 'oauth_token_secret', 'oauth_expires_at','oauth_authorization_expires_at']
        [setattr(self, attr, TOKEN_CACHE[attr]) for attr in attrs if TOKEN_CACHE.get(attr)]

    def _init_credentials(self):
        if not(self.oauth_token and self.oauth_token_secret):
            oauth_kwargs = {"client_secret": self.client_secret, "callback_uri": self.redirect_uri}
            oauth = OAuth1(self.client_id, **oauth_kwargs)
            r = requests.post(url=self.request_url, auth=oauth)
            self._process_oauth_response(r)

    @property
    def oauth(self):
        oauth_kwargs = {**self.resource_kwargs, "client_secret": self.client_secret}
        return OAuth1(self.client_id, **oauth_kwargs)

    def _process_oauth_response(self, response):
        if response.ok:
            credentials = {k: v[0] for k, v in parse_qs(response.text).items()}
            self.oauth_token = credentials['oauth_token']
            self.oauth_token_secret = credentials['oauth_token_secret']

            oauth_expires_in = credentials.get('oauth_expires_in', OAUTH_EXPIRY_SECONDS)
            oauth_authorisation_expires_in = credentials.get('oauth_authorization_expires_in', OAUTH_EXPIRY_SECONDS)

            self.oauth_expires_at = dt.now() + timedelta(seconds=int(oauth_expires_in))
            self.oauth_authorization_expires_at = dt.now() + timedelta(seconds=int(oauth_authorisation_expires_in))
            self.save()
        else:
            logger.error(f"not ok! {response.text}")
            self.error = response.text

    def save(self):
        TOKEN_CACHE.update(self.token)

    @property
    def token(self):
        attrs = ['verified', 'oauth_token', 'oauth_token_secret', 'oauth_expires_at','oauth_authorization_expires_at']
        return {attr: getattr(self, attr) for attr in attrs}

    @property
    def resource_kwargs(self):
        return {
            "resource_owner_key": self.oauth_token,
            "resource_owner_secret": self.oauth_token_secret,
        }

    @property
    def oauth_session(self):
        oauth_kwargs = {"client_secret": self.client_secret, **self.resource_kwargs}
        return OAuth1Session(self.client_id, **oauth_kwargs)

    def verify(self, verifier):
        oauth = OAuth1(
            self.client_id,
            client_secret=self.client_secret,
            resource_owner_key=self.oauth_token,
            resource_owner_secret=self.oauth_token_secret,
            verifier=verifier,
        )

        response = requests.post(url=self.token_url, auth=oauth)
        self._process_oauth_response(response)

        if response.ok:
            self.verified = True
            self.save()

    @property
    def authorization_url(self):
        query_string = {'oauth_token': self.oauth_token}
        return f"{self.authorization_base_url}?{urlencode(query_string)}"

    @property
    def expired(self):
        expires_at = self.token.get("oauth_expires_at", dt.now())
        return expires_at <= dt.now() + timedelta(seconds=EXPIRATION_BUFFER)


def get_auth_client(prefix, state=None, **kwargs):
    auth_client_name = f"{prefix}_auth_client"

    if True:
        oauth_version = kwargs.get(f"{prefix}_OAUTH_VERSION", 2)

        if oauth_version == 1:
            client_id = kwargs[f"{prefix}_CONSUMER_KEY"]
            client_secret = kwargs[f"{prefix}_CONSUMER_SECRET"]

            _auth_kwargs = {
                "request_url": kwargs.get(f"{prefix}_REQUEST_URL"),
                "authorization_base_url": kwargs.get(f"{prefix}_AUTHORIZATION_BASE_URL_V1"),
                "token_url": kwargs.get(f"{prefix}_TOKEN_URL_V1"),
            }
        else:
            client_id = kwargs[f"{prefix}_CLIENT_ID"]
            client_secret = kwargs[f"{prefix}_SECRET"]

            _auth_kwargs = {
                "authorization_base_url": kwargs[f"{prefix}_AUTHORIZATION_BASE_URL"],
                "token_url": kwargs[f"{prefix}_TOKEN_URL"],
                "refresh_url": kwargs[f"{prefix}_REFRESH_URL"],
                "scope": kwargs.get(f"{prefix}_SCOPES"),
                "tenant_id": kwargs.get("tenant_id"),
                "state": state,
            }

        auth_kwargs = {
            **kwargs,
            **_auth_kwargs,
            "oauth_version": oauth_version,
            "api_base_url": kwargs[f"{prefix}_API_BASE_URL"],
            "redirect_uri": kwargs.get(f"{prefix}_REDIRECT_URI"),
            "account_id": kwargs.get(f"{prefix}_ACCOUNT_ID"),
        }

        client = MyAuth1Client(prefix, client_id, client_secret, **auth_kwargs)

    return client


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

            if real_field == "label_ids":
                values = [
                    label
                    for label in item[real_field]
                    if label not in {BILLABLE_LABEL_ID, NONBILLABLE_LABEL_ID}
                ]
            else:
                values = item[real_field]

            try:
                value = values[pos]
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


def add_day(item):
    day = item["dateUtc"].split("T")[0]
    return {**item, "day": day}


def get_realtime_response(url, client, params=None, **kwargs):
    if client.error:
        response = {"status_code": 500, "message": client.error}
    elif not client.verified:
        response = {"message": "Client not authorized.", "status_code": 401}
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
            status_code = 401 if result.status_code == 200 else result.status_code

            if "<!DOCTYPE html>" in result.text:
                message = "Got HTML response."
            elif "oauth_problem_advice" in result.text:
                message = parse_qs(result.text)["oauth_problem_advice"][0]

            response = {"message": message, "status_code": status_code}
        else:
            if result.ok:
                response = {"result": json}
            else:

                for part in (result.request.body or "").split("&"):
                    logger.debug(part)

                message = json.get("message") or json.get("detail")
                response = {"status_code": result.status_code, "message": message}

    status_code = response.get("status_code", 200)

    if status_code != 200:

        @after_this_request
        def clear_cache(response):
            response = uncache_header(response)
            return response

    if status_code == 401 and not (client.oauth1 or kwargs.get("renewed")):
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
    oauth_response = request.args

    if not all(map(oauth_response.get, ['oauth_token', 'oauth_verifier', 'org'])):
        logger.error('Missing parameters required.')

    client = get_auth_client(prefix, **app.config)
    client.verify(oauth_response['oauth_verifier'])
    redirect_url = url_for(f".{prefix}_status".lower())



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

    if xero.oauth1:
        api_url = f"{xero.api_base_url}/projects.xro/2.0/projectsusers"
        message = ""
    else:
        api_url = f"{xero.api_base_url}/connections"

    response = get_realtime_response(api_url, xero, **app.config)

    if not xero.oauth1:
        if response.get("status_code", 200) == 200:
            if result and result[0].get("tenantId"):
                xero.tenant_id = result[0]["tenantId"]
                xero.save()
                message = f"Set Xero tenantId to {xero.tenant_id}."
            else:
                message = "No tenantId found."

            logger.info(message)
        else:
            message = "Failed to set Xero tenantId! "
            logger.error(message)

    response["result"] = xero.token

    if message and response.get("message"):
        response["message"] += message
    elif message:
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

    if request.args.get("process", "").lower() == "true":
        fields = ["id", "name"]
        _billable = next(
            r["children"] for r in response["result"] if r["id"] == BILLABLE_LABEL_ID
        )
        _non_billable = next(
            r["children"] for r in response["result"] if r["id"] == NONBILLABLE_LABEL_ID
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

        # https://gist.github.com/ib-lundgren/6507798#gistcomment-1006218
        # State is used to prevent CSRF, keep this for later.

        # Step 2: User authorization, this happens on the provider.
        if client.verified and not client.expired:
            redirect_url = url_for(f".{self.prefix}_status".lower())
        else:
            redirect_url = client.authorization_url

        logger.info("redirecting to %s", redirect_url)
        return redirect(redirect_url)

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
        self.populate = False
        self.add_day = False
        self.project_pos = int(request.values.get("projectPos", 0))
        self.event_pos = int(request.values.get("eventPos", 0))

        project_ids = (p[self.lowered] for p in projects if p.get(self.lowered))
        def_project_id = next(islice(project_ids, self.project_pos, None))
        self.project_id = request.values.get("id", def_project_id)

        if self.prefix == "TIMELY":
            self.api_base_url = f"{self.client.api_base_url}/{self.client.account_id}"
        elif self.prefix == "XERO":
            self.headers = {**HEADERS, "Xero-tenant-id": self.client.tenant_id}
            self.api_base_url = f"{self.client.api_base_url}/projects.xro/2.0"
            self.subkey = "items"

    def get(self):
        process = request.args.get("process", "").lower() == "true"
        response = get_realtime_response(
            self.api_url,
            self.client,
            headers=self.headers,
            params=self.params,
            **app.config,
        )

        result = response.get("result")

        if self.subkey and result:
            response["result"] = result = result[self.subkey]

        if self.fields and process and result:
            response["result"] = result = list(process_result(result, self.fields))

        if self.populate and result:
            # populate result with mapping info
            mapping = getattr(mappings, self.__class__.__name__.lower())
            result = [
                m[self.lowered]
                for m in mapping
                if m.get(self.lowered) and m[self.lowered]["id"] in set(result)
            ]

            # populate result with projectId
            fields = ["billable", "id", "name"]
            response["result"] = result = list(
                process_result(result, fields, projectId=self.project_id)
            )

        if self.add_day and result:
            response["result"] = result = [add_day(item) for item in result]

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
            print({"client_id": self.client.client_id})


class Tasks(ProjectBase):
    def __init__(self, prefix):
        super().__init__(prefix)

        if self.prefix == "TIMELY":
            self.api_url = f"{self.api_base_url}/projects/{self.project_id}"
            self.subkey = "label_ids"
            self.populate = True
        elif self.prefix == "XERO":
            self.api_url = f"{self.api_base_url}/projects/{self.project_id}/tasks"
            self.fields = ["name", "taskId", "status", "rate.value", "projectId"]


class Time(ProjectBase):
    def __init__(self, prefix):
        super().__init__(prefix)

        def_end = date.today()
        def_start = def_end - timedelta(days=app.config["REPORT_DAYS"])
        end = request.values.get("end", def_end.strftime("%Y-%m-%d"))
        start = request.values.get("start", def_start.strftime("%Y-%m-%d"))

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
            self.add_day = True
            self.params = {"dateAfterUtc": start, "dateBeforeUtc": end}
            self.api_url = f"{self.api_base_url}/projects/{self.project_id}/time"

    def put(self):
        # r = requests.put(url, data={"eventId": 165829339, "dryRun": "true"})
        if self.prefix == "TIMELY":
            if request.form.get("eventId"):
                event_id = request.form["eventId"]
            else:
                project_id = request.form.get("projectId", self.project_id)
                p = Path(f"app/data/timely_{project_id}_events.json")

                try:
                    timely_events = load(p.open())
                except FileNotFoundError:
                    timely_events = {}
                    error_msg = f"File {p} not found!"

                if timely_events:
                    try:
                        event = timely_events[self.event_pos]
                    except IndexError:
                        event = {}
                        eof = True

                        if not error_msg:
                            error_msg = f"Event position {self.event_pos} not found!"
                            logger.error(error_msg)
                else:
                    event = {}

                    if not error_msg:
                        error_msg = "No events found!"
                        logger.error(error_msg)

                event_id = event.get("id")

            if event_id:
                self.api_url = f"{self.api_base_url}/events/{event_id}"
                total_minutes = event["duration.total_minutes"]

                data = {
                    "id": event_id,
                    "day": event["day"],
                    "hours": total_minutes // 60,
                    "minutes": total_minutes % 60,
                    "billed": True,
                }

                kwargs = {
                    **app.config,
                    "headers": self.headers,
                    "method": "put",
                    "data": data,
                }

                if request.values.get("dryRun") == "true":
                    response = {"result": data}
                else:
                    response = get_realtime_response(
                        self.api_url, self.client, **kwargs
                    )
            else:
                if not error_msg:
                    error_msg = f"No event_id found!"
                    logger.error(error_msg)

                response = {"status_code": 404}

        else:
            base_url = get_request_base()
            error_msg = f"The {request.method}:{base_url} route is not yet enabled."
            response = {"status_code": 404}

        response.update(
            {
                "links": list(gen_links()),
                "message": error_msg,
                "eof": eof,
                "event_id": event["id"],
            }
        )
        return jsonify(**response)

    def post(self):
        # r = requests.post(url, data={"timelyProjectId": 2389295, "dryRun": "true"})
        if self.prefix == "XERO":
            timely_project_id = int(request.form.get("timelyProjectId", 0))
            error_msg = ""
            eof = False

            if timely_project_id:
                project_id = timely_to_xero["projects"].get(timely_project_id)
                p = Path(f"app/data/timely_{timely_project_id}_events.json")

                try:
                    timely_events = load(p.open())
                except FileNotFoundError:
                    timely_events = {}
                    error_msg = f"File {p} not found!"
                    logger.error(error_msg)
            else:
                project_id = None
                timely_events = {}
                error_msg = "No 'timelyProjectId' given!"
                logger.error(error_msg)

            if timely_events:
                try:
                    event = timely_events[self.event_pos]
                except IndexError:
                    event = {}
                    eof = True

                    if not error_msg:
                        error_msg = f"Event {self.event_pos} not found!"
                        logger.error(error_msg)
            else:
                event = {}

                if not error_msg:
                    error_msg = "No events found!"
                    logger.error(error_msg)

            unbilled = not event.get("billed")
            timely_user_id = event.get("user.id")
            label_id = int(event.get("label_ids[0]", 0))
            timely_event_id = event.get("id")

            if unbilled:
                user_id = timely_to_xero["users"].get(timely_user_id)
            else:
                user_id = ""

                if not error_msg:
                    error_msg = f"Event {timely_event_id} is already billed!"
                    logger.error(error_msg)

            if user_id:
                task_id = (
                    timely_to_xero["tasks"].get(timely_project_id, {}).get(label_id)
                )
            else:
                task_id = ""

                if not error_msg:
                    error_msg = (
                        f"Timely user {timely_user_id} not found in Xero mapping!"
                    )
                    logger.error(error_msg)

            if task_id:
                data = {"userId": user_id, "taskId": task_id}
            else:
                data = {}

                if not error_msg:
                    error_msg = f"Timely -> Xero 'project:label' mapping missing! \n\t{timely_project_id}:{label_id} -> {project_id}:"
                    logger.error(error_msg)

            if data:
                day = event["day"]
                duration = event["duration.total_minutes"]
                description = event["note"]
                data.update(
                    {"dateUtc": day, "duration": duration, "description": description}
                )
            else:
                day = duration = None

            if project_id:
                xero_trunc_project_id = project_id.split("-")[0]
                p = Path(f"app/data/xero_{xero_trunc_project_id}_events.json")

                try:
                    xero_events = load(p.open())
                except FileNotFoundError:
                    xero_events = {}
                    error_msg = f"File {p} not found!"
                    logger.error(error_msg)
            else:
                xero_events = {}

                if not error_msg:
                    error_msg = "Xero project_id missing!"
                    logger.error(error_msg)

            if day and duration:
                key = (day, duration, user_id, task_id)
                fields = ["day", "duration", "userId", "taskId"]
                event_keys = {tuple(xe[f] for f in fields) for xe in xero_events}
                exists = key in event_keys
            else:
                exists = True

                if not error_msg:
                    error_msg = "Either day or duration (or both) are empty!"
                    logger.error(error_msg)

            if exists:
                response = {}

                if not error_msg:
                    error_msg = f"Xero time entry {key} already exists!"
                    logger.error(error_msg)
            elif data:
                kwargs = {
                    **app.config,
                    "headers": self.headers,
                    "method": "post",
                    "data": data,
                    "event_id": timely_event_id,
                }

                if request.values.get("dryRun") == "true":
                    response = {"result": data}
                else:
                    response = get_realtime_response(
                        self.api_url, self.client, **kwargs
                    )
            else:
                response = {"result": data}

                if not error_msg:
                    error_msg = "No data to add!"
                    logger.error(error_msg)

            if not response:
                response = {"result": data, "status_code": 404}
        else:
            base_url = get_request_base()
            error_msg = f"The {request.method}:{base_url} route is not yet enabled."
            response = {"status_code": 404}

        response.update(
            {
                "links": list(gen_links()),
                "message": error_msg,
                "eof": eof,
                "event_id": timely_event_id,
            }
        )
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

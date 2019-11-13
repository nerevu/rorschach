# -*- coding: utf-8 -*-
"""
    app.api
    ~~~~~~~

    Provides additional api endpoints
"""
from json.decoder import JSONDecodeError
from json import load, dumps
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

import pygogo as gogo

logger = gogo.Gogo(__name__, monolog=True).logger
blueprint = Blueprint("API", __name__)
fake = Faker()

ROUTE_TIMEOUT = Config.ROUTE_TIMEOUT
SET_TIMEOUT = Config.SET_TIMEOUT
PREFIX = Config.API_URL_PREFIX
HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}
BILLABLE = 1344430
NONBILLABLE = 1339635
OAUTH_EXPIRY_SECONDS = 3600
EXPIRATION_BUFFER = 30

timely_events_p = Path(f"app/data/timely_events.json")
timely_users_p = Path(f"app/data/timely_users.json")
timely_projects_p = Path(f"app/data/timely_projects.json")
timely_tasks_p = Path(f"app/data/timely_tasks.json")
sync_results_p = Path(f"app/data/sync_results.json")
timely_events = load(timely_events_p.open())
timely_users = load(timely_users_p.open())
timely_projects = load(timely_projects_p.open())
timely_tasks = load(timely_tasks_p.open())


class AuthClient(object):
    def __init__(self, prefix, client_id, client_secret, **kwargs):
        self.prefix = prefix
        self.client_id = client_id
        self.client_secret = client_secret
        self.oauth1 = kwargs["oauth_version"] == 1
        self.oauth2 = kwargs["oauth_version"] == 2
        self.authorization_base_url = kwargs["authorization_base_url"]
        self.redirect_uri = kwargs["redirect_uri"]
        self.api_base_url = kwargs["api_base_url"]
        self.token_url = kwargs["token_url"]
        self.account_id = kwargs["account_id"]
        self.state = kwargs.get("state")
        self.created_at = None
        self.error = ""

    @property
    def expired(self):
        return self.expires_at <= dt.now() + timedelta(seconds=EXPIRATION_BUFFER)


class MyAuth2Client(AuthClient):
    def __init__(self, prefix, client_id, client_secret, **kwargs):
        super().__init__(prefix, client_id, client_secret, **kwargs)
        self.refresh_url = kwargs["refresh_url"]
        self.scope = kwargs.get("scope", "")
        self.tenant_id = kwargs.get("tenant_id", "")
        self.extra = {"client_id": self.client_id, "client_secret": self.client_secret}
        self.expires_at = dt.now()
        self.expires_in = 0
        self.oauth_session = None
        self.restore()
        self._init_credentials()

    def _init_credentials(self):
        try:
            self.oauth_session = OAuth2Session(self.client_id, **self.oauth_kwargs)
        except TokenExpiredError:
            # this path shouldn't be reached...
            logger.warning("Token expired. Attempting to renew...")
            self.renew_token()
        except Exception as e:
            self.error = str(e)
            logger.error(f"Error authenticating: {self.error}", exc_info=True)
        else:
            if self.verified:
                logger.info("Successfully authenticated!")
            else:
                logger.warning("Not authorized. Attempting to renew...")

                self.renew_token()

    @property
    def oauth_kwargs(self):
        if self.state and self.access_token:
            token_fields = ["access_token", "refresh_token", "token_type", "expires_in"]
            token = {field: self.token[field] for field in token_fields}
            oauth_kwargs = {
                "redirect_uri": self.redirect_uri,
                "scope": self.scope,
                "token": token,
                "state": self.state,
                "auto_refresh_kwargs": self.extra,
                "auto_refresh_url": self.refresh_url,
                "token_updater": self.update_token,
            }
        elif self.state:
            oauth_kwargs = {
                "redirect_uri": self.redirect_uri,
                "scope": self.scope,
                "state": self.state,
            }
        else:
            oauth_kwargs = {"redirect_uri": self.redirect_uri, "scope": self.scope}

        return oauth_kwargs

    @property
    def token(self):
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_type": "Bearer",
            "expires_in": self.expires_in,
            "expires_at": self.expires_at,
            "expired": self.expired,
            "verified": self.verified,
            "created_at": self.created_at,
        }

    @token.setter
    def token(self, value):
        self.access_token = value["access_token"]
        self.refresh_token = value["refresh_token"]
        self.token_type = value["token_type"]
        self.created_at = value.get("created_at", dt.now())
        self.expires_in = value.get("expires_in", SET_TIMEOUT)
        self.expires_at = dt.now() + timedelta(seconds=self.expires_in)

        self.save()
        logger.debug(self.token)

    @property
    def verified(self):
        return self.oauth_session.authorized if self.oauth_session else False

    @property
    def authorization_url(self):
        return self.oauth_session.authorization_url(self.authorization_base_url)

    def fetch_token(self):
        kwargs = {"client_secret": self.client_secret}

        if request.args.get("code"):
            kwargs["code"] = request.args["code"]
        else:
            kwargs["authorization_response"] = request.url

        try:
            token = self.oauth_session.fetch_token(self.token_url, **kwargs)
        except Exception as e:
            self.error = str(e)
            logger.error(f"Failed to fetch token: {self.error}", exc_info=True)
            token = {}
        else:
            self.token = token

        return token

    def update_token(self, token):
        self.token = token

    def renew_token(self):
        if self.refresh_token:
            try:
                logger.info(f"Renewing token using {self.refresh_url}...")
                token = self.oauth_session.refresh_token(
                    self.refresh_url, self.refresh_token
                )
            except Exception as e:
                self.error = str(e)
                logger.error(f"Failed to renew token: {self.error}", exc_info=True)
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

    def save(self):
        self.state = session.get(f"{self.prefix}_state") or self.state
        cache.set(f"{self.prefix}_state", self.state)
        cache.set(f"{self.prefix}_access_token", self.access_token)
        cache.set(f"{self.prefix}_refresh_token", self.refresh_token)
        cache.set(f"{self.prefix}_created_at", self.created_at)
        cache.set(f"{self.prefix}_expires_at", self.expires_at)
        cache.set(f"{self.prefix}_tenant_id", self.tenant_id)

    def restore(self):
        self.state = cache.get(f"{self.prefix}_state") or session.get(
            f"{self.prefix}_state"
        )
        self.access_token = cache.get(f"{self.prefix}_access_token")
        self.refresh_token = cache.get(f"{self.prefix}_refresh_token")
        self.created_at = cache.get(f"{self.prefix}_created_at")
        self.expires_at = cache.get(f"{self.prefix}_expires_at") or dt.now()
        self.expires_in = (self.expires_at - dt.now()).total_seconds()
        self.tenant_id = cache.get(f"{self.prefix}_tenant_id")


class MyAuth1Client(AuthClient):
    def __init__(self, prefix, client_id, client_secret, **kwargs):
        super().__init__(prefix, client_id, client_secret, **kwargs)
        self.request_url = kwargs["request_url"]
        self.verified = False
        self.oauth_token = None
        self.oauth_token_secret = None
        self.oauth_expires_at = None
        self.oauth_authorization_expires_at = None

        self.restore()
        self._init_credentials()

    def _init_credentials(self):
        if not (self.oauth_token and self.oauth_token_secret):
            try:
                self.token = self.oauth_session.fetch_request_token(self.request_url)
            except TokenRequestDenied as e:
                self.error = str(e)
                logger.error(f"Error authenticating: {self.error}", exc_info=True)

    @property
    def resource_owner_kwargs(self):
        return {
            "resource_owner_key": self.oauth_token,
            "resource_owner_secret": self.oauth_token_secret,
        }

    @property
    def oauth_kwargs(self):
        oauth_kwargs = {"client_secret": self.client_secret}

        if self.oauth_token and self.oauth_token_secret:
            oauth_kwargs.update(self.resource_owner_kwargs)
        else:
            oauth_kwargs["callback_uri"] = self.redirect_uri

        return oauth_kwargs

    @property
    def oauth_session(self):
        return OAuth1Session(self.client_id, **self.oauth_kwargs)

    @property
    def token(self):
        return {
            "oauth_token": self.oauth_token,
            "oauth_token_secret": self.oauth_token_secret,
            "expires_in": self.oauth_expires_in,
            "expires_at": self.oauth_expires_at,
            "expired": self.expired,
            "verified": self.verified,
            "created_at": self.created_at,
        }

    @token.setter
    def token(self, token):
        self.oauth_token = token["oauth_token"]
        self.oauth_token_secret = token["oauth_token_secret"]

        oauth_expires_in = token.get("oauth_expires_in", OAUTH_EXPIRY_SECONDS)
        oauth_authorisation_expires_in = token.get(
            "oauth_authorization_expires_in", OAUTH_EXPIRY_SECONDS
        )

        self.created_at = token.get("created_at", dt.now())
        self.oauth_expires_at = dt.now() + timedelta(seconds=int(oauth_expires_in))

        seconds = timedelta(seconds=int(oauth_authorisation_expires_in))
        self.oauth_authorization_expires_at = dt.now() + seconds

        self.save()
        logger.debug(self.token)

    @property
    def expires_at(self):
        return self.oauth_expires_at

    @property
    def expires_in(self):
        return self.oauth_expires_in

    @property
    def authorization_url(self):
        query_string = {"oauth_token": self.oauth_token}
        authorization_url = f"{self.authorization_base_url}?{urlencode(query_string)}"
        return (authorization_url, False)

    def fetch_token(self):
        kwargs = {"verifier": request.args["oauth_verifier"]}

        try:
            token = self.oauth_session.fetch_access_token(self.token_url, **kwargs)
        except TokenRequestDenied as e:
            self.error = str(e)
            logger.error(f"Error authenticating: {self.error}", exc_info=True)
        else:
            self.verified = True
            self.token = token

    def save(self):
        cache.set(f"{self.prefix}_oauth_token", self.oauth_token)
        cache.set(f"{self.prefix}_oauth_token_secret", self.oauth_token_secret)
        cache.set(f"{self.prefix}_created_at", self.created_at)
        cache.set(f"{self.prefix}_oauth_expires_at", self.oauth_expires_at)
        cache.set(
            f"{self.prefix}_oauth_authorization_expires_at",
            self.oauth_authorization_expires_at,
        )
        cache.set(f"{self.prefix}_verified", self.verified)

    def restore(self):
        self.oauth_token = cache.get(f"{self.prefix}_oauth_token")
        self.oauth_token_secret = cache.get(f"{self.prefix}_oauth_token_secret")
        self.created_at = cache.get(f"{self.prefix}_created_at")
        self.oauth_expires_at = cache.get(f"{self.prefix}_oauth_expires_at") or dt.now()
        self.oauth_expires_in = (self.oauth_expires_at - dt.now()).total_seconds()

        cached_expires_at = cache.get(f"{self.prefix}_oauth_authorization_expires_at")
        expires_at = cached_expires_at or dt.now()
        self.oauth_authorization_expires_at = expires_at
        self.oauth_authorization_expires_in = (expires_at - dt.now()).total_seconds()

        self.verified = cache.get(f"{self.prefix}_verified")

    def renew_token(self):
        self.oauth_token = None
        self.oauth_token_secret = None
        self.verified = False
        self._init_credentials()


def get_auth_client(prefix, state=None, **kwargs):
    auth_client_name = f"{prefix}_auth_client"

    if auth_client_name not in g:
        oauth_version = kwargs.get(f"{prefix}_OAUTH_VERSION", 2)

        if oauth_version == 1:
            MyAuthClient = MyAuth1Client
            client_id = kwargs[f"{prefix}_CONSUMER_KEY"]
            client_secret = kwargs[f"{prefix}_CONSUMER_SECRET"]

            _auth_kwargs = {
                "request_url": kwargs.get(f"{prefix}_REQUEST_URL"),
                "authorization_base_url": kwargs.get(
                    f"{prefix}_AUTHORIZATION_BASE_URL_V1"
                ),
                "token_url": kwargs.get(f"{prefix}_TOKEN_URL_V1"),
            }
        else:
            MyAuthClient = MyAuth2Client
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
            **_auth_kwargs,
            "oauth_version": oauth_version,
            "api_base_url": kwargs[f"{prefix}_API_BASE_URL"],
            "redirect_uri": kwargs.get(f"{prefix}_REDIRECT_URI"),
            "account_id": kwargs.get(f"{prefix}_ACCOUNT_ID"),
        }

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
            value = item[field]

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


def get_realtime_response(url, client, params=None, **kwargs):
    if client.error:
        response = {"status_code": 500, "message": client.error}
    elif not client.verified:
        response = {"message": "Client not authorized.", "status_code": 401}
    elif client.expired:
        response = {"message": "Token Expired.", "status_code": 401}
    else:
        params = params or {}
        data = kwargs.get("data", {})
        json = kwargs.get("json", {})
        method = kwargs.get("method", "get")
        headers = kwargs.get("headers", HEADERS)
        verb = getattr(client.oauth_session, method)
        result = verb(url, params=params, data=data, json=json, headers=headers)
        logger.debug("%s %s", result.request.method, result.request.url)

        try:
            json = result.json()
        except JSONDecodeError:
            status_code = 401 if result.status_code == 200 else result.status_code

            if "<!DOCTYPE html>" in result.text:
                message = "Got HTML response."
            elif "oauth_problem_advice" in result.text:
                message = parse_qs(result.text)["oauth_problem_advice"][0]
            else:
                message = result.text

            response = {"message": message, "status_code": status_code}
        else:
            if result.ok:
                response = {"result": json}
            else:
                logger.debug(result.request.headers.get("Authorization"))
                # logger.debug(result.request.headers.get("Accept"))
                # logger.debug(result.request.headers.get("Xero-tenant-id"))

                for part in (result.request.body or "").split("&"):
                    logger.debug(part)

                message = json.get("message") or json.get("detail") or json.get("error")
                response = {"status_code": result.status_code, "message": message}

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
    oauth_response = request.args

    state = oauth_response.get("state") or session.get(f"{prefix}_state")
    valid = all(map(oauth_response.get, ["oauth_token", "oauth_verifier", "org"]))
    client = get_auth_client(prefix, **app.config)

    if state or valid:
        client.fetch_token()
        redirect_url = url_for(f".{prefix}_status".lower())
    else:
        redirect_url = url_for(f".{prefix}_auth".lower())

    return redirect_url, client


def callback(prefix):
    redirect_url, client = get_redirect_url(prefix)

    if client.error:
        response = {
            "message": client.error,
            "status_code": 401,
            "links": list(gen_links()),
        }
        return jsonify(**response)
    else:
        return redirect(redirect_url)


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
    return callback("TIMELY")


@blueprint.route(f"{PREFIX}/xero-callback")
def xero_callback():
    return callback("XERO")


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

    if xero.oauth2:
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


@blueprint.route(f"{PREFIX}/xero-contacts")
def contacts():
    xero = get_auth_client("XERO", **app.config)
    api_url = f"{xero.api_base_url}/api.xro/2.0/Contacts"
    response = get_realtime_response(api_url, xero, **app.config)
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
        authorization_url, state = client.authorization_url
        client.state = session[f"{self.prefix}_state"] = state
        client.save()

        # Step 2: User authorization, this happens on the provider.
        if client.verified and not client.expired:
            redirect_url = url_for(f".{self.prefix}_status".lower())
        else:
            if client.oauth1:
                # clear previously cached token
                client.renew_token()
                authorization_url = client.authorization_url[0]

            redirect_url = authorization_url

        logger.info("redirecting to %s", redirect_url)
        return redirect(redirect_url)

    def patch(self):
        client = get_auth_client(self.prefix, **app.config)
        client.renew_token()
        return redirect(url_for(f".{self.prefix}_status".lower()))


class APIBase(MethodView):
    def __init__(self, prefix):
        self.prefix = prefix
        self.lowered = self.prefix.lower()
        self.client = get_auth_client(self.prefix, **app.config)
        self.fields = []
        self.black_list = set()
        self.subkey = ""
        self.params = {}
        self.headers = {}
        self.populate = False
        self.add_day = False

        values = request.values or {}
        json = request.json or {}
        self.values = {**values, **json}
        self.project_pos = int(self.values.get("projectPos", 0))
        self.event_pos = int(self.values.get("eventPos", 0))
        self.error_msg = ""

        project_ids = (p[self.lowered] for p in projects if p.get(self.lowered))
        def_project_id = next(islice(project_ids, self.project_pos, None))
        self.project_id = self.values.get("id", def_project_id)

        if self.prefix == "TIMELY":
            self.api_base_url = f"{self.client.api_base_url}/{self.client.account_id}"
        elif self.prefix == "XERO":
            if self.client.oauth2:
                self.headers = {**HEADERS, "Xero-tenant-id": self.client.tenant_id}

            self.api_base_url = f"{self.client.api_base_url}/projects.xro/2.0"
            self.subkey = "items"

    def get(self):
        process = request.args.get("process", "").lower() == "true"
        dictify = request.args.get("dictify", "").lower() == "true"
        response = get_realtime_response(
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
            mapped = (timely_tasks[str(r)] for r in result if timely_tasks.get(str(r)))
            result = process_result(mapped, self.fields, projectId=self.project_id)
        elif self.fields and process and result:
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

        if dictify and result:
            if self.fields:
                id_field = next(f for f in self.fields if "id" in f.lower())
            else:
                id_field = "id"

            result = ((item.get(id_field), item) for item in result)
            response["result"] = dict(result)
        else:
            response["result"] = list(result or [])

        return jsonify(**response)


class Projects(APIBase):
    def __init__(self, prefix):
        super().__init__(prefix)

        if self.prefix == "TIMELY":
            self.api_url = f"{self.api_base_url}/projects"
            self.fields = ["active", "billable", "id", "name"]
        elif self.prefix == "XERO":
            self.api_url = f"{self.api_base_url}/projects"
            self.fields = ["name", "projectId", "status"]

    def post(self):
        # url = 'http://localhost:5000/v1/xero-projects'
        # data = {
        #     "contactId": "69eab95a-775b-4a30-9bdb-de366253208a",
        #     "name": "Project Name",
        #     "dryRun": True
        # }
        # r = requests.post(url, data=data)
        if self.prefix == "XERO":
            data = self.values
            kwargs = {
                **app.config,
                "headers": self.headers,
                "method": "post",
                "data": data,
            }

            if self.values.get("dryRun", "").lower() == "true":
                response = {"result": data}
            else:
                response = get_realtime_response(self.api_url, self.client, **kwargs)
        else:
            base_url = get_request_base()
            self.error_msg = (
                f"The {request.method}:{base_url} route is not yet enabled."
            )
            response = {"status_code": 404}

        response["links"] = list(gen_links())

        if self.error_msg:
            response["message"] = self.error_msg

        return jsonify(**response)


class Users(APIBase):
    def __init__(self, prefix):
        super().__init__(prefix)

        if self.prefix == "TIMELY":
            self.api_url = f"{self.api_base_url}/users"
            self.fields = ["name", "id"]
        elif self.prefix == "XERO":
            self.api_url = f"{self.api_base_url}/projectsusers"
            self.fields = ["name", "userId"]


class Tasks(APIBase):
    def __init__(self, prefix):
        super().__init__(prefix)

        if self.prefix == "TIMELY":
            if self.values.get("all", "").lower() == "true":
                self.api_url = f"{self.api_base_url}/labels"
                self.fields = ["id", "name"]
            else:
                self.api_url = f"{self.api_base_url}/projects/{self.project_id}"
                self.subkey = "label_ids"
                self.fields = ["id", "name"]
                self.populate = True

        elif self.prefix == "XERO":
            self.api_url = f"{self.api_base_url}/projects/{self.project_id}/tasks"
            self.fields = ["name", "taskId", "status", "rate.value", "projectId"]

    def post(self):
        # url = 'http://localhost:5000/v1/timely-tasks'
        # r = requests.post(url, data={"name": "Test task", "dryRun": True})
        if self.prefix == "TIMELY":
            self.api_url = f"{self.api_base_url}/labels"

            data = dict(self.values)
            dry_run = data.pop("dryRun", "").lower()
            kwargs = {
                **app.config,
                "headers": self.headers,
                "method": "post",
                "json": {"label": data},
            }

            if dry_run == "true":
                response = {"result": {"label": data}}
            else:
                response = get_realtime_response(self.api_url, self.client, **kwargs)
        else:
            base_url = get_request_base()
            self.error_msg = (
                f"The {request.method}:{base_url} route is not yet enabled."
            )
            response = {"status_code": 404}

        response["links"] = list(gen_links())

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

        if self.prefix == "TIMELY":
            self.params = {"since": start, "upto": end}

            if self.values.get("all", "").lower() == "true":
                self.api_url = f"{self.api_base_url}/events"
            else:
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

    def patch(self):
        # url = 'http://localhost:5000/v1/timely-time'
        # r = requests.patch(url, data={"eventId": 165829339, "dryRun": True})
        if self.prefix == "TIMELY":
            sync_results = load(sync_results_p.open())

            if self.values.get("eventId"):
                event_id = str(self.values["eventId"])
                patched = sync_results.get(event_id, {}).get("patched")

                if patched:
                    self.error_msg = f"Event {event_id} already patched!"
                    events = {}
                else:
                    events = timely_events
            else:
                events = {}
                self.error_msg = "No 'projectId' given!"
                logger.error(self.error_msg)

            if events:
                event = events.get(event_id)
            else:
                event = {}

                if not self.error_msg:
                    self.error_msg = "No events found!"
                    logger.error(self.error_msg)

            if patched:
                response = {"status_code": 409}
            elif event:
                self.api_url = f"{self.api_base_url}/events/{event_id}"
                total_minutes = event["duration.total_minutes"]
                billed = event["billed"]

                if billed:
                    self.error_msg = f"Event {event_id} already billed!"
                    response = {"status_code": 409}
                else:
                    data = {
                        "id": event_id,
                        "day": event["day"],
                        "hours": total_minutes // 60,
                        "minutes": total_minutes % 60,
                        "billed": True,
                        "user_id": event["user.id"],
                    }

                    kwargs = {
                        **app.config,
                        "headers": self.headers,
                        "method": "put",
                        "json": {"event": data},
                    }

                    if self.values.get("dryRun", "").lower() == "true":
                        response = {"result": {"event": data}}
                    else:
                        response = get_realtime_response(
                            self.api_url, self.client, **kwargs
                        )
            else:
                if not self.error_msg:
                    self.error_msg = f"Event {event_id} not found!"
                    logger.error(self.error_msg)

                response = {"status_code": 404}

        else:
            base_url = get_request_base()
            self.error_msg = (
                f"The {request.method}:{base_url} route is not yet enabled."
            )
            response = {"status_code": 404}

        response.update(
            {
                "links": list(gen_links()),
                "message": self.error_msg,
                "event_id": event_id,
            }
        )
        return jsonify(**response)

    def post(self):
        # url = 'http://localhost:5000/v1/xero-time'
        # r = requests.post(url, data={"timelyProjectId": 2389295, "dryRun": True})
        if self.prefix == "XERO":
            sync_results = load(sync_results_p.open())
            timely_project_id = int(self.values.get("timelyProjectId", 0))
            eof = False

            if timely_project_id:
                project_id = timely_to_xero["projects"].get(timely_project_id)
                events_p = Path(f"app/data/timely_{timely_project_id}_events.json")

                try:
                    timely_events = load(events_p.open())
                except FileNotFoundError:
                    timely_events = {}
                    self.error_msg = f"{events_p} not found!"
                    logger.error(self.error_msg)
                else:
                    logger.debug(f"{events_p} found!")
            else:
                project_id = None
                timely_events = {}
                self.error_msg = "No 'timelyProjectId' given!"
                logger.error(self.error_msg)

            if timely_events:
                try:
                    event = timely_events[self.event_pos]
                except IndexError:
                    event = {}
                    eof = True

                    if not self.error_msg:
                        self.error_msg = f"Event {self.event_pos} not found!"
                        logger.error(self.error_msg)
                else:
                    logger.debug(f"Event {self.event_pos} found!")
            else:
                event = {}

                if not self.error_msg:
                    self.error_msg = "No events found!"
                    logger.error(self.error_msg)

            if not (project_id or self.error_msg):
                error_data = {"timely": timely_project_id, "xero": "<projectId>"}
                self.error_msg = "No Xero project ID found!"
                self.error_msg += " Add the following to 'mappings.py'\n"
                self.error_msg += f"{dumps(error_data, indent=2)}"
                logger.error(self.error_msg)

            timely_event_id = event.get("id")
            unbilled = not event.get("billed")
            timely_user_id = event.get("user.id")
            added = sync_results.get(str(timely_event_id), {}).get("added")

            if added:
                label_id = 0
                self.error_msg = f"Event {timely_event_id} already added!"
            else:
                try:
                    label_id = int(event.get("label_ids[0]", 0))
                except TypeError:
                    label_id = 0

            if not (label_id or self.error_msg):
                self.error_msg = f"Event {timely_event_id} missing label in {events_p}!"
                logger.error(self.error_msg)

            if event and unbilled:
                user_id = timely_to_xero["users"].get(timely_user_id)
                logger.debug(f"Event {timely_event_id} is unbilled!")
            else:
                user_id = ""

                if not self.error_msg:
                    self.error_msg = f"Event {timely_event_id} is already billed!"
                    logger.error(self.error_msg)

            if user_id:
                key = (timely_project_id, timely_user_id)
                task_id = timely_to_xero["tasks"].get(key, {}).get(label_id, {})
                logger.debug(f"Timely user {timely_user_id} found in Xero mapping!")
            else:
                task_id = ""

                if not self.error_msg:
                    self.error_msg = (
                        f"Timely user {timely_user_id} not found in Xero mapping!"
                    )
                    logger.error(self.error_msg)

            if task_id:
                data = {"userId": user_id, "taskId": task_id}
                logger.debug(f"Timely task {label_id} found in Xero mapping!")
            else:
                data = {}

                if not self.error_msg:
                    user_name = timely_users.get(str(timely_user_id), {}).get(
                        "name", "Unknown"
                    )
                    task_name = (
                        timely_tasks.get(str(label_id), {})
                        .get("name", "Unknown")
                        .split(" ")[0]
                    )
                    project_name = timely_projects.get(str(timely_project_id), {}).get(
                        "name", "Unknown"
                    )

                    self.error_msg = f"Timely->Xero mapping for {user_name}:{task_name} on {project_name} not found!"

                    error_data = {
                        "timely": {
                            "task": label_id,
                            "project": timely_project_id,
                            "users": [timely_user_id],
                        },
                        "xero": {"task": "", "project": project_id},
                    }

                    self.error_msg += f"\n{dumps(error_data, indent=2)}"
                    logger.error(self.error_msg)

            if data:
                day = event["day"]
                date_utc = f"{day}T12:00:00Z"
                duration = event["duration.total_minutes"]

                if len(event["note"]) > 64:
                    description = f"{event['note'][:64]}…"
                else:
                    description = event["note"]

                data.update(
                    {
                        "dateUtc": date_utc,
                        "duration": duration,
                        "description": description,
                    }
                )
                logger.debug("Created data!")
            else:
                day = duration = None

            if project_id and data:
                self.api_url = f"{self.api_base_url}/projects/{project_id}/time"
                xero_trunc_project_id = project_id.split("-")[0]
                events_p = Path(f"app/data/xero_{xero_trunc_project_id}_events.json")

                try:
                    xero_events = load(events_p.open())
                except FileNotFoundError:
                    xero_events = {}
                    self.error_msg = f"{events_p} not found!"
                    logger.error(self.error_msg)
                else:
                    logger.debug(f"{events_p} found!")
            else:
                xero_events = {}

                if not self.error_msg:
                    self.error_msg = "Xero project_id missing!"
                    logger.error(self.error_msg)

            if day and duration:
                key = (day, duration, user_id, task_id)
                truncated_key = (
                    day,
                    duration,
                    user_id.split("-")[0],
                    task_id.split("-")[0],
                )
                fields = ["day", "duration", "userId", "taskId"]
                event_keys = {tuple(xe[f] for f in fields) for xe in xero_events}
                exists = key in event_keys
                logger.debug("Day and duration found!")
            else:
                exists = False

                if not self.error_msg:
                    self.error_msg = "Either day or duration (or both) are empty!"
                    logger.error(self.error_msg)

            if exists or added:
                response = {"result": {}, "status_code": 409}

                if not self.error_msg:
                    self.error_msg = f"Xero time entry {truncated_key} already exists!"
                    logger.error(self.error_msg)
            elif data:
                kwargs = {
                    **app.config,
                    "headers": self.headers,
                    "method": "post",
                    "data": data,
                    "event_id": timely_event_id,
                }

                logger.debug(f"Xero time entry {truncated_key} is available!")

                if self.values.get("dryRun", "").lower() == "true":
                    response = {"result": data}
                else:
                    response = get_realtime_response(
                        self.api_url, self.client, **kwargs
                    )
            else:
                response = {"result": data, "status_code": 400}

                if not self.error_msg:
                    self.error_msg = "No data to add!"
                    logger.error(self.error_msg)

            if not response:
                response = {"result": data, "status_code": 400}
        else:
            base_url = get_request_base()
            self.error_msg = (
                f"The {request.method}:{base_url} route is not yet enabled."
            )
            response = {"status_code": 404}

        response.update(
            {"links": list(gen_links()), "eof": eof, "event_id": timely_event_id}
        )

        if self.error_msg:
            response["message"] = self.error_msg

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

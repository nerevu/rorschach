# -*- coding: utf-8 -*-
"""
    app.api
    ~~~~~~~

    Provides additional api endpoints
"""
from flask import Blueprint, request, redirect, session, url_for, g, current_app as app
from flask import after_this_request
from flask.views import MethodView
from faker import Faker

from config import Config, __APP_TITLE__ as APP_TITLE
from app import cache, __version__
from app.utils import (
    responsify,
    jsonify,
    parse,
    cache_header,
    make_cache_key,
    uncache_header,
)

from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import TokenExpiredError
from riko.dotdict import DotDict

blueprint = Blueprint("API", __name__)
fake = Faker()

ROUTE_TIMEOUT = Config.ROUTE_TIMEOUT
SET_TIMEOUT = Config.SET_TIMEOUT
PREFIX = Config.API_URL_PREFIX
HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}


class MyAuthClient(object):
    def __init__(self, client_id, client_secret, **kwargs):
        self.client_id = client_id
        self.client_secret = client_secret
        self.authorization_base_url = kwargs["authorization_base_url"]
        self.token_url = kwargs["token_url"]
        self.refresh_url = kwargs["refresh_url"]
        self.redirect_uri = kwargs["redirect_uri"]
        self.api_base_url = kwargs["api_base_url"]
        self.account_id = kwargs["account_id"]
        self.extra = {'client_id': self.client_id, 'client_secret': self.client_secret}
        self.error = ''

        if kwargs.get("state"):
            self.state = kwargs["state"]

        self.restore()

        if self.state and self.access_token:
            try:
                self.oauth_session = OAuth2Session(
                    self.client_id,
                    token=self.token,
                    state=self.state,
                    auto_refresh_kwargs=self.extra,
                    auto_refresh_url=self.refresh_url,
                    token_updater=self.update_token,
                )
            except TokenExpiredError:
                # this path shouldn't be reached...
                print("Token expired. Attempting to refresh...")
                self.refresh_token()
            except TypeError as e:
                self.oauth_session = None
                self.error = str(e)
                print(f"Error authenticating: {str(e)}")
            else:
                print("Successfully authenticated!")
        elif self.state:
            self.oauth_session = OAuth2Session(self.client_id, redirect_uri=self.redirect_uri, state=self.state)
        else:
            self.oauth_session = OAuth2Session(self.client_id, redirect_uri=self.redirect_uri)

    def save(self):
        self.state = session.get("state") or self.state
        cache.set("state", self.state, SET_TIMEOUT)
        cache.set("access_token", self.access_token, SET_TIMEOUT)
        cache.set("refreshed_token", self.refreshed_token, SET_TIMEOUT)
        cache.set("expires_in", self.expires_in, SET_TIMEOUT)

    def restore(self):
        self.state = cache.get("state") or session.get("state")
        self.access_token = cache.get("access_token")
        self.refreshed_token = cache.get("refreshed_token")
        self.expires_in = cache.get("expires_in") or SET_TIMEOUT

    @property
    def token(self):
        return {
            "access_token": self.access_token,
            "refresh_token": self.refreshed_token,
            "token_type": "Bearer",
            "expires_in": self.expires_in,
        }

    @token.setter
    def token(self, value):
        self.access_token = value["access_token"]
        self.refreshed_token = value["refresh_token"]
        self.token_type = value["token_type"]
        self.expires_in = value.get("expires_in", SET_TIMEOUT)
        self.created_at = value.get("created_at")
        self.save()

    def get_authorization_url(self):
        return self.oauth_session.authorization_url(self.authorization_base_url)

    def fetch_token(self, **kwargs):
        return self.oauth_session.fetch_token(self.token_url, client_secret=self.client_secret, **kwargs)

    def update_token(self, token):
        self.token = token

    def refresh_token(self):
        try:
            token = self.oauth_session.refresh_token(self.refresh_url, **self.extra)
        except Exception as e:
            print(f"Client authentication error: {str(e)}")
            self.error = str(e)
        else:
            self.token = token
            self.save()

def get_auth_client(state=None, **kwargs):
    if 'auth_client' not in g:
        auth_kwargs = {
            "authorization_base_url": kwargs["TIMELY_AUTHORIZATION_BASE_URL"],
            "token_url": kwargs["TIMELY_TOKEN_URL"],
            "redirect_uri": kwargs["TIMELY_REDIRECT_URI"],
            "refresh_url": kwargs["TIMELY_REFRESH_URL"],
            "api_base_url": kwargs["TIMELY_API_BASE_URL"],
            "account_id": kwargs["TIMELY_ACCOUNT_ID"],
            "state": state,
        }

        client_id = kwargs["TIMELY_CLIENT_ID"]
        client_secret = kwargs["TIMELY_SECRET"]
        g.auth_client = MyAuthClient(client_id, client_secret, **auth_kwargs)

    return g.auth_client


def get_request_base():
    return request.base_url.split("/")[-1].split("?")[0]


def gen_links(**kwargs):
    url_root = request.url_root.rstrip("/")
    prefixed = f"{url_root}{PREFIX}"
    self_link = request.url

    links = [
        {"rel": "home", "href": prefixed, "method": "GET"},
        {"rel": "events", "href": f"{prefixed}/events", "method": "GET"},
        {"rel": "cached_events", "href": f"{prefixed}/cached_events", "method": "GET"},
        {"rel": "authenticate", "href": f"{prefixed}/auth", "method": "GET"},
        {"rel": "refresh", "href": f"{prefixed}/auth", "method": "UPDATE"},
        {"rel": "accounts", "href": f"{prefixed}/accounts", "method": "GET"},
        {"rel": "ipsum", "href": f"{prefixed}/ipsum", "method": "GET"},
        {"rel": "memoize", "href": f"{prefixed}/memoization", "method": "GET"},
        {"rel": "reset", "href": f"{prefixed}/memoization", "method": "DELETE"},
    ]

    for link in links:
        if link["href"] == self_link and link["method"] == request.method:
            link["rel"] = "self"

        yield link


def extract_fields(record, fields):
    item = DotDict(record)

    for field in fields:
        if '[' in field:
            split_field = field.split('[')
            real_field = split_field[0]
            pos = int(split_field[1].split(']')[0])

            try:
                value = item[real_field][pos]
            except IndexError:
                value = None
        else:
            value = item[field]

        yield (field, value)


def process_events(events, fields):
    for event in events:
        if not (event['billed'] or event['deleted']):
            yield dict(extract_fields(event, fields))


def get_realtime_response(url, client, params=None, **kwargs):
    if client.error:
        response = {"status_code": 401, "message": client.error}
    else:
        params = params or {}
        result = client.oauth_session.get(url, params=params, headers=HEADERS)
        response = {"result": result.json()}

        if not result.ok:
            response["status_code"] = result.status_code

    if response.get("status_code", 200) != 200:
        @after_this_request
        def clear_cache(response):
            response = uncache_header(response)
            return response

    response["links"] = list(gen_links())
    return response


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


@blueprint.route(f"{PREFIX}/callback")
def callback():
    """ Step 3: Retrieving an access token.

    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """
    state = session.get("state") or request.args.get("state")

    if state:
        timely = get_auth_client(state=state, **app.config)
        timely.save()

        if request.args.get("code"):
            token = timely.fetch_token(code=request.args["code"])
        else:
            token = timely.fetch_token(authorization_response=request.url)

        timely.token = token
        timely.save()
        return redirect(url_for('.accounts'))
    else:
        return redirect(url_for('.auth'))


@blueprint.route(f"{PREFIX}/accounts")
def accounts():
    timely = get_auth_client(**app.config)
    api_url = f"{timely.api_base_url}/accounts"
    response = get_realtime_response(api_url, timely, **app.config)
    return jsonify(**response)


@blueprint.route(f"{PREFIX}/labels")
def labels():
    timely = get_auth_client(**app.config)
    api_url = f"{timely.api_base_url}/{timely.account_id}/labels"
    response = get_realtime_response(api_url, timely, **app.config)
    return jsonify(**response)


@blueprint.route(f"{PREFIX}/projects")
def projects():
    timely = get_auth_client(**app.config)
    api_url = f"{timely.api_base_url}/{timely.account_id}/projects"
    response = get_realtime_response(api_url, timely, **app.config)
    return jsonify(**response)


@blueprint.route(f"{PREFIX}/users")
def users():
    timely = get_auth_client(**app.config)
    api_url = f"{timely.api_base_url}/{timely.account_id}/users"
    response = get_realtime_response(api_url, timely, **app.config)
    return jsonify(**response)


@blueprint.route(f"{PREFIX}/events")
def events():
    # https://dev.timelyapp.com/#list-all-events
    timely = get_auth_client(**app.config)
    since = request.args.get("since", "2019-09-01")
    upto = request.args.get("upto", "2019-10-01")
    params = {"since": since, "upto": upto}
    api_url = f"{timely.api_base_url}/{timely.account_id}/events"
    response = get_realtime_response(api_url, timely, params=params, **app.config)

    if response.get("status_code", 200) == 200:
        fields = ['id', 'day', 'duration.total_minutes', 'label_ids[0]', 'project.id', 'user.id']
        processed_events = list(process_events(response["result"], fields))
        response["result"] = processed_events

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
    def get(self):
        """Step 1: User Authorization.

        Redirect the user/resource owner to the OAuth provider (i.e. Github)
        using an URL with a few key OAuth parameters.
        """
        timely = get_auth_client(**app.config)
        authorization_url, state = timely.get_authorization_url()

        # https://gist.github.com/ib-lundgren/6507798#gistcomment-1006218
        # State is used to prevent CSRF, keep this for later.
        timely.state = session['state'] = state
        timely.save()

        # Step 2: User authorization, this happens on the provider.
        return redirect(authorization_url)

    def update(self):
        timely = get_auth_client(**app.config)
        timely.refresh_token()
        return redirect(url_for(".accounts"))


class Memoization(MethodView):
    def get(self):
        base_url = get_request_base()
        message = f"The {request.method}:{base_url} route is not yet complete."

        response = {
            "description": "Deletes a cache url",
            "links": list(gen_links()),
            "message": message,
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

add_rule(f"{PREFIX}/auth", view_func=Auth.as_view("auth"))
add_rule(memo_url, view_func=memo_view)
add_rule(memo_path_url, view_func=memo_view, methods=["DELETE"])

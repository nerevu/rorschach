# -*- coding: utf-8 -*-
"""
    app.authclient
    ~~~~~~~~~~~~~~

    Provides OAuth authentication functionality
"""
from datetime import timedelta, datetime as dt
from urllib.parse import urlencode, urlparse, parse_qs, parse_qsl
from itertools import chain
from json import JSONDecodeError
from base64 import b64encode

import pygogo as gogo
import gspread

from flask import (
    request,
    session,
    redirect,
    g,
    current_app as app,
    after_this_request,
    url_for,
)
from oauthlib.oauth2 import TokenExpiredError
from oauth2client.service_account import ServiceAccountCredentials
from requests_oauthlib import OAuth1Session, OAuth2Session
from requests_oauthlib.oauth1_session import TokenRequestDenied

from config import Config
from app import cache
from app.utils import uncache_header, make_cache_key, jsonify, get_links, HEADERS
from app.headless import headless_auth

logger = gogo.Gogo(__name__, monolog=True).logger

SET_TIMEOUT = Config.SET_TIMEOUT
OAUTH_EXPIRY_SECONDS = 3600
EXPIRATION_BUFFER = 30
RENEW_TIME = 60


def _clear_cache():
    cache.delete(make_cache_key())


class AuthClient(object):
    def __init__(self, prefix, client_id, client_secret, **kwargs):
        self.prefix = prefix
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None
        self.refresh_token = None
        self.oauth1 = kwargs["oauth_version"] == 1
        self.oauth2 = kwargs["oauth_version"] == 2
        self.authorization_base_url = kwargs.get("authorization_base_url")
        self.redirect_uri = kwargs.get("redirect_uri")
        self.api_base_url = kwargs.get("api_base_url")
        self.domain = kwargs.get("domain")
        self.token_url = kwargs.get("token_url")
        self.account_id = kwargs.get("account_id")
        self.state = kwargs.get("state")
        self.headers = kwargs.get("headers", {})
        self.auth_params = kwargs.get("auth_params", {})
        self.created_at = None
        self.error = ""

    @property
    def expired(self):
        return self.expires_at <= dt.now() + timedelta(seconds=EXPIRATION_BUFFER)


class MyAuth2Client(AuthClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.refresh_url = kwargs["refresh_url"]
        self.revoke_url = kwargs.get("revoke_url")
        self.scope = kwargs.get("scope", "")
        self.tenant_id = kwargs.get("tenant_id", "")
        self.realm_id = kwargs.get("realm_id")
        self.extra = {"client_id": self.client_id, "client_secret": self.client_secret}
        self.expires_at = dt.now()
        self.expires_in = 0
        self.oauth_session = None
        self.restore()
        self._init_credentials()

    def _init_credentials(self):
        # TODO: check to make sure the token gets renewed on realtime_data call
        # See how it works
        try:
            self.oauth_session = OAuth2Session(self.client_id, **self.oauth_kwargs)
        except TokenExpiredError:
            # this path shouldn't be reached...
            logger.warning(f"{self.prefix} token expired. Attempting to renew...")
            self.renew_token("TokenExpiredError")
        except Exception as e:
            self.error = str(e)
            logger.error(
                f"{self.prefix} error authenticating: {self.error}", exc_info=True
            )
        else:
            if self.verified:
                logger.info(f"{self.prefix} successfully authenticated!")
            else:
                logger.warning(f"{self.prefix} not authorized. Attempting to renew...")
                self.renew_token("init")

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
        self.access_token = value.get("access_token")
        self.refresh_token = value.get("refresh_token")
        self.token_type = value.get("token_type")
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
            self.error = ""

        self.token = token

        return token

    def update_token(self, token):
        self.token = token

    def renew_token(self, source):
        logger.debug(f"renew_token from {source}")
        failed = cache.get(f"{self.prefix}_headless_auth_failed")
        has_username = app.config[f"{self.prefix}_USERNAME"]
        has_password = app.config[f"{self.prefix}_PASSWORD"]
        has_performed_headless_auth = cache.get(f"{self.prefix}_headless_auth")
        failed_or_tried = failed or has_performed_headless_auth

        if self.refresh_token:
            try:
                logger.info(f"Renewing token using {self.refresh_url}…")

                if self.prefix == "XERO":
                    # https://developer.xero.com/documentation/oauth2/auth-flow
                    authorization = f"{self.client_id}:{self.client_secret}"
                    encoded = b64encode(authorization.encode("utf-8")).decode("utf-8")
                    headers = {"Authorization": f"Basic {encoded}"}
                else:
                    headers = {}

                token = self.oauth_session.refresh_token(
                    self.refresh_url, self.refresh_token, headers=headers
                )
            except Exception as e:
                self.error = f"Failed to renew token: {str(e)} Please re-authenticate!"
                logger.error(self.error)
                self.oauth_token = None
                self.access_token = None
                cache.set(f"{self.prefix}_access_token", self.access_token)
                cache.set(f"{self.prefix}_oauth_token", self.oauth_token)
                # logger.debug("", exc_info=True)
            else:
                if self.oauth_session.authorized:
                    logger.info("Successfully renewed token!")
                    self.token = token
                else:
                    self.error = "Failed to renew token!"
                    logger.error(self.error)
        elif has_username and has_password and not failed_or_tried:
            logger.info(f"Attempting to renew using headless browser")
            cache.set(f"{self.prefix}_headless_auth", True)
            headless_auth(self.authorization_url[0], self.prefix)
        else:
            error = f"No {self.prefix} refresh token present. Please re-authenticate!"
            logger.error(error)
            self.error = error

        return self

    def revoke_token(self):
        # TODO: this used to be AuthClientError. What will it be now?
        # https://developer.intuit.com/app/developer/qbo/docs/develop/authentication-and-authorization/oauth-2.0#revoke-token-disconnect
        try:
            response = {
                "status_code": 404,
                "message": "This endpoint is not yet implemented.",
            }
        except Exception:
            message = "Can't revoke authentication rights because the app is"
            message += " not currently authenticated."
            response = {"status_code": 400, "message": message}

        return response

    def save(self):
        try:
            def_state = session.get(f"{self.prefix}_state")
        except RuntimeError:
            def_state = None

        if not self.state:
            self.state = def_state or cache.get(f"{self.prefix}_state")

        cache.set(f"{self.prefix}_state", self.state)
        cache.set(f"{self.prefix}_access_token", self.access_token)
        cache.set(f"{self.prefix}_refresh_token", self.refresh_token)
        cache.set(f"{self.prefix}_created_at", self.created_at)
        cache.set(f"{self.prefix}_expires_at", self.expires_at)
        cache.set(f"{self.prefix}_tenant_id", self.tenant_id)
        cache.set(f"{self.prefix}_realm_id", self.realm_id)

    def restore(self):
        try:
            def_state = session.get(f"{self.prefix}_state")
        except RuntimeError:
            def_state = None

        self.state = def_state or cache.get(f"{self.prefix}_state")
        self.access_token = cache.get(f"{self.prefix}_access_token")
        self.refresh_token = cache.get(f"{self.prefix}_refresh_token")
        self.created_at = cache.get(f"{self.prefix}_created_at")
        self.expires_at = cache.get(f"{self.prefix}_expires_at") or dt.now()
        self.expires_in = (self.expires_at - dt.now()).total_seconds()
        self.tenant_id = cache.get(f"{self.prefix}_tenant_id")
        self.realm_id = cache.get(f"{self.prefix}_realm_id")


class MyAuth1Client(AuthClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
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

    def renew_token(self, source):
        logger.debug(f"renew_token from {source}")
        self.oauth_token = None
        self.oauth_token_secret = None
        self.verified = False
        self._init_credentials()


class MyHeaderAuthClient(AuthClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @property
    def expired(self):
        return False


class MyServiceAuthClient(AuthClient):
    def __init__(self, *args, keyfile_path=None, **kwargs):
        super().__init__(*args, **kwargs)
        p = keyfile_path
        credentials = ServiceAccountCredentials.from_json_keyfile_name(p, self.scope)
        self.gc = gspread.authorize(credentials)

    @property
    def expired(self):
        return False


def get_auth_client(prefix, state=None, **kwargs):
    cache.set(f"{prefix}_headless_auth_failed", False)
    auth_client_name = f"{prefix}_auth_client"

    if auth_client_name not in g:
        oauth_version = kwargs.get(f"{prefix}_OAUTH_VERSION", 2)
        keyfile_path = kwargs.get(f"{prefix}_KEYFILE_PATH")

        if oauth_version == 0:
            MyAuthClient = MyHeaderAuthClient
            client_id = ""
            client_secret = ""
            _auth_kwargs = {}
        elif oauth_version == 1:
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
        elif keyfile_path:
            MyAuthClient = MyServiceAuthClient
            client_id = ""
            client_secret = ""
            _auth_kwargs = {"keyfile_path": keyfile_path}
        else:
            MyAuthClient = MyAuth2Client
            client_id = kwargs[f"{prefix}_CLIENT_ID"]
            client_secret = kwargs[f"{prefix}_SECRET"]

            _auth_kwargs = {
                "authorization_base_url": kwargs[f"{prefix}_AUTHORIZATION_BASE_URL"],
                "token_url": kwargs[f"{prefix}_TOKEN_URL"],
                "refresh_url": kwargs[f"{prefix}_REFRESH_URL"],
                "revoke_url": kwargs.get(f"{prefix}_REVOKE_URL"),
                "scope": kwargs.get(f"{prefix}_SCOPES"),
                "tenant_id": kwargs.get("tenant_id") or "",
                "realm_id": kwargs.get("realm_id") or "",
                "state": state,
            }

        auth_kwargs = {
            **_auth_kwargs,
            "oauth_version": oauth_version,
            "api_base_url": kwargs[f"{prefix}_API_BASE_URL"],
            "redirect_uri": kwargs.get(f"{prefix}_REDIRECT_URI"),
            "domain": kwargs.get(f"{prefix}_API_DOMAIN"),
            "account_id": kwargs.get(f"{prefix}_ACCOUNT_ID"),
            "auth_params": kwargs.get(f"{prefix}_AUTH_PARAMS", {}),
            "headers": kwargs.get(f"{prefix}_HEADERS", {}),
        }

        client = MyAuthClient(prefix, client_id, client_secret, **auth_kwargs)

        # if cache.get(f"{prefix}_restore_from_headless"):
        #     client.restore()
        #     client.renew_token()
        #     cache.set(f"{prefix}_restore_from_headless", False)

        setattr(g, auth_client_name, client)

    client = g.get(auth_client_name)

    if client.expires_in < RENEW_TIME:
        client.renew_token("expired")

    return g.get(auth_client_name)


def get_response(url, client, params=None, **kwargs):
    ok = False
    unscoped = False

    if client.expired:
        response = {"message": "Token Expired.", "status_code": 401}
    elif not client.verified:
        response = {"message": "Client not authorized.", "status_code": 401}
    elif client.error:
        response = {"message": client.error, "status_code": 500}
    else:
        params = params or {}
        data = kwargs.get("data", {})
        json = kwargs.get("json", {})
        method = kwargs.get("method", "get")
        headers = kwargs.get("headers", HEADERS)
        verb = getattr(client.oauth_session, method)
        result = verb(url, params=params, data=data, json=json, headers=headers)
        unscoped = result.headers.get("WWW-Authenticate") == "insufficient_scope"
        ok = result.ok

        try:
            json = result.json()
        except JSONDecodeError:
            status_code = 500 if result.status_code == 200 else result.status_code

            if "404 Not Found" in result.text:
                status_code = 404
                message = f"Endpoint {url} not found!"
            elif "<!DOCTYPE html>" in result.text:
                message = "Got HTML response."
            elif "oauth_problem_advice" in result.text:
                message = parse_qs(result.text)["oauth_problem_advice"][0]
            else:
                message = result.text

            response = {"message": message, "status_code": status_code}
        else:
            try:
                # in case the json result is list
                item = json[0]
            except (AttributeError, KeyError):
                item = json
            except IndexError:
                item = {}

            if item.get("errorcode") or item.get("error"):
                ok = False

            if item.get("fault"):
                # QuickBooks
                ok = False
                fault = item["fault"]

                if fault.get("type") == "AUTHENTICATION":
                    response = {"message": "Client not authorized.", "status_code": 401}
                elif fault.get("error"):
                    error = fault["error"][0]
                    detail = error.get("detail", "")

                    if detail.startswith("Token expired"):
                        response = {"message": "Token Expired.", "status_code": 401}

                    err_message = error["message"]
                    _response = dict(
                        pair.split("=") for pair in err_message.split("; ")
                    )
                    _message = _response["message"]
                    message = f"{_message}: {detail}" if detail else _message
                    response = {
                        "message": message,
                        "status_code": int(_response["statusCode"]),
                    }
                else:
                    response = {"message": fault.get("type"), "status_code": 500}
            elif ok:
                response = {"result": json}
            else:
                message_keys = ["message", "Message", "detail", "error"]

                try:
                    message = next(item[key] for key in message_keys if item.get(key))
                except StopIteration:
                    logger.debug(item)
                    message = ""

                if item.get("modelState"):
                    items = item["modelState"].items()
                    message += " "
                    message += ". ".join(f"{k}: {', '.join(v)}" for k, v in items)
                elif item.get("Elements"):
                    items = chain.from_iterable(e.items() for e in item["Elements"])
                    message += " "
                    message += ". ".join(
                        f"{k}: {', '.join(e['Message'] for e in v)}" for k, v in items
                    )

                status_code = 500 if result.status_code == 200 else result.status_code
                response = {"message": message, "status_code": status_code}

        if not ok:
            header_names = ["Authorization", "Accept", "Content-Type"]

            if client.prefix == "XERO" and client.oauth2:
                header_names.append("Xero-tenant-id")

            for name in header_names:
                logger.debug({name: result.request.headers.get(name, "")[:32]})

            body = result.request.body or ""

            try:
                parsed = parse_qs(body)
            except UnicodeEncodeError:
                decoded = body.decode("utf-8")
                parsed = parse_qs(decoded)

            if parsed:
                logger.debug({k: v[0] for k, v in parsed.items()})

    status_code = response.get("status_code", 200)
    response["ok"] = ok

    if not ok:
        try:

            @after_this_request
            def clear_cache(response):
                _clear_cache()
                response = uncache_header(response)
                return response

        except AttributeError:
            pass

    if status_code == 401 and not kwargs.get("renewed"):
        if unscoped:
            logger.debug(f"Insufficient scope: {client.scope}.")
        else:
            logger.debug("Token expired!")

        client.renew_token(401)
        response = get_response(url, client, params=params, renewed=True, **kwargs)
    else:
        try:
            response["links"] = get_links(app.url_map.iter_rules())
        except RuntimeError:
            pass


    return response


def get_redirect_url(prefix):
    """ Step 3: Retrieving an access token.

    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """
    query = urlparse(request.url).query
    response = dict(parse_qsl(query), **request.args)
    state = response.get("state") or session.get(f"{prefix}_state")
    realm_id = response.get("realm_id") or session.get(f"{prefix}_realm_id")
    valid = all(map(response.get, ["oauth_token", "oauth_verifier", "org"]))
    client = get_auth_client(prefix, state=state, realm_id=realm_id, **app.config)

    if state or valid:
        session[f"{prefix}_state"] = client.state
        session[f"{prefix}_realm_id"] = client.realm_id
        client.fetch_token()

    redirect_url = cache.get(f"{prefix}_callback_url")

    if redirect_url:
        cache.delete(f"{prefix}_callback_url")
    else:
        redirect_url = url_for(f".{prefix}-auth".lower())

    if prefix == "XERO" and client.oauth2:
        api_url = f"{client.api_base_url}/connections"
        response = get_response(api_url, client, **app.config)
        # https://developer.xero.com/documentation/oauth2/auth-flow
        result = response.get("result")
        tenant_id = result[0].get("tenantId") if result else None

        if tenant_id:
            client.tenant_id = tenant_id
            client.save()
            logger.debug(f"Set Xero tenantId to {client.tenant_id}.")
        else:
            client.error = response.get("message", "No tenantId found.")

    return redirect_url, client


def callback(prefix):
    redirect_url, client = get_redirect_url(prefix)

    if client.error:
        response = {
            "message": client.error,
            "status_code": 401,
            "links": get_links(app.url_map.iter_rules()),
        }
        return jsonify(**response)
    else:
        return redirect(redirect_url)

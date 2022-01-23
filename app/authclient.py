# -*- coding: utf-8 -*-
"""
    app.authclient
    ~~~~~~~~~~~~~~

    Provides OAuth authentication functionality
"""
from datetime import datetime as dt, timedelta, timezone
from functools import partial
from itertools import chain
from json import JSONDecodeError, load
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.parse import parse_qs, parse_qsl, urlencode, urlparse

import boto3
import pygogo as gogo
import requests

from botocore.exceptions import ProfileNotFound
from flask import (
    after_this_request,
    current_app as app,
    g,
    has_app_context,
    redirect,
    request,
    session,
    url_for,
)
from google.auth.transport.requests import Request
from google.oauth2.service_account import Credentials
from oauthlib.oauth2 import TokenExpiredError
from requests_oauthlib import OAuth1Session, OAuth2Session
from requests_oauthlib.oauth1_session import TokenRequestDenied

from app import cache
from app.headless import headless_auth
from app.helpers import flask_formatter as formatter, toposort
from app.utils import get_links, jsonify, make_cache_key, uncache_header
from config import Config

logger = gogo.Gogo(
    __name__, low_formatter=formatter, high_formatter=formatter, monolog=True
).logger
logger.propagate = False

SET_TIMEOUT = Config.SET_TIMEOUT
OAUTH_EXPIRY_SECONDS = 3600
EXPIRATION_BUFFER = 30
RENEW_TIME = 60
HEADERS = {"Accept": "application/json"}


def _clear_cache():
    cache.delete(make_cache_key())


class BaseClient(object):
    def __init__(self, prefix, client_id=None, client_secret=None, **kwargs):
        self.prefix = prefix
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth = None
        self.oauth_version = kwargs.get("oauth_version")
        self.oauth1 = self.oauth_version == 1
        self.oauth2 = self.oauth_version == 2
        self.api_base_url = kwargs.get("api_base_url", "")
        self.debug = kwargs.get("debug")
        self.username = kwargs.get("username")
        self.password = kwargs.get("password")
        self.headers = kwargs.get("headers", {})
        self.created_at = None
        self.error = ""

    def __repr__(self):
        return f"{self.prefix} {self.auth_type}"


class AuthClient(BaseClient):
    def __init__(self, prefix=None, **kwargs):
        super().__init__(prefix, **kwargs)
        self.auth_type = "custom"
        self.verified = True
        self.expired = False


class OAuth2BaseClient(BaseClient):
    def __init__(
        self, prefix=None, refresh_url=None, **kwargs,
    ):
        super().__init__(prefix, **kwargs)
        self.scope = kwargs.get("scope", "")
        self.state = kwargs.get("state")
        self.access_token = None
        self.refresh_token = None
        self.realm_id = kwargs.get("realm_id")
        self.tenant_id = kwargs.get("tenant_id")
        self.expires_at = dt.now(timezone.utc)
        self.expires_in = 0

    @property
    def expired(self):
        return self.expires_at <= dt.now(timezone.utc) + timedelta(
            seconds=EXPIRATION_BUFFER
        )

    @property
    def token(self):
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_type": self.token_type,
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
        self.created_at = value.get("created_at") or dt.now(timezone.utc)

        try:
            self.created_at.timestamp
        except AttributeError:
            self.created_at = dt.fromtimestamp(self.created_at, timezone.utc)

        if value.get("expires_in"):
            self.expires_in = value["expires_in"]
            self.expires_at = self.created_at + timedelta(seconds=self.expires_in)
        else:
            def_expires_at = self.created_at + timedelta(seconds=SET_TIMEOUT)
            self.expires_at = value.get("expires_at") or def_expires_at

            try:
                self.expires_at.timestamp
            except AttributeError:
                self.expires_at = dt.fromtimestamp(self.expires_at, timezone.utc)

            self.expires_in = (
                self.expires_at.replace(tzinfo=timezone.utc) - dt.now(timezone.utc)
            ).total_seconds()

        self.save()

        if self.debug:
            logger.debug(self.token)

    def save(self):
        logger.debug(f"saving {self}")

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
        cache.set(f"{self.prefix}_realm_id", self.realm_id)
        cache.set(f"{self.prefix}_tenant_id", self.tenant_id)

    def restore(self):
        logger.debug(f"restoring {self}")

        try:
            def_state = session.get(f"{self.prefix}_state")
        except RuntimeError:
            def_state = None

        seconds = int(OAUTH_EXPIRY_SECONDS)
        def_expires_at = dt.now(timezone.utc) + timedelta(seconds=seconds)

        self.state = def_state or cache.get(f"{self.prefix}_state")
        self.access_token = cache.get(f"{self.prefix}_access_token")
        self.refresh_token = cache.get(f"{self.prefix}_refresh_token")
        self.created_at = cache.get(f"{self.prefix}_created_at")
        self.expires_at = cache.get(f"{self.prefix}_expires_at") or def_expires_at
        self.expires_in = (self.expires_at - dt.now(timezone.utc)).total_seconds()
        self.realm_id = cache.get(f"{self.prefix}_realm_id")
        self.tenant_id = cache.get(f"{self.prefix}_tenant_id")


class OAuth2Client(OAuth2BaseClient):
    def __init__(
        self, prefix=None, refresh_url=None, **kwargs,
    ):
        super().__init__(prefix, **kwargs)
        self.auth_type = "oauth2"
        self.token_type = "Bearer"
        self.refresh_url = refresh_url
        self.oauth_session = None

        self.authorization_base_url = kwargs.get("authorization_base_url")
        self.revoke_url = kwargs.get("revoke_url")
        self.redirect_uri = kwargs.get("redirect_uri")
        self.token_url = kwargs.get("token_url")
        self.account_id = kwargs.get("account_id")
        self.extra = {"client_id": self.client_id, "client_secret": self.client_secret}
        self.username = kwargs.get("username")
        self.password = kwargs.get("password")
        self.headless = kwargs.get("headless", False)
        self.headless_elements = kwargs.get("headless_elements") or []
        self.debug = kwargs.get("debug")
        self.tried_headless_auth = False
        self.failed_headless_auth = False
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
    def failed_or_tried_headless(self):
        return self.failed_headless_auth or self.tried_headless_auth

    @property
    def headless_status(self):
        return "failed" if self.failed_headless_auth else "succeeded"

    @property
    def restore_from_headless(self):
        return self.tried_headless_auth and not self.failed_headless_auth

    @property
    def can_headlessly_auth(self):
        auth_info = self.username and self.password and self.headless_elements
        return auth_info and self.headless and not self.failed_or_tried_headless

    @property
    def headless_kwargs(self):
        return {
            "username": self.username,
            "password": self.password,
            "elements": self.headless_elements,
            "debug": self.debug,
        }

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
        logger.debug(f"renew {self} from {source}")

        if self.refresh_token and self.refresh_url:
            logger.info(f"Renewing token using {self.refresh_url}…")
            args = (self.refresh_url, self.refresh_token)

            if self.client_id and self.client_secret:
                auth = (self.client_id, self.client_secret)
            else:
                auth = None

            try:
                token = self.oauth_session.refresh_token(*args, auth=auth)
            except Exception as e:
                self.error = f"Failed to renew {self}: {str(e)} Please re-authenticate!"
                logger.error(self.error)
                self.oauth_token = None
                self.access_token = None
                cache.set(f"{self.prefix}_access_token", self.access_token)
                cache.set(f"{self.prefix}_oauth_token", self.oauth_token)
            else:
                if self.oauth_session.authorized:
                    logger.info(f"Successfully renewed {self}!")
                    self.token = token
                else:
                    self.error = f"Failed to renew {self}!"
                    logger.error(self.error)
        elif self.refresh_token:
            logger.error("No refresh_url provided!")
        elif self.can_headlessly_auth:
            logger.info(f"Attempting to renew {self} using headless authentication")
            url = self.authorization_url[0]
            self.failed_headless_auth = headless_auth(
                url, self.prefix, **self.headless_kwargs
            )
            self.tried_headless_auth = True
        else:
            error = f"No {self.prefix} refresh token present. Please re-authenticate!"

            if self.tried_headless_auth:
                error += (
                    f" Previous headless authentication attempt {self.headless_status}."
                )

            logger.error(error)
            self.error = error

        return self

    def revoke_token(self):
        # https://developer.intuit.com/app/developer/qbo/docs/develop/authentication-and-authorization/oauth-2.0#revoke-token-disconnect
        if self.revoke_url and self.verified:
            json = get_json_response(self.revoke_url, self.client)
        elif self.verified:
            json = {
                "status_code": 404,
                "message": "This endpoint is not yet implemented.",
            }
        else:
            message = "Can't revoke authentication rights because the app is"
            message += " not currently authenticated."
            json = {"status_code": 400, "message": message}

        return json


class OAuth1Client(AuthClient):
    def __init__(self, prefix=None, **kwargs):
        super().__init__(prefix, **kwargs)
        self.auth_type = "oauth1"
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
    def expired(self):
        return self.expires_at <= dt.now(timezone.utc) + timedelta(
            seconds=EXPIRATION_BUFFER
        )

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

        self.created_at = token.get("created_at", dt.now(timezone.utc))
        self.oauth_expires_at = dt.now(timezone.utc) + timedelta(
            seconds=int(oauth_expires_in)
        )

        seconds = timedelta(seconds=int(oauth_authorisation_expires_in))
        self.oauth_authorization_expires_at = dt.now(timezone.utc) + seconds

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

        return token

    def save(self):
        logger.debug(f"saving {self}")
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
        logger.debug(f"restoring {self}")
        def_expires_at = dt.now(timezone.utc) + timedelta(
            seconds=int(OAUTH_EXPIRY_SECONDS)
        )

        self.oauth_token = cache.get(f"{self.prefix}_oauth_token")
        self.oauth_token_secret = cache.get(f"{self.prefix}_oauth_token_secret")
        self.created_at = cache.get(f"{self.prefix}_created_at")
        self.oauth_expires_at = (
            cache.get(f"{self.prefix}_oauth_expires_at") or def_expires_at
        )
        self.oauth_expires_in = (
            self.oauth_expires_at - dt.now(timezone.utc)
        ).total_seconds()

        cached_expires_at = cache.get(f"{self.prefix}_oauth_authorization_expires_at")
        expires_at = cached_expires_at or def_expires_at
        self.oauth_authorization_expires_at = expires_at
        self.oauth_authorization_expires_in = (
            expires_at - dt.now(timezone.utc)
        ).total_seconds()

        self.verified = cache.get(f"{self.prefix}_verified")

    def renew_token(self, source):
        logger.debug(f"renew {self} from {source}")
        self.oauth_token = None
        self.oauth_token_secret = None
        self.verified = False
        self._init_credentials()


class BasicAuthClient(AuthClient):
    def __init__(self, prefix=None, username=None, password=None, **kwargs):
        super().__init__(prefix, **kwargs)
        self.auth_type = "basic"
        self.auth = (username, password)


class BearerAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers["authorization"] = f"Bearer {self.token}"
        return r


class BearerAuthClient(AuthClient):
    def __init__(self, prefix=None, token=None, **kwargs):
        super().__init__(prefix, **kwargs)
        self.auth_type = "bearer"
        self.auth = BearerAuth(token)


class BotoAuthClient(AuthClient):
    def __init__(self, prefix=None, profile_name=None, **kwargs):
        super().__init__(prefix, **kwargs)
        self.auth_type = "boto"
        self.profile_name = profile_name
        self.aws_access_key_id = kwargs.get("aws_access_key_id")
        self.aws_secret_access_key = kwargs.get("aws_secret_access_key")
        self.region_name = kwargs.get("region_name")
        self._session = None
        self._init_credentials()

    @property
    def kwargs(self):
        return {
            "aws_access_key_id": self.aws_access_key_id,
            "aws_secret_access_key": self.aws_secret_access_key,
            "region_name": self.region_name,
        }

    @property
    def session(self):
        if not self._session:
            try:
                _session = boto3.Session(profile_name=self.profile_name)
            except ProfileNotFound:
                _session = boto3.Session(**self.kwargs)
                logger.debug("Loaded session from config.")
            else:
                logger.debug(f"Loaded session from profile {self.profile_name}.")

            self._session = _session

        return self._session

    def _init_credentials(self):
        self.session


class ServiceAuthClient(OAuth2BaseClient):
    def __init__(self, prefix=None, keyfile_path=None, **kwargs):
        super().__init__(prefix, **kwargs)
        self._info = None
        self._credentials = None
        self.auth_type = "service"
        self.token_type = "service"
        self.private_key = None
        self.auth_provider_x509_cert_url = None
        self.client_x509_cert_url = None
        self.project_id = None
        self.client_email = None
        self.token_uri = None
        self.keyfile_path = keyfile_path
        self.restore()
        self._init_credentials()

    def save(self):
        super().save()
        cache.set(f"{self.prefix}_scopes", self.credentials.scopes)
        cache.set(f"{self.prefix}_project_id", self.credentials.project_id)
        cache.set(f"{self.prefix}_client_email", self.credentials.service_account_email)
        cache.set(f"{self.prefix}_token_uri", self.credentials._token_uri)
        cache.set(f"{self.prefix}_private_key", self.private_key)

    def restore(self):
        super().restore()
        self.project_id = cache.get(f"{self.prefix}_project_id")
        self.client_email = cache.get(f"{self.prefix}_client_email")
        self.token_uri = cache.get(f"{self.prefix}_token_uri")
        self.private_key = cache.get(f"{self.prefix}_private_key")
        self.scope = cache.get(f"{self.prefix}_scopes") or self.scope

    def _init_credentials(self):
        if not self.credentials:
            p = Path(self.keyfile_path)
            logger.debug(f"Loading {self.prefix} keyfile from {p}...")

            with p.open() as f:
                self._info = load(f)
                self.private_key = self._info["private_key"]

        if self.expired:
            logger.warning(f"{self.prefix} token expired. Attempting to renew...")
            self.renew_token("TokenExpiredError")
        elif self.verified:
            logger.info(f"{self.prefix} successfully authenticated!")
        else:
            logger.warning(f"{self.prefix} not authorized. Attempting to renew...")
            self.renew_token("init")

    @property
    def info(self):
        if not self._info:
            self._info = {
                "private_key": self.private_key,
                "project_id": self.project_id,
                "client_email": self.client_email,
                "token_uri": self.token_uri,
            }

        return self._info

    @property
    def credentials(self):
        if not self._credentials:
            try:
                self._credentials = Credentials.from_service_account_info(
                    self.info, scopes=self.scope
                )
            except Exception as e:
                logger.warning(f"{self.prefix} info invalid: {e}.")

        return self._credentials

    @property
    def verified(self):
        return self.credentials.valid

    @property
    def _token(self):
        return {
            "access_token": self.credentials.token,
            "expires_at": self.credentials.expiry.replace(tzinfo=timezone.utc),
        }

    def fetch_token(self):
        self.token = self._token
        return self._token

    def renew_token(self, source):
        logger.debug(f"renew {self} from {source}")
        logger.info("Renewing token using credentials refresh…")
        self.credentials.refresh(Request())

        if self.verified:
            self.token = self._token
        else:
            logger.info("Failed to renew, re-authenticating…")
            self.fetch_token()

            if self.verified:
                logger.info(f"Successfully renewed {self}!")
                self.token = self._token
            else:
                self.error = f"Failed to renew {self}: Please re-authenticate!"
                logger.error(self.error)

        return self


def get_auth(prefix, auth_key=None, **kwargs):
    authentication = kwargs["AUTHENTICATION"].get(prefix.lower(), {})

    if auth_key:
        auth_kwargs = authentication[auth_key]
    else:
        for auth_key, auth_kwargs in toposort(**authentication):
            if auth_kwargs.get("default"):
                break

    if auth_kwargs.get("parent"):
        auth_kwargs = {**authentication[auth_kwargs["parent"]], **auth_kwargs}

    return (auth_key, auth_kwargs)


def get_auth_client(prefix, state=None, API_URL="", **kwargs):
    auth_key, auth_kwargs = get_auth(prefix, **kwargs)
    auth_client_name = f"{prefix}_{auth_key}_auth_client"

    if auth_client_name not in g:
        available_auths = {
            "oauth1": {"oauth_version": 1, "auth_client": OAuth1Client},
            "oauth2": {"oauth_version": 2, "auth_client": OAuth2Client, "state": state},
            "service": {"auth_client": ServiceAuthClient},
            "bearer": {"auth_client": BearerAuthClient},
            "boto": {"auth_client": BotoAuthClient},
            "basic": {"auth_client": BasicAuthClient},
            "custom": {"auth_client": AuthClient},
        }

        auth_type = auth_kwargs["auth_type"]
        extra_auth_kwargs = available_auths[auth_type]
        MyAuthClient = extra_auth_kwargs.pop("auth_client")
        auth_kwargs.update(extra_auth_kwargs)
        redirect_uri = auth_kwargs.get("redirect_uri") or ""

        if redirect_uri.startswith("/") and API_URL:
            auth_kwargs["redirect_uri"] = f"{API_URL}{redirect_uri}"

        if "debug" in kwargs:
            auth_kwargs["debug"] = kwargs["debug"]

        if "headless" in kwargs:
            auth_kwargs["headless"] = kwargs["headless"]

        client = MyAuthClient(prefix, **auth_kwargs)
        client.attrs = auth_kwargs.get("attrs", {})
        client.params = auth_kwargs.get("params", {})
        client.param_map = auth_kwargs.get("param_map", {})
        client.verb_map = auth_kwargs.get("verb_map", {})
        client.method_map = auth_kwargs.get("method_map", {})
        client.tenant_path = auth_kwargs.get("tenant_path")
        client.api_ext = auth_kwargs.get("api_ext")
        client.rid_last = auth_kwargs.get("rid_last")

        try:
            restore_from_headless = client.restore_from_headless
        except AttributeError:
            restore_from_headless = False

        if restore_from_headless:
            logger.debug("restoring client from headless session")
            client.restore()
            client.renew_token("headless")

        setattr(g, auth_client_name, client)

    client = g.get(auth_client_name)

    if client.oauth_version == 2 and client.expires_in < RENEW_TIME:
        client.renew_token("expired")

    return client


def get_quickbooks_error(**kwargs):
    fault = kwargs["fault"]

    if fault.get("type") == "AUTHENTICATION":
        json = {"message": "Client not authorized.", "status_code": 401}
    elif fault.get("error"):
        error = fault["error"][0]
        detail = error.get("detail", "")

        if detail.startswith("Token expired"):
            json = {"message": "Token Expired.", "status_code": 401}

        err_message = error["message"]
        _json = dict(pair.split("=") for pair in err_message.split("; "))
        _message = _json["message"]
        message = f"{_message}: {detail}" if detail else _message
        json = {
            "message": message,
            "status_code": int(_json["statusCode"]),
        }
    else:
        json = {"message": fault.get("type"), "status_code": 500}

    return json


def get_other_errors(result, **kwargs):
    message_keys = ["message", "Message", "detail", "error"]

    try:
        message = next(kwargs[key] for key in message_keys if kwargs.get(key))
    except StopIteration:
        logger.debug(kwargs)
        message = ""

    if kwargs.get("modelState"):
        items = kwargs["modelState"].items()
        message += " "
        message += ". ".join(f"{k}: {', '.join(v)}" for k, v in items)
    elif kwargs.get("Elements"):
        items = chain.from_iterable(e.items() for e in kwargs["Elements"])
        message += " "
        message += ". ".join(
            f"{k}: {', '.join(e['Message'] for e in v)}" for k, v in items
        )

    if 200 <= result.status_code < 300:
        status_code = 500
    else:
        status_code = result.status_code

    return {"message": message, "status_code": status_code}


def get_json_error(url, result):
    content_type = result.headers.get("Content-Type", "")
    is_json = content_type.endswith("json")
    is_file = content_type.endswith("pdf")

    if is_json and 200 <= result.status_code < 300:
        status_code = 500
    else:
        status_code = result.status_code

    if "404 Not Found" in result.text:
        status_code = 404
        message = f"Endpoint {url} not found!"
    elif "Bad Request" in result.text:
        message = "Bad Request."
    elif "<!DOCTYPE html>" in result.text:
        message = "Got HTML response."
    elif "oauth_problem_advice" in result.text:
        message = parse_qs(result.text)["oauth_problem_advice"][0]
    elif is_file:
        f = NamedTemporaryFile(delete=False)
        f.write(result.content)
        message = f"saved file to {f.name}"
    else:
        message = result.text

    json = {"message": message, "status_code": status_code}

    if is_file:
        json["result"] = {f.name}

    return json


def debug_header(result):
    logger.debug({k: v[:32] for k, v in result.request.headers.items()})
    body = result.request.body or ""

    try:
        parsed = parse_qs(body)
    except UnicodeEncodeError:
        decoded = body.decode("utf-8")
        parsed = parse_qs(decoded)

    if parsed:
        logger.debug({k: v[0] for k, v in parsed.items()})


def debug_json(url, method="get", status_code=200, **kwargs):
    try:

        @after_this_request
        def clear_cache(response):
            _clear_cache()
            return uncache_header(response)

    except AttributeError:
        pass

    message = kwargs.get("message", "")

    if url:
        logger.error(f"Error {method}ing {url}!")

    logger.error(f"Server returned {status_code}: {message}")


def debug_status(client, unscoped=False, status_code=200, **kwargs):
    if unscoped:
        message = f"Insufficient scope: {client.scope}."
    elif status_code == 401:
        message = kwargs.get("message", "Token expired!")
    else:
        message = kwargs.get("message", "")

    logger.debug(message)


def is_ok(success_code=200, **kwargs):
    status_code = kwargs.get("status_code", success_code)
    ok = 200 <= status_code < 300
    return (status_code, ok)


def get_result(url, client, params=None, method="get", **kwargs):
    params = params or {}
    data = kwargs.get("data", {})
    json_data = kwargs.get("json", {})
    def_headers = kwargs.get("headers", {})
    all_headers = client.headers.get("all", {})
    method_headers = client.headers.get(method, {})
    __headers = {**all_headers, **method_headers}
    _headers = {k: v.format(**client.__dict__) for k, v in __headers.items()}
    headers = {**HEADERS, **_headers, **def_headers}

    try:
        requestor = client.oauth_session
    except AttributeError:
        requestor = requests

    verb = getattr(requestor, method)

    try:
        verb = partial(verb, auth=client.auth)
    except AttributeError:
        pass

    return verb(url, params=params, data=data, json=json_data, headers=headers)


def get_errors(result, _json):
    ok = result.ok

    try:
        # in case the json result is list
        item = _json[0]
    except (AttributeError, KeyError):
        item = _json
    except IndexError:
        item = {}

    if item.get("errorcode") or item.get("error") or item.get("fault"):
        ok = False

    if item.get("fault"):
        json = get_quickbooks_error(**item)
    elif ok:
        json = {"result": _json}
    else:
        json = get_other_errors(result, **item)

    return json


def get_json(url, client, params=None, method="get", success_code=200, **kwargs):
    try:
        result = get_result(url, client, params=params, method=method, **kwargs)
    except TokenExpiredError:
        unscoped = False
        result = None
        json = {"message": "Token Expired", "status_code": 401}
    else:
        unscoped = result.headers.get("WWW-Authenticate") == "insufficient_scope"

        try:
            json = result.json()
        except AttributeError:
            json = {"message": result.text, "status_code": result.status_code}
        except JSONDecodeError:
            json = get_json_error(url, result)
        else:
            json = get_errors(result, json)

    status_code, ok = is_ok(success_code, **json)

    if (result is not None) and (not ok) and kwargs.get("debug"):
        debug_header(result)

    return (json, unscoped)


def get_json_response(url, client, params=None, renewed=False, **kwargs):
    unscoped = False
    success_code = kwargs.get("success_code", 200)
    method = kwargs.get("method", "get")

    if not client:
        json = {"message": "No client.", "status_code": 407}
    elif client.expired:
        json = {"message": "Token Expired.", "status_code": 401}
    elif not client.verified:
        json = {"message": "Client not authorized.", "status_code": 401}
    elif client.error:
        json = {"message": client.error, "status_code": 500}
    elif url:
        json, unscoped = get_json(
            url,
            client,
            params=params,
            method=method,
            success_code=success_code,
            **kwargs,
        )
    else:
        json = client.json

    status_code, ok = is_ok(success_code, **json)
    json["ok"] = ok

    if status_code in {400, 401} and not renewed:
        debug_status(client, unscoped, **json)

        try:
            client.renew_token(status_code)
        except AttributeError:
            pass
        else:
            json = get_json_response(url, client, params=params, renewed=True, **kwargs)
    elif ok and has_app_context():
        json["links"] = get_links(app.url_map.iter_rules())
    else:
        debug_json(url, method=method, **json)

    return json


def get_redirect_url(prefix):
    """Step 3: Retrieving an access token.

    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """
    query = urlparse(request.url).query
    json = dict(parse_qsl(query), **request.args)
    state = json.get("state") or session.get(f"{prefix}_state")
    realm_id = json.get("realm_id") or session.get(f"{prefix}_realm_id")
    valid = state or all(map(json.get, ["oauth_token", "oauth_verifier", "org"]))
    client = get_auth_client(prefix, state=state, realm_id=realm_id, **app.config)

    if valid:
        session[f"{prefix}_state"] = client.state
        session[f"{prefix}_realm_id"] = client.realm_id
        client.fetch_token()
    else:
        client.error = json.get("message", "Invalid access token!")

    redirect_url = cache.get(f"{prefix}_callback_url")

    if redirect_url:
        cache.delete(f"{prefix}_callback_url")
    else:
        redirect_url = url_for(f".{prefix}-auth".lower())

    return redirect_url, client


def callback(prefix):
    redirect_url, client = get_redirect_url(prefix)

    if client.error:
        json = {
            "message": client.error,
            "status_code": 401,
            "links": get_links(app.url_map.iter_rules()),
        }
        return jsonify(**json)
    else:
        return redirect(redirect_url)

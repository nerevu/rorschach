# -*- coding: utf-8 -*-
""" app.routes
~~~~~~~~~~~~~~
Provides common routes.

"""
import pygogo as gogo

from attr import dataclass, field
from faker import Faker
from flask import current_app as app, request
from flask.views import MethodView, View

from app import cache
from app.helpers import flask_formatter as formatter
from app.utils import (
    cache_header,
    gen_config,
    get_links,
    get_request_base,
    jsonify,
    make_cache_key,
    parse_request,
)
from config import Config

fake = Faker()
logger = gogo.Gogo(
    __name__, low_formatter=formatter, high_formatter=formatter, monolog=True
).logger
logger.propagate = False

PREFIX = Config.API_URL_PREFIX
ROUTE_TIMEOUT = Config.ROUTE_TIMEOUT


@dataclass
class PatchedMethodView(MethodView):
    prefix: str
    lowered: str = field(init=False, repr=False)
    path: str = field(init=False, repr=False)
    _kwargs: dict = field(init=False, factory=dict, repr=False)

    def dispatch_request(self, *args, **kwargs):
        return MethodView.dispatch_request(self, *args, **kwargs)

    def __attrs_post_init__(self):
        lowered_class = type(self).__name__.lower()

        if self.prefix:
            self.lowered = self.prefix.lower()
            self.path = f"{PREFIX}/{self.lowered}-{lowered_class}"
        else:
            self.lowered = None
            self.path = f"{PREFIX}/{lowered_class}"

        self._kwargs = None

    @property
    def kwargs(self):
        if self._kwargs is None:
            try:
                if self.path == request.path:
                    self._kwargs = parse_request(app)
                else:
                    self._kwargs = {}
                    logger.debug(
                        f"path:{self.path} doesn't match request:{request.path}"
                    )
            except RuntimeError:
                self._kwargs = {}

            self._kwargs.update(dict(gen_config(app)))

        return self._kwargs


class ProviderMixin:
    def __init__(self, prefix, **kwargs):
        self.prefix = prefix or ""
        self.lowered = self.prefix.lower()

        lowered_class = type(self).__name__.lower()

        if self.prefix:
            self.path = f"{PREFIX}/{self.lowered}-{lowered_class}"
        else:
            self.path = f"{PREFIX}/{lowered_class}"

        self._values = None
        self._kwargs = None

    @property
    def values(self):
        if self._values is None:
            try:
                if self.path == request.path:
                    self._values = parse_request()
                else:
                    self._values = {}
                    logger.debug(
                        f"path:{self.path} doesn't match request:{request.path}"
                    )
            except RuntimeError:
                self._values = {}

        return self._values

    @property
    def kwargs(self):
        if self._kwargs is None:
            try:
                if self.path == request.path:
                    self._kwargs = parse_kwargs(app)
                else:
                    self._kwargs = {}
                    logger.debug(
                        f"path:{self.path} doesn't match request:{request.path}"
                    )
            except RuntimeError:
                self._kwargs = {}

            self._kwargs.update(dict(gen_config(app)))

        return self._kwargs


class Memoization(PatchedMethodView):
    def get(self):
        base_url = get_request_base()

        json = {
            "description": "Deletes a cache url",
            "links": get_links(app.url_map.iter_rules()),
            "message": f"The {request.method}:{base_url} route is not yet complete.",
        }

        return jsonify(**json)

    def delete(self, path=None):
        if path:
            url = f"{PREFIX}/{path}"
            cache.delete(url)
            message = f"Deleted cache for {url}"
        else:
            cache.clear()
            message = "Caches cleared!"

        json = {"links": get_links(app.url_map.iter_rules()), "message": message}
        return jsonify(**json)


@cache_header(ROUTE_TIMEOUT, key_prefix=make_cache_key)
def ipsum():
    json = {
        "description": "Displays a random sentence",
        "links": get_links(app.url_map.iter_rules()),
        "result": fake.sentence(),
    }

    return jsonify(**json)

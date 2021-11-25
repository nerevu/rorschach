# -*- coding: utf-8 -*-
""" app.routes
~~~~~~~~~~~~~~
Provides common routes.

"""
import pygogo as gogo

from flask import current_app as app, request
from flask.views import MethodView

from config import Config

from app import cache

from app.utils import (
    jsonify,
    parse_request,
    parse_kwargs,
    gen_config,
    get_links,
    get_request_base,
)

from app.helpers import flask_formatter as formatter

logger = gogo.Gogo(
    __name__, low_formatter=formatter, high_formatter=formatter, monolog=True
).logger
logger.propagate = False

PREFIX = Config.API_URL_PREFIX


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


class Memoization(ProviderMixin, MethodView):
    def __init__(self):
        super().__init__()

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

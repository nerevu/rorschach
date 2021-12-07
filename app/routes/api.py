# -*- coding: utf-8 -*-
"""
    app.api
    ~~~~~~~

    Provides additional api endpoints
"""
import pygogo as gogo

from flask import Blueprint, current_app as app
from faker import Faker

from config import Config

from app.utils import (
    jsonify,
    cache_header,
    make_cache_key,
    get_links,
)

from app.routes import auth, Memoization
from app.helpers import get_collection, flask_formatter as formatter

logger = gogo.Gogo(
    __name__, low_formatter=formatter, high_formatter=formatter, monolog=True
).logger
logger.propagate = False
blueprint = Blueprint("API", __name__)
fake = Faker()

ROUTE_TIMEOUT = Config.ROUTE_TIMEOUT
PREFIX = Config.API_URL_PREFIX
AUTHENTICATION = Config.AUTHENTICATION
RESOURCES = Config.RESOURCES
WEBHOOKS = Config.WEBHOOKS

METHOD_VIEWS = {
    "memoization": {
        "view": Memoization,
        "params": ["string:path"],
        "methods": ["GET", "DELETE"],
    },
    "callback": {"view": auth.Callback, "providers": AUTHENTICATION},
    "auth": {
        "view": auth.Auth,
        "providers": AUTHENTICATION,
        "methods": ["GET", "PATCH"],
    },
}

BASE = auth.Resource

add_rule = blueprint.add_url_rule


def create_route(view, prefix, name, *args, **kwargs):
    route_name = f"{prefix}-{name}".lower() if prefix else name
    view_func = view.as_view(route_name, prefix)
    url = f"{PREFIX}/{route_name}"

    for param in kwargs.get("params", []):
        url += f"/<{param}>"

    add_rule(url, view_func=view_func, methods=args)


def _format(value, **kwargs):
    try:
        return value.format(**kwargs)
    except AttributeError:
        return value


def get_value(value, **kwargs):
    try:
        func = value.get("func")
    except AttributeError:
        func = args = key = conditional = result = None
    else:
        args = value.get("args", [])
        key = value.get("key")
        conditional = value.get("conditional")
        result = value.get("result")

    if func:
        _attr_value = _format(func, **kwargs)(*(_format(a, **kwargs) for a in args))
        attr_value = _attr_value[_format(key, **kwargs)] if key else _attr_value
    elif conditional and _format(conditional, **kwargs):
        attr_value = _format(result[0], **kwargs)
    elif conditional:
        attr_value = _format(result[1], **kwargs)
    else:
        attr_value = _format(value, **kwargs)

    return attr_value


def create_class(cls_name, *bases, lookup=None, **kwargs):
    lookup = lookup or {}
    attrs = {}
    base = bases[0]

    try:
        lookup.update(base._registry)
    except AttributeError:
        pass

    for attr_name, value in kwargs.pop("attrs", {}).items():
        attrs[attr_name] = get_value(value, **lookup)

    lookup.update(attrs)

    for prop_name, value in kwargs.pop("props", {}).items():
        attrs[prop_name] = property(get_value(value, **lookup))

    return type(cls_name, bases, attrs, **kwargs)


###########################################################################
# ROUTES
###########################################################################
@blueprint.route("/")
@blueprint.route(PREFIX)
@cache_header(ROUTE_TIMEOUT, key_prefix=make_cache_key)
def home():
    json = {
        "description": "Returns API documentation",
        "message": "Welcome to the Nerevu API!",
        "links": get_links(app.url_map.iter_rules()),
    }

    return jsonify(**json)


@blueprint.route(f"{PREFIX}/ipsum")
@cache_header(ROUTE_TIMEOUT, key_prefix=make_cache_key)
def ipsum():
    json = {
        "description": "Displays a random sentence",
        "links": get_links(app.url_map.iter_rules()),
        "result": fake.sentence(),
    }

    return jsonify(**json)


for name, options in METHOD_VIEWS.items():
    for prefix in options.get("providers", [None]):
        view = get_collection(prefix, **options) or options.get("view")
        methods = options.get("methods", ["GET"])
        create_route(view, prefix, name, *methods)


for prefix, classes in RESOURCES.items():
    auth = AUTHENTICATION[prefix]
    classes.setdefault("Status", {})

    for cls_name, kwargs in classes.items():
        if "collection" in kwargs:
            collection = kwargs.pop("collection")
            base = get_collection(prefix, collection=collection)
        else:
            base = kwargs.pop("base", BASE)

        hidden = kwargs.pop("hidden", False)

        if auth_key := kwargs.get("auth_key"):
            lookup = auth[auth_key].get("attrs", {})

            if auth_parent := auth[auth_key].get("parent"):
                attrs = auth[auth_parent].get("attrs", {})
                [lookup.setdefault(k, v) for k, v in attrs.items()]
        else:
            lookup = {}

        kwargs.setdefault("resource", cls_name.lower())
        resource = kwargs.get("resource")
        methods = kwargs.pop("methods", ["GET"])
        view = get_collection(prefix, collection=cls_name)

        if not view:
            view = create_class(cls_name, base, lookup=lookup, prefix=prefix, **kwargs)

        if not hidden:
            create_route(view, prefix, cls_name.lower(), *methods)

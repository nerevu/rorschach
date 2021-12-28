# -*- coding: utf-8 -*-
"""
    app.api
    ~~~~~~~

    Provides additional api endpoints
"""
import pygogo as gogo

from inspect import getmembers

from flask import Blueprint, current_app as app
from faker import Faker

from config import Config

from app.utils import cache_header, get_links, jsonify, make_cache_key
from app.routes import auth, Memoization, webhook
from app.helpers import (
    flask_formatter as formatter,
    get_member,
    toposort,
    get_collection,
)


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
    view_func = view.as_view(route_name, prefix, **kwargs)
    url = f"{PREFIX}/{route_name}"

    for param in kwargs.get("params", []):
        url += f"/<{param}>"

    add_rule(url, view_func=view_func, methods=args)


def _format(value, **kwargs):
    try:
        return value.format(**kwargs)
    except AttributeError:
        return value


def getattrs(obj, *attrs):
    attr = getattr(obj, attrs[0])

    if len(attrs) > 1:
        attr = getattrs(attr, *attrs[1:])

    return attr


def get_value(value, obj=None, **kwargs):
    try:
        _func = value.get("func")
    except AttributeError:
        _func = fargs = key = conditional = result = None
    else:
        fargs = value.get("args", [])
        fkwargs = value.get("kwargs", [])
        key = value.get("key")
        conditional = value.get("conditional")
        result = value.get("result")

    if _func:
        func = getattrs(obj, *_func.split("."))
        _args = (_format(a, **kwargs) for a in fargs)
        _kwargs = {k: _format(v, **kwargs) for k, v in fkwargs}
        _attr_value = func(*_args, **_kwargs)
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

    for method, response in kwargs.get("responses", {}).items():

        def method_response(Resource, *args, **kwargs):
            lookup.update(getmembers(Resource))
            result = get_value(response, obj=Resource, **lookup)
            return {"result": result}

        attrs[f"{method}_response"] = method_response

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


for prefix, classes in RESOURCES.items():
    _auth = AUTHENTICATION[prefix]
    classes.setdefault("Status", {})

    for cls_name, kwargs in toposort("base", **classes):
        if collection := kwargs.pop("collection", None):
            base = get_collection(prefix, collection=collection)
            assert base, f"Base {collection} not found in {prefix}"
        elif _base := kwargs.pop("base", None):
            base = BASE._registry[prefix].get(_base)
            assert base, f"Base {collection} not found in {prefix}"
        else:
            base = kwargs.pop("base", BASE)

        hidden = kwargs.pop("hidden", False)
        auth_key = kwargs.get("auth_key", base.auth_key)
        assert auth_key, f"{prefix}/{cls_name} is missing auth_key!"

        try:
            lookup = _auth[auth_key].get("attrs", {})
        except KeyError:
            logger.error(f"{prefix} doesn't have auth method {auth_key}!")
            lookup = {}

        if auth_parent := _auth[auth_key].get("parent"):
            attrs = _auth[auth_parent].get("attrs", {})
            [lookup.setdefault(k, v) for k, v in attrs.items()]

        kwargs.setdefault("resource", base.resource or cls_name.lower())
        methods = kwargs.pop("methods", ["GET"])
        view = create_class(cls_name, base, lookup=lookup, prefix=prefix, **kwargs)

        if not hidden:
            create_route(view, prefix, cls_name.lower(), *methods)


for name, options in METHOD_VIEWS.items():
    for prefix in options.get("providers", [None]):
        view = get_collection(prefix, **options) or options.get("view")
        methods = options.get("methods", ["GET"])
        create_route(view, prefix, name, *methods)


for prefix, options in WEBHOOKS.items():
    if view := get_member(webhook, f"{prefix.title()}Hook"):
        create_route(view, prefix, "hooks", "GET", "POST", **kwargs)

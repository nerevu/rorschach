# -*- coding: utf-8 -*-
"""
    app.api
    ~~~~~~~

    Provides additional api endpoints
"""
from collections import Counter
from dataclasses import asdict
from importlib import import_module
from os import getenv

import pygogo as gogo

from attr import make_class
from flask import Blueprint, current_app as app

from app.helpers import (
    flask_formatter as formatter,
    get_collection,
    get_member,
    toposort,
)
from app.routes.auth import Resource as WebResource, _registry
from app.utils import cache_header, get_links, jsonify, make_cache_key
from config import Config

try:
    from app.api_configs import BlueprintRouteParams, MethodViewRouteParams
except ImportError:
    BlueprintRouteParams = MethodViewRouteParams = None

try:
    from app.providers import Authentication, Provider, Resource
except ImportError:
    Authentication = Provider = Resource = None

logger = gogo.Gogo(
    __name__, low_formatter=formatter, high_formatter=formatter, monolog=True
).logger
logger.propagate = False
blueprint = Blueprint("API", __name__)


ROUTE_TIMEOUT = Config.ROUTE_TIMEOUT
PREFIX = Config.API_URL_PREFIX

AUTH_PARAMS = [
    {
        "name": "callback",
        "module": "app.routes.auth",
        "className": "Callback",
    },
    {
        "name": "auth",
        "module": "app.routes.auth",
        "className": "Auth",
        "methods": ["GET", "PATCH"],
    },
]


def create_route(view, name, *args, methods=None, **kwargs):
    methods = methods or ["GET"]
    view_func = view.as_view(name, *args, **kwargs)
    url = f"{PREFIX}/{name}"

    for param in kwargs.get("params", []):
        url += f"/<{param}>"

    print(f"new route {url}!")
    blueprint.add_url_rule(url, view_func=view_func, methods=methods)


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


def create_class(
    base: WebResource = WebResource, lookup: dict = None, **kwargs
) -> WebResource:
    resource_id = kwargs.get("resource_id")
    name = snake_to_pascal_case(resource_id)

    def gen_fields(*args):
        for field in args:
            default = kwargs.get(field.name)

            try:
                if "$" in default:
                    breakpoint()
            except TypeError:
                pass

            yield field.evolve(default=default) if default is not None else field

    def reset_defaults(cls, fields):
        if kwargs.get("prefix") and kwargs.get("resource_id"):
            _registry[kwargs["prefix"]][kwargs["resource_id"]] = cls

        return list(gen_fields(*fields))

    return make_class(name, {}, bases=(base,), field_transformer=reset_defaults)


def get_authentication(*args: Authentication, auth_id: str = None) -> Authentication:
    authentication = None

    if auth_id:
        for authentication in args:
            if authentication.auth_id == auth_id:
                break
        else:
            raise AssertionError(f"authKey `{auth_id}` is missing from auth!")
    else:
        for _, authentication in toposort(*args, id_key="auth_id"):
            if authentication.is_default:
                break
        else:
            raise AssertionError(f"No auths found in provider!")

    return authentication


def snake_to_pascal_case(text: str) -> str:
    return "".join(word.title() for word in text.split("_"))


def augment_auth(provider: Provider, authentication: Authentication):
    authentication.attrs = authentication.attrs or {}

    if authentication.parent:
        parent = get_authentication(*provider.auths, auth_id=authentication.parent)

        for k, v in asdict(parent).items():
            if v and not getattr(authentication, k):
                setattr(authentication, k, v)

        parent_attrs = parent.attrs or {}
        [authentication.attrs.setdefault(k, v) for k, v in parent_attrs.items()]

    for k, v in asdict(authentication).items():
        try:
            is_env = v.startswith("$")
        except AttributeError:
            is_env = False

        if is_env:
            env = v.lstrip("$")
            setattr(authentication, k, getenv(env))


def augment_resource(provider: Provider, resource: Resource):
    resource.parent = WebResource
    resource.auth_id = resource.auth_id or resource.parent.auth_id
    assert (
        resource.auth_id
    ), f"{provider.prefix}/{resource.resource_id} is missing auth_id!"

    resource.resource = resource.resource or resource.parent.resource
    assert (
        resource.resource
    ), f"{provider.prefix}/{resource.resource_id} is missing resource!"

    authentication = get_authentication(*provider.auths, auth_id=resource.auth_id)
    augment_auth(provider, authentication)

    resource.methods = resource.methods or ["GET"]
    resource.attrs = resource.attrs or {}


def validate_providers(*args: Provider):
    prefix_counts = Counter(provider.prefix for provider in args)
    most_common = prefix_counts.most_common(1)

    if most_common[0][1] > 1:
        for prefix, count in most_common:
            raise AssertionError(
                f"The provider prefix `{prefix}` is specified {count} times!"
            )

    for provider in args:
        id_counts = Counter(resource.resource_id for resource in provider.resources)
        most_common = id_counts.most_common(1)

        if most_common[0][1] > 1:
            for resource_id, count in most_common:
                _path = f"{provider.prefix}/resources[?]/{resource_id}"
                raise AssertionError(
                    f"The resourceId {_path} is specified {count} times!"
                )

        id_counts = Counter(auth.auth_id for auth in provider.auths)
        most_common = id_counts.most_common(1)

        if most_common[0][1] > 1:
            for auth_id, count in most_common:
                _path = f"{provider.prefix}/auths[?]/{auth_id}"
                raise AssertionError(f"The authId {_path} is specified {count} times!")


def create_resource_routes(provider: Provider):
    for _, resource in toposort(*provider.resources, id_key="resource_id"):
        augment_resource(provider, resource)
        authentication = get_authentication(*provider.auths, auth_id=resource.auth_id)
        args = (resource, provider.prefix, authentication)

        if not resource.hidden:
            create_resource_route(*args)

        if resource.resource_id == provider.status_resource:
            create_resource_route(*args, resource_id="status")


def create_resource_route(
    resource: Resource,
    prefix: str,
    authentication: Authentication,
    resource_id: str = None,
):
    resource_id = resource_id or resource.resource_id
    kwargs = {
        **asdict(resource),
        "auth": authentication,
        "resource_id": resource_id,
        # "lookup": authentication.attrs,
        "prefix": prefix,
    }
    view = create_class(resource.parent, **kwargs)
    name = f"{prefix}-{resource_id}".replace("_", "-")
    create_route(view, name, prefix, methods=resource.methods)


def create_method_view_route(params: MethodViewRouteParams, prefix=None, **kwargs):
    module = import_module(params.module)
    view = get_member(module, params.class_name)
    name = f"{prefix}-{params.name}" if prefix else params.name
    create_route(view, name, prefix, methods=params.methods, **kwargs)


def create_blueprint_route(params: BlueprintRouteParams, **kwargs):
    module = import_module(params.module)
    view_func = get_member(module, params.func_name, classes_only=False)
    blueprint.route(f"{PREFIX}/{params.name}")(view_func)
    print(f"new route {PREFIX}/{params.name}!")


def create_home_route(description: str, message: str):
    def home():
        json = {
            "description": description,
            "message": message,
            "links": get_links(app.url_map.iter_rules()),
        }

        return jsonify(**json)

    view_func = cache_header(ROUTE_TIMEOUT, key_prefix=make_cache_key)(home)
    blueprint.route("/")(view_func)
    blueprint.route(PREFIX)(view_func)
    print(f"new home route!")

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

from app import actions
from app.routes import auth, Memoization, subscription
from app.helpers import get_collection, get_member

logger = gogo.Gogo(__name__, monolog=True).logger
blueprint = Blueprint("API", __name__)
fake = Faker()

ROUTE_TIMEOUT = Config.ROUTE_TIMEOUT
PREFIX = Config.API_URL_PREFIX
AUTHENTICATION = Config.AUTHENTICATION
WEBHOOKS = Config.WEBHOOKS


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


add_rule = blueprint.add_url_rule

method_views = {
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
    "status": {"collection": "Status", "providers": AUTHENTICATION},
    "projects": {
        "collection": "Projects",
        "providers": AUTHENTICATION,
        "methods": ["GET", "POST"],
    },
    "contacts": {"collection": "Contacts", "providers": AUTHENTICATION},
    "users": {"collection": "Users", "providers": AUTHENTICATION},
    "inventory": {"collection": "Inventory", "providers": AUTHENTICATION},
    "tasks": {"collection": "Tasks", "providers": AUTHENTICATION},
    "time": {
        "collection": "Time",
        "providers": AUTHENTICATION,
        "methods": ["GET", "PATCH"],
    },
    "projecttasks": {
        "collection": "ProjectTasks",
        "providers": AUTHENTICATION,
        "methods": ["GET", "POST"],
    },
    "projecttime": {
        "collection": "ProjectTime",
        "providers": AUTHENTICATION,
        "methods": ["GET", "POST"],
    },
    "email": {"collection": "Email", "providers": AUTHENTICATION, "methods": ["POST"]},
    "invoices": {
        "collection": "Invoices",
        "providers": AUTHENTICATION,
        "methods": ["GET", "POST"],
    },
    "invoicenotification": {
        "collection": "InvoiceNotification",
        "providers": AUTHENTICATION,
    },
    "onlineinvoices": {"collection": "OnlineInvoices", "providers": AUTHENTICATION},
    "subscription": {"view": subscription.Subscription, "methods": ["GET", "POST"]},
}

for name, options in method_views.items():
    for provider in options.get("providers", [None]):
        view = options.get("view", get_collection(provider, **options))

        if not view:
            continue

        route_name = f"{provider}-{name}".lower() if provider else name
        view_func = view.as_view(route_name)
        methods = options.get("methods", ["GET"])
        url = f"{PREFIX}/{route_name}"

        for param in options.get("params", []):
            url += f"/<{param}>"

        add_rule(url, view_func=view_func, methods=methods)


def gen_actions(activities=None, **kwargs):
    _actions = activities or {}

    for key, action_name in _actions.items():
        member = get_member(actions, action_name, classes_only=False)
        yield (key, member)


for provider, options in WEBHOOKS.items():
    view = get_collection(provider, "Hooks")
    _actions = dict(gen_actions(**options))
    route_name = f"{provider}-hooks".lower()
    view_func = view.as_view(route_name, actions=_actions, **options)
    methods = options.get("methods", ["POST"])
    url = f"{PREFIX}/{route_name}"
    add_rule(url, view_func=view_func, methods=methods)

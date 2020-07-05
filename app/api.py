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

from app.routes import auth, Memoization, subscription
from app.helpers import get_collection
from app.providers import xero, aws

logger = gogo.Gogo(__name__, monolog=True).logger
blueprint = Blueprint("API", __name__)
fake = Faker()

ROUTE_TIMEOUT = Config.ROUTE_TIMEOUT
PREFIX = Config.API_URL_PREFIX
AUTHENTICATION = Config.AUTHENTICATION


###########################################################################
# ROUTES
###########################################################################
@blueprint.route("/")
@blueprint.route(PREFIX)
@cache_header(ROUTE_TIMEOUT, key_prefix=make_cache_key)
def home():
    response = {
        "description": "Returns API documentation",
        "message": "Welcome to the Timero API!",
        "links": get_links(app.url_map.iter_rules()),
    }

    return jsonify(**response)


@blueprint.route(f"{PREFIX}/ipsum")
@cache_header(ROUTE_TIMEOUT, key_prefix=make_cache_key)
def ipsum():
    response = {
        "description": "Displays a random sentence",
        "links": get_links(app.url_map.iter_rules()),
        "result": fake.sentence(),
    }

    return jsonify(**response)


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
    "projects": {"collection": "Projects", "providers": AUTHENTICATION},
    "contacts": {"collection": "Contacts", "providers": AUTHENTICATION},
    "users": {"collection": "Users", "providers": AUTHENTICATION},
    "inventory": {"collection": "Inventory", "providers": AUTHENTICATION},
    "tasks": {"collection": "Tasks", "providers": AUTHENTICATION},
    "time": {"collection": "Time", "providers": AUTHENTICATION},
    "projecttasks": {"collection": "ProjectTasks", "providers": AUTHENTICATION},
    "projecttime": {"collection": "ProjectTime", "providers": AUTHENTICATION},
    "email": {"collection": "Email", "providers": AUTHENTICATION, "methods": ["POST"]},
    "subscription": {"view": subscription.Subscription, "methods": ["GET", "POST"]},
    "invoicehook": {"view": xero.InvoiceHook, "methods": ["GET", "POST"]},
    "distributionhook": {"view": aws.DistributionHook, "methods": ["GET", "POST"]},
}

for name, options in method_views.items():
    providers = options.get("providers", [None])

    for provider in providers:
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

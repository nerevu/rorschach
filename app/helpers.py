# -*- coding: utf-8 -*-
"""
    app.helpers
    ~~~~~~~~~~~

    Provides misc helper functions
"""
from inspect import getmembers, isclass
from importlib import import_module

import inflect
import config

p = inflect.engine()
singularize = p.singular_noun


def configure(flask_config, **kwargs):
    if kwargs.get("config_file"):
        flask_config.from_pyfile(kwargs["config_file"])
    elif kwargs.get("config_envvar"):
        flask_config.from_envvar(kwargs["config_envvar"])
    elif kwargs.get("config_mode"):
        obj = getattr(config, kwargs["config_mode"])
        flask_config.from_object(obj)
    else:
        flask_config.from_envvar("APP_SETTINGS", silent=True)


get_class_members = lambda module: getmembers(module, isclass)


def get_member(module, member_name):
    for member in get_class_members(module):
        if member[0].lower() == member_name.lower():
            return member[1]


def get_provider(prefix):
    provider_name = prefix.lower() if prefix else ""

    try:
        provider = import_module(f"app.providers.{provider_name}")
    except (ModuleNotFoundError, ValueError):
        provider = None

    return provider


def get_collection(prefix, collection="", **kwargs):
    if collection:
        provider = get_provider(prefix)
        Collection = get_member(provider, collection)
    else:
        Collection = None

    return Collection

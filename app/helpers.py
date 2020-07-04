# -*- coding: utf-8 -*-
"""
    app.helpers
    ~~~~~~~~~~~

    Provides misc helper functions
"""
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

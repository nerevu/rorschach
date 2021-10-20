# -*- coding: utf-8 -*-
"""
    app.providers.heroku
    ~~~~~~~~~~~~~~~~~~~~

    Provides Heroku API related functions
"""
from app.routes.webhook import Webhook

PREFIX = __name__.split(".")[-1]


class Hooks(Webhook):
    def __init__(self, prefix=PREFIX, **kwargs):
        super().__init__(prefix, **kwargs)

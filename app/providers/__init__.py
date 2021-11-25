# -*- coding: utf-8 -*-
"""
    app.providers
    ~~~~~~~~~~~~~

    Provides General provider related functions
"""
import pygogo as gogo

from app.routes.auth import Resource
from app.helpers import flask_formatter as formatter

logger = gogo.Gogo(
    __name__, low_formatter=formatter, high_formatter=formatter, monolog=True
).logger
logger.propagate = False


###########################################################################
# Resources
###########################################################################
class Status(Resource):
    def __init__(self, prefix, **kwargs):
        super().__init__(prefix, resource="status", **kwargs)

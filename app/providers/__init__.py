# -*- coding: utf-8 -*-
"""
    app.providers
    ~~~~~~~~~~~~~

    Provides General provider related functions
"""
import pygogo as gogo

from app.routes.auth import Resource

logger = gogo.Gogo(__name__, monolog=True).logger
logger.propagate = False


###########################################################################
# Resources
###########################################################################
class Status(Resource):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, resource="status", **kwargs)

# -*- coding: utf-8 -*-
"""
    app.providers.nerevu
    ~~~~~~~~~~~~~~~~~~~~

    Provides Nerevu API related functions
"""
import pygogo as gogo

from app.routes.webhook import Webhook

logger = gogo.Gogo(__name__, monolog=True).logger
logger.propagate = False

PREFIX = __name__.split(".")[-1]


class Hooks(Webhook):
    def __init__(self, prefix=PREFIX, **kwargs):
        super().__init__(prefix, **kwargs)

    def process_value(self, value, activity_name, **kwargs):
        action = self.actions.get(activity_name)

        if action:
            result = action(value, **kwargs)
        else:
            message = f"Activity {activity_name} doesn't exist!"
            logger.warning(message)
            result = {"message": message, "status_code": 404}

        return result

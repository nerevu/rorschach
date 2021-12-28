# -*- coding: utf-8 -*-
"""
    app.providers.aws
    ~~~~~~~~~~~~~~~~~

    Provides AWS Sheets API related functions
"""
from datetime import datetime as dt

import pygogo as gogo

from app.routes.auth import Resource
from app.helpers import flask_formatter as formatter

logger = gogo.Gogo(
    __name__, low_formatter=formatter, high_formatter=formatter, monolog=True
).logger
logger.propagate = False


class AWS(Resource):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._awsc = None

    @property
    def awsc(self):
        if self.client and self._awsc is None:
            self._awsc = self.client.session.client(self.resource)

        return self._awsc

    @property
    def invalidation_batch(self):
        return {
            "Paths": {"Quantity": 4, "Items": self.items},
            "CallerReference": dt.utcnow().isoformat(),
        }

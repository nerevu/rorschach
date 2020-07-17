# -*- coding: utf-8 -*-
""" app.api
~~~~~~~~~~~~
Provides endpoints for authenticating with and pulling data from quickbooks.

Live Site:
    https://alegna-api.nerevu.com/v1

Endpoints:
    Visit the live site for a list of all available endpoints
"""
from flask import request
from flask.views import MethodView

import pygogo as gogo

from config import Config

from app.routes import ProviderMixin
from app.utils import responsify, check_signature

WEBHOOKS = Config.WEBHOOKS

# https://requests-oauthlib.readthedocs.io/en/latest/index.html
# https://oauth-pythonclient.readthedocs.io/en/latest/index.html
logger = gogo.Gogo(__name__, monolog=True).logger


###########################################################################
# METHODVIEW ROUTES
###########################################################################
class Webhook(ProviderMixin, MethodView):
    def __init__(self, *args, methods=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.methods = methods or {}

        try:
            self.webhook_kwargs = WEBHOOKS[self.prefix.lower()]
        except IndexError:
            logger.error(f"Invalid provider: {self.prefix}")
            self.payload_key = None
        else:
            self.payload_key = self.webhook_kwargs["payload_key"]

    @property
    def verified(self):
        return self.payload_key and check_signature(**self.webhook_kwargs)

    # def get(self):
    #     response = {"description": f"The {self.prefix} webhook."}
    #
    #     try:
    #         response["links"] = get_links(app.url_map.iter_rules())
    #     except RuntimeError:
    #         pass
    #
    #     return jsonify(**response)
    #
    def post(self):
        """ Respond to a Webhook post.
        """
        mimetype = "application/json"

        if self.verified:
            payload = request.get_json(force=True, silent=True) or {}
            value = payload.get(self.payload_key)

            if value is not None:
                mimetype = "text/plain"
                response = {"status_code": 200, "result": self.process_value(value)}
            else:
                response = {"message": "Invalid payload", "status_code": 400}
        elif self.payload_key:
            response = {"message": "Invalid signature", "status_code": 401}
        else:
            response = {"message": "Missing payload key", "status_code": 401}

        return responsify(mimetype, **response)

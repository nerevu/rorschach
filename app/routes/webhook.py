# -*- coding: utf-8 -*-
""" app.api
~~~~~~~~~~~~
Provides endpoints for authenticating with and pulling data from quickbooks.

Live Site:
    https://alegna-api.nerevu.com/v1

Endpoints:
    Visit the live site for a list of all available endpoints
"""
import hmac

from base64 import b64encode

from flask import request, current_app as app
from flask.views import MethodView

import pygogo as gogo

from app.routes import ProviderMixin
from app.utils import responsify, get_links, jsonify

# https://requests-oauthlib.readthedocs.io/en/latest/index.html
# https://oauth-pythonclient.readthedocs.io/en/latest/index.html
logger = gogo.Gogo(__name__, monolog=True).logger


###########################################################################
# METHODVIEW ROUTES
###########################################################################
class Webhook(ProviderMixin, MethodView):
    def __init__(self, *args, actions=None, digest="sha256", **kwargs):
        super().__init__(*args, **kwargs)
        self.actions = actions or {}
        self.digest = digest
        self.payload_key = kwargs.get("payload_key")
        self.signature_header = kwargs.get("signature_header")
        self.webhook_secret = kwargs.get("webhook_secret")
        self.split_signature = kwargs.get("split_signature")
        self.b64_encode = kwargs.get("b64_encode")
        self.ignore_signature = kwargs.get("ignore_signature")

    # https://github.com/bloomberg/python-github-webhook
    # https://github.com/carlos-jenkins/python-github-webhooks
    # https://github.com/nickfrostatx/flask-hookserver
    def verified(self):
        if self.ignore_signature:
            is_valid = True
        elif not self.payload_key:
            is_valid = False
        elif self.signature_header and self.webhook_secret:
            signature = request.headers.get(self.signature_header).encode("utf-8")

            if self.split_signature:
                signature = signature.split("=")[1]

            secret = self.webhook_secret.encode("utf-8")

            if self.b64_encode:
                mac_digest = hmac.digest(secret, request.data, self.digest)
                calculated_hmac = b64encode(mac_digest)
            else:
                mac = hmac.new(secret, request.data, self.digest)
                calculated_hmac = mac.hexdigest()

            is_valid = hmac.compare_digest(calculated_hmac, signature)
        else:
            is_valid = False

        return is_valid

    def process_value(self, value):
        action = self.actions.get(value)
        return action(value) if action else {}

    def get(self):
        json = {"description": f"The {self.prefix} webhook."}

        try:
            json["links"] = get_links(app.url_map.iter_rules())
        except RuntimeError:
            pass

        return jsonify(**json)

    def post(self):
        """ Respond to a Webhook post.
        """
        mimetype = "application/json"

        if self.verified:
            payload = request.get_json(force=True, silent=True) or {}
            value = payload.get(self.payload_key)

            if value is not None:
                mimetype = "text/plain"
                json = {"status_code": 200, "result": self.process_value(value)}
            else:
                json = {"message": "Invalid payload", "status_code": 400}
        elif self.payload_key:
            json = {"message": "Invalid signature", "status_code": 401}
        else:
            json = {"message": "Missing payload key", "status_code": 401}

        return responsify(mimetype, **json)

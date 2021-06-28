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
from app.utils import get_links, jsonify, parse_request

# https://requests-oauthlib.readthedocs.io/en/latest/index.html
# https://oauth-pythonclient.readthedocs.io/en/latest/index.html
logger = gogo.Gogo(__name__, monolog=True).logger
logger.propagate = False


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
        self.activities = kwargs.get("activities", {})

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

    def process_value(self, value, activity_name=None, **kwargs):
        action = self.actions.get(activity_name or value)
        return action(value, **kwargs) if action else {}

    def get(self, activity_name=None):
        json = {
            "description": f"The {self.prefix} webhook.",
            "payload_key": self.payload_key,
        }
        action = self.actions.get(activity_name) if activity_name else None

        if activity_name and action:
            json["description"] = action.__doc__
            json["activity"] = activity_name
            json["action"] = action.__name__
            json["kwargs"] = {}

            for x in self.activities:
                if x["name"] == activity_name:
                    json["kwargs"].update(x.get("kwargs", {}))
                    break

            json["kwargs"].update(parse_request())

        elif activity_name:
            json["description"] = f"Activity {activity_name} doesn't exist!"
            json["status_code"] = 404
        else:
            json["activities"] = list(self.actions)
        try:
            json["links"] = get_links(app.url_map.iter_rules())
        except RuntimeError:
            pass

        return jsonify(**json)

    def post(self, activity_name=None):
        """ Respond to a Webhook post.
        """
        if self.verified:
            payload = parse_request()
            value = payload.get(self.payload_key) if self.payload_key else payload

            if value is None:
                message = f"Invalid payload! Ensure key {self.payload_key} is present"
                json = {"message": message, "status_code": 400}
            else:
                json = self.process_value(value, activity_name, **payload)
        elif self.payload_key:
            json = {"message": "Invalid signature!", "status_code": 401}
        else:
            json = {"message": "Missing payload key!", "status_code": 401}

        json.pop("links", None)
        json.pop("Attachments", None)
        return jsonify(**json)

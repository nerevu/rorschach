# -*- coding: utf-8 -*-
""" app.api
~~~~~~~~~~~~
Provides endpoints for authenticating with and pulling data from quickbooks.

Live Site:
    https://alegna-api.nerevu.com/v1

Endpoints:
    Visit the live site for a list of all available endpoints
"""
from flask import request, url_for
from flask.views import MethodView

import pygogo as gogo

from config import Config

from app.routes import ProviderMixin
from app.utils import responsify, jsonify, verify
from app.providers.mailgun import Email

WEBHOOKS = Config.WEBHOOKS

# https://requests-oauthlib.readthedocs.io/en/latest/index.html
# https://oauth-pythonclient.readthedocs.io/en/latest/index.html
logger = gogo.Gogo(__name__, monolog=True).logger


###########################################################################
# METHODVIEW ROUTES
###########################################################################
class Subscription(ProviderMixin, MethodView):
    def get(self):
        email = self.kwargs.get("email")
        list_prefix = self.kwargs.get("list")
        self.emails = Email(list_prefix=list_prefix)

        if not (email and list_prefix):
            message = "You must provide an email address and mailing list."
            response = {"message": message, "status_code": 400}
        elif verify(**self.kwargs):
            subscribed = self.emails.post(**self.kwargs)

            if subscribed["ok"]:
                message = f"Thanks for subscribing {email} to {self.emails.list_name}."
                response = {"message": message}
            else:
                response = subscribed
        else:
            message = "Failed to verify {} for {}.".format(email, self.emails.list_name)
            response = {"message": message, "status_code": 401}

        return jsonify(**response)

    def post(self):
        if self.kwargs.get("honey"):
            message = "You appear to be a bot."
            response = {"message": message, "status_code": 403}
        elif self.kwargs.get("email"):
            url = url_for("subscription", _external=True)
            response = self.emails.send_confirmation(url=url, **self.kwargs)
        else:
            message = "You must provide an email address."
            response = {"message": message, "status_code": 400}

        if request.args.get("format", "json") == "json":
            mimetype = "application/json"
        else:
            mimetype = "text/html"
            heading = f"<h1>{'Success!' if response['ok'] else 'Error.'}</h1>"
            response["html"] = f"<html>{heading}<h2>{response['message']}</h2></html>"

        return responsify(mimetype, **response)

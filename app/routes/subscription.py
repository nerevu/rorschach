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
from app.utils import responsify, verify
from app.providers.mailgun import Email, EmailLists, EmailListMembers

WEBHOOKS = Config.WEBHOOKS

# https://requests-oauthlib.readthedocs.io/en/latest/index.html
# https://oauth-pythonclient.readthedocs.io/en/latest/index.html
logger = gogo.Gogo(__name__, monolog=True).logger


def get_html(ok=False, message="", **kwargs):
    heading = f"<h1>{'Success!' if ok else 'Error.'}</h1>"
    return f"<html>{heading}<h2>{message}</h2></html>"


###########################################################################
# METHODVIEW ROUTES
###########################################################################
class Subscription(ProviderMixin, MethodView):
    def get(self):
        email = self.kwargs.get("email")
        list_prefix = self.kwargs.get("list")
        email_lists = EmailLists(list_prefix=list_prefix, **self.kwargs)
        email_list_members = EmailListMembers(list_prefix=list_prefix, **self.kwargs)
        list_name = email_lists.list_name

        if not (email and list_prefix):
            message = "You must provide an email address and mailing list."
            json = {"message": message, "status_code": 400}
        elif verify(**self.kwargs):
            data = email_list_members.get_post_data(**self.kwargs)
            response = email_list_members.post(**data)
            json = response.json

            if json["ok"]:
                json["message"] = f"Thanks for subscribing {email} to {list_name}."
            else:
                json["status_code"] = response.status_code
        else:
            message = "Failed to verify {} for {}.".format(email, list_name)
            json = {"message": message, "status_code": 401}

        if request.args.get("format", "json") == "json":
            mimetype = "application/json"
        else:
            mimetype = "text/html"
            json["html"] = get_html(**json)

        return responsify(mimetype, **json)

    def post(self):
        list_prefix = self.kwargs.get("list")
        emails = Email(list_prefix=list_prefix, **self.kwargs)

        if self.kwargs.get("honey"):
            json = {"message": "You appear to be a bot.", "status_code": 403}
        elif self.kwargs.get("email"):
            url = url_for("subscription", _external=True)
            json = emails.send_confirmation(url=url, **self.kwargs)
        else:
            json = {"message": "You must provide an email address.", "status_code": 400}

        if request.args.get("format", "json") == "json":
            mimetype = "application/json"
        else:
            mimetype = "text/html"
            json["html"] = get_html(**json)

        return responsify(mimetype, **json)

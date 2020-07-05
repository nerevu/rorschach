# -*- coding: utf-8 -*-
"""
    app.providers.postmark
    ~~~~~~~~~~~~~~~~~~~~~~

    Provides Postmark API related functions
"""
from os.path import splitext

import pygogo as gogo

from app.utils import CTYPES
from app.routes.auth import Resource

logger = gogo.Gogo(__name__, monolog=True).logger


class Domains(Resource):
    def __init__(self, *args, **kwargs):
        kwargs["subkey"] = "domain"
        super().__init__(__name__, "domains", **kwargs)


class EmailLists(Resource):
    def __init__(self, list_prefix=None, **kwargs):
        super().__init__(__name__, "lists", **kwargs)
        self._list_prefix = None
        self.list_prefix = list_prefix

    @property
    def list_prefix(self):
        return self._list_prefix

    @list_prefix.setter
    def list_prefix(self, value):
        self._list_prefix = value

        if self.list_prefix:
            self.rid = f"{self.list_prefix}@{self.client.domain}"


class EmailListMembers(EmailLists):
    def __init__(self, *args, **kwargs):
        kwargs["subresource"] = "members"
        super().__init__(*args, **kwargs)

    def set_post_data(self, email, list_prefix=None, **kwargs):
        assert email, ("You must provide an email address.", 400)

        if list_prefix:
            self.list_prefix = list_prefix

    def get_post_data(self, email, **kwargs):
        try:
            self.set_post_data(email, **kwargs)
        except AssertionError as err:
            self.error_msg, self.status_code = err.args[0]
            member_data = {}
        else:
            member_data = {"subscribed": True, "address": email}

        return member_data


class Email(EmailLists):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.resource = "email"
        self.id_field = "MessageID"

        email_list = self.extract_model()
        self.list_name = email_list[self.name_field]
        self.admin_email = f"owner@{self.client.domain}"
        self.admin_name = self.kwargs["admin"].name

    def set_post_data(self, email, subject, text="", html="", **kwargs):
        assert email, ("You must provide an email address.", 400)
        name = kwargs.get("name")
        self.recipient = f"{name} <{email}>" if name else email
        self.sender = f"{self.admin_name} <{self.admin_email}>"

        assert subject, ("You must provide a subject.", 400)
        self.subject = subject

        assert html or text, ("You must provide the email body text or html.", 400)
        self.text = text
        self.html = html or f"<html><p>{self.text}</p></html>"
        self.tag = kwargs.get("tag")

        if kwargs.get("f"):
            f = kwargs["f"]
            filename = kwargs.get("filename", str(f))
            ext = splitext(filename)[0].lstrip(".")
            content_type = CTYPES[ext]

            self.attachments = [
                {"Name": filename, "Content": f.read(), "ContentType": content_type},
            ]
        else:
            self.attachments = []

        self.metadata = {"client-id": "12345"}

    def get_post_data(self, *args, **kwargs):
        try:
            self.set_post_data(*args, **kwargs)
        except AssertionError as err:
            self.error_msg, self.status_code = err.args[0]
            email_data = {}
        else:
            email_data = {
                "From": self.sender,
                "To": self.recipient,
                "Subject": self.subject,
                "Tag": self.tag,
                "HtmlBody": self.html,
                "TextBody": self.text,
                "TrackOpens": True,
                "TrackLinks": "None",
                "Attachments": self.attachments,
                "Metadata": self.metadata,
            }

            message = f'Prepared email data "{self.subject}" to {self.recipient}'
            self.logger.debug(message)

        return email_data

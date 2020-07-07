# -*- coding: utf-8 -*-
"""
    app.providers.mailgun
    ~~~~~~~~~~~~~~~~~~~~~

    Provides Mailgun API related functions
"""
from urllib.parse import quote

import pygogo as gogo

from flask import current_app as app

from app.utils import hash_text
from app.routes.auth import Resource

logger = gogo.Gogo(__name__, monolog=True).logger

PREFIX = __name__.split(".")[-1]


class Domains(Resource):
    def __init__(self, *args, **kwargs):
        kwargs.update({"subkey": "domain", "ignore_domain": True})
        super().__init__(PREFIX, "domains", *args, **kwargs)


class EmailLists(Resource):
    def __init__(self, *args, list_prefix=None, **kwargs):
        kwargs["ignore_domain"] = True
        super().__init__(PREFIX, "lists", *args, **kwargs)

        def_list_prefix = self.kwargs.get("mailgun_list_prefix")
        self._list_prefix = None
        self.list_prefix = list_prefix or def_list_prefix

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

    def get_post_data(self, email, **kwargs):
        if email:
            member_data = {"subscribed": True, "address": email}
        else:
            self.error_msg = "You must provide an email address."
            self.status_code = 400
            member_data = {}

        return member_data


class Email(Resource):
    def __init__(self, *args, **kwargs):
        kwargs["id_field"] = "MessageID"
        super().__init__(PREFIX, "messages", *args, **kwargs)

        self.lists = EmailLists()
        email_list = self.lists.extract_model()
        self.list_name = email_list[self.lists.name_field]
        self.admin_email = f"owner@{self.client.domain}"
        self.admin_name = app.config["ADMIN"].name

    def set_post_data(self, email="", subject="", text="", html="", **kwargs):
        assert email, ("You must provide an email address.", 400)

        self.lists.list_prefix = kwargs.get("list_prefix", self.lists.list_prefix)
        assert self.lists.list_prefix, ("You must provide a mailing list.", 400)
        name = kwargs.get("name")
        self.recipient = f"{name} <{email}>" if name else email
        self.sender = f"{self.admin_name} <{self.admin_email}>"

        assert subject, ("You must provide a subject.", 400)
        self.subject = subject

        assert html or text, ("You must provide the email body text or html.", 400)
        self.text = text
        self.html = html or f"<html><p>{self.text}</p></html>"
        self.tags = kwargs.get("tags", [])

    def get_post_data(self, *args, **kwargs):
        try:
            self.set_post_data(*args, **kwargs)
        except AssertionError as err:
            self.error_msg, self.status_code = err.args[0]
            email_data = {}
        else:
            email_data = {
                "from": self.sender,
                "to": self.recipient,
                "subject": self.subject,
                "text": self.text,
                "html": self.html,
                "o:tag": self.tags,
            }

            message = f'Prepared email data "{self.subject}" to {self.recipient}'
            self.logger.debug(message)

        return email_data

    def send_confirmation(self, url, **kwargs):
        list_prefix = self.lists.list_prefix
        email = kwargs.get("email")
        qemail = (quote(email or ""),)
        hashed = (hash_text(**kwargs),)

        url = f"{url}?hash={hashed}&email={qemail}&domain={self.client.domain}"
        url += f"&list={list_prefix}&format=html"

        subject = f"[{self.list_name}] Please confirm your subscription"
        html = "<html><p>Hello, please confirm that you want to subscribe to "
        html += f'{self.list_name} by <a href="{url}">clicking here</a>.</p></html>'
        response = self.post(email, subject, html=html, tags=["signup"])

        if response["ok"]:
            message = f"{self.emails.list_prefix} list subscription confirmation sent "
            message += f"to {self.email}."
            response["message"] = message

        return response

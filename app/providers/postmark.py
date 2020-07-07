# -*- coding: utf-8 -*-
"""
    app.providers.postmark
    ~~~~~~~~~~~~~~~~~~~~~~

    Provides Postmark API related functions
"""
from os.path import splitext
from base64 import b64encode

import pygogo as gogo

from app.utils import CTYPES
from app.routes.auth import Resource

logger = gogo.Gogo(__name__, monolog=True).logger

PREFIX = __name__.split(".")[-1]


class Domains(Resource):
    def __init__(self, *args, **kwargs):
        kwargs.update({"subkey": "Domains", "id_field": "ID", "name_field": "Name"})
        kwargs["subkey"] = "Domains"
        super().__init__(PREFIX, "domains", *args, **kwargs)


class Templates(Resource):
    def __init__(self, *args, **kwargs):
        kwargs.update(
            {"subkey": "Templates", "id_field": "TemplateId", "name_field": "Name"}
        )
        super().__init__(PREFIX, "templates", *args, **kwargs)


class Email(Resource):
    def __init__(self, *args, template_id=None, **kwargs):
        kwargs.update({"id_field": "MessageID", "name_field": "To"})
        super().__init__(PREFIX, "email", *args, **kwargs)
        admin = self.kwargs["admin"]
        sender_name = kwargs.get("sender_name") or admin.name
        sender_email = kwargs.get("sender_email") or admin.email
        self.sender = f"{sender_name} <{sender_email}>"

        def_template_id = self.kwargs.get("postmark_template_id")
        self.template_id = template_id or def_template_id

    def set_post_data(self, email, name="", subject="", text="", html="", **kwargs):
        assert email, ("You must provide an email address.", 400)
        self.recipient = f"{name} <{email}>" if name else email
        self.tag = kwargs.get("tag")
        self.metadata = kwargs.get("metadata", {})
        model = kwargs.get("model")

        if self.template_id:
            assert model, ("You must provide a model.", 400)
            self.model = model
            self.resource += "/withTemplate"
        else:
            assert subject, ("You must provide a subject.", 400)
            self.subject = subject

            assert html or text, ("You must provide the email body text or html.", 400)
            self.text = text
            self.html = html or f"<html><p>{self.text}</p></html>"

        if kwargs.get("f"):
            f = kwargs["f"]
            filename = kwargs.get("filename", f.name)
            ext = splitext(filename)[-1].lstrip(".")
            content_type = CTYPES[ext]

            self.attachments = [
                {
                    "Name": filename,
                    "Content": b64encode(f.read()).decode("utf-8"),
                    "ContentType": content_type,
                },
            ]
        else:
            self.attachments = []

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
                "Tag": self.tag,
                "TrackOpens": True,
                "TrackLinks": "None",
                "Attachments": self.attachments,
                "Metadata": self.metadata,
            }

            message = "Got email data for "

            if self.template_id:
                updates = {"TemplateId": self.template_id, "TemplateModel": self.model}
                message += f"template {self.template_id} "
            else:
                updates = {
                    "Subject": self.subject,
                    "HtmlBody": self.html,
                    "TextBody": self.text,
                }

                message += f'subject "{self.subject}" '

            message += f"to {self.recipient} from {self.sender}"
            email_data.update(updates)
            logger.debug(message)

        return email_data

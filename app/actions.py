# -*- coding: utf-8 -*-
"""
    app.actions
    ~~~~~~~~~~~

    Provides misc syncing actions
"""
from pathlib import Path

import pygogo as gogo

from flask import has_request_context

from app.authclient import get_json_response
from app.helpers import get_provider, flask_formatter as formatter
from app.utils import fetch_bool
from app.providers.aws import Distribution
from app.providers.postmark import Email
from app.providers.xero import ProjectTime, InvoiceEmailTemplate, PaymentEmailTemplate

logger = gogo.Gogo(
    __name__, low_formatter=formatter, high_formatter=formatter, monolog=True
).logger
logger.propagate = False


def add_xero_time(source_prefix, project_id=None, position=None, **kwargs):
    """Creates Xero time entries from Timely"""
    xero_time = ProjectTime(
        dictify=True,
        event_pos=position,
        source_project_id=project_id,
        source_prefix=source_prefix,
        **kwargs,
    )

    data = xero_time.get_post_data(source_prefix=source_prefix, **kwargs)

    json = {
        "eof": xero_time.eof,
        "event_id": xero_time.event_id,
        "event_pos": xero_time.event_pos,
    }

    if data:
        response = xero_time.post(**data)
        json.update(response.json)
        status_code = response.status_code
    else:
        json.update({"message": xero_time.error_msg, "ok": False})
        status_code = xero_time.status_code

    json.update({"status_code": status_code, "conflict": status_code == 409})
    return json


def mark_billed(source_prefix, rid, **kwargs):
    """Marks Xero and Timely time as billed"""
    provider = get_provider(source_prefix)
    time = provider.Time(dictify=True, rid=rid, **kwargs)
    data = time.get_patch_data()

    json = {
        "eof": False,
        "event_id": time.rid,
    }

    if data:
        response = time.patch(**data)
        json.update(response.json)
        status_code = response.status_code
    else:
        json.update({"message": time.error_msg, "ok": False})
        status_code = xero_time.status_code

    json.update({"status_code": status_code, "conflict": status_code == 409})
    return json


def send_notification(template, resource_id, prompt=False, **kwargs):
    """Sends an email notification to Xero clients via Postmark"""
    email_template = template(rid=resource_id, **kwargs)
    client = email_template.client
    json = None
    pdf_path = None

    if client and client.verified:
        try:
            template_data = email_template.extract_model()
        except AssertionError as err:
            message, status_code = err.args[0]
            json = {"message": message, "ok": False, "status_code": status_code}
        else:
            pdf_path = template_data["pdf"][0]
            template_data["f"] = open(pdf_path, mode="rb")
            email = Email(**kwargs)
            data = email.get_post_data(**template_data)

            if prompt:
                answer = "n" if has_request_context else fetch_bool("Send email?")
            else:
                answer = "y"
    else:
        answer = "n"

    if json:
        pass
    elif answer == "y":
        response = email.post(**data)
        json = response.json
        json["message"] = json["result"]["Message"]
    elif client and client.verified:
        if has_request_context:
            json = data
        else:
            json = {
                "message": "You canceled the notification.",
                "ok": False,
                "status_code": 400,
            }
    else:
        try:
            json = get_json_response(None, email_template.client, **kwargs)
        except AssertionError as err:
            message, status_code = err.args[0]
            json = {"message": message, "ok": False, "status_code": status_code}

    if client and client.verified and pdf_path:
        Path(pdf_path).unlink(missing_ok=True)

    return json


def send_invoice_notification(invoice_id, **kwargs):
    """Sends an invoice email notification to Xero clients via Postmark"""
    return send_notification(InvoiceEmailTemplate, invoice_id, **kwargs)


def send_payment_notification(payment_id, **kwargs):
    """Sends a payment email notification to Xero clients via Postmark"""
    return send_notification(PaymentEmailTemplate, payment_id, **kwargs)


def invalidate_cf_distribution(action, **kwargs):
    distribution = Distribution(**kwargs)
    json = distribution.invalidate(**kwargs)

    status_code = json["ResponseMetadata"]["HTTPStatusCode"]
    json = {
        "message": json["Invalidation"]["Status"],
        "ok": status_code == 201,
        "status_code": status_code,
    }
    return json

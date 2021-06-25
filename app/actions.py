# -*- coding: utf-8 -*-
"""
    app.actions
    ~~~~~~~~~~~

    Provides misc syncing actions
"""
from pathlib import Path

import pygogo as gogo

from app.authclient import get_json_response
from app.helpers import get_provider
from app.utils import fetch_bool
from app.providers.aws import Distribution
from app.providers.postmark import Email
from app.providers.xero import ProjectTime, EmailTemplate

logger = gogo.Gogo(__name__, monolog=True).logger
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

    data = xero_time.get_post_data()
    response = xero_time.post(**data)
    json = response.json
    status_code = response.status_code
    conflict = status_code == 409

    json.update(
        {
            "status_code": status_code,
            "conflict": conflict,
            "eof": xero_time.eof,
            "event_id": xero_time.event_id,
            "event_pos": xero_time.event_pos,
        }
    )

    if xero_time.error_msg:
        json["message"] = xero_time.error_msg

    return json


def mark_billed(source_prefix, rid, **kwargs):
    """Marks Xero and Timely time as billed"""
    provider = get_provider(source_prefix)
    time = provider.Time(dictify=True, rid=rid, **kwargs)
    data = time.get_patch_data()
    response = time.patch(**data)
    json = response.json
    status_code = response.status_code
    conflict = status_code == 409

    json.update(
        {
            "status_code": status_code,
            "conflict": conflict,
            "eof": False,
            "event_id": time.rid,
        }
    )

    if time.error_msg:
        json["message"] = time.error_msg

    return json


def send_notification(invoice_id, prompt=False, **kwargs):
    """Sends an invoice email notification to Xero clients via Postmark"""
    email_template = EmailTemplate(rid=invoice_id, **kwargs)
    client = email_template.client

    if client and client.verified:
        template_data = email_template.extract_model()
        pdf_path = template_data["pdf"][0]
        template_data["f"] = open(pdf_path, mode="rb")
        email = Email(**kwargs)
        data = email.get_post_data(**template_data)
        answer = fetch_bool("Send email?") if prompt else "y"
    else:
        answer = "n"

    if answer == "y":
        response = email.post(**data)
        json = response.json
        json["message"] = json["result"]["Message"]
    elif client and client.verified:
        json = {
            "message": "You canceled the notification.",
            "ok": False,
            "status_code": 400,
        }
    else:
        json = get_json_response(None, email_template.client, **kwargs)

    if client and client.verified:
        Path(pdf_path).unlink(missing_ok=True)

    return json


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

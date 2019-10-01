# -*- coding: utf-8 -*-
"""
    app.services
    ~~~~~~~~~~~~

    Provides misc syncing services
"""
import requests

import pygogo as gogo

logger = gogo.Gogo(__name__, monolog=True).logger


def add_xero_time(project_id=None, position=None, dry_run=False, **kwargs):
    url = "http://localhost:5000/v1/xero-time"
    data = {"timelyProjectId": project_id, "eventPos": position}

    if dry_run:
        data["dryRun"] = "true"

    r = requests.post(url, data=data)
    json = r.json()

    return {
        "event_id": json.get("event_id"),
        "ok": r.ok,
        "conflict": r.status_code == 409,
        "eof": json.get("eof"),
        "message": json.get("message"),
    }


def mark_billed(event_id, dry_run=False, **kwargs):
    url = "http://localhost:5000/v1/timely-time"
    data = {"eventId": event_id}

    if dry_run:
        data["dryRun"] = "true"

    r = requests.patch(url, data=data)
    return {
        "ok": r.ok,
        "conflict": r.status_code == 409,
        "message": r.json()["message"],
    }

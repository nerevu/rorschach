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
        data.update({"dryRun": "true"})

    r = requests.post(url, data=data)
    json = r.json()
    result = json["result"]
    return {
        "event_id": json.get("event_id"),
        "ok": r.ok,
        "eof": json.get("eof"),
        "message": json["message"],
    }


def mark_billed(event_id):
    url = "http://localhost:5000/v1/timely-time"
    data = {"timelyProjectId": project}

    if dry_run:
        data.update({"dryRun": "true"})

    r = requests.post(url, data=data)
    json = r.json()
    result = json["result"]
    return (json["event_id"], r.ok, json["eof"])

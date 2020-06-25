# -*- coding: utf-8 -*-
"""
    app.services
    ~~~~~~~~~~~~

    Provides misc syncing services
"""
import pygogo as gogo

from app.api import ProjectTime, Time

logger = gogo.Gogo(__name__, monolog=True).logger


def add_xero_time(project_id=None, position=None, dry_run=False, **kwargs):
    xero_time = ProjectTime(
        "XERO",
        dictify=True,
        dry_run=dry_run,
        event_pos=position,
        timely_project_id=project_id,
    )
    response = xero_time.post()
    json = response.json
    json["conflict"] = response.status_code == 409
    return json


def mark_billed(rid, dry_run=False, **kwargs):
    timely_time = Time("TIMELY", dictify=True, dry_run=dry_run, rid=rid)
    response = timely_time.patch()
    json = response.json
    json["conflict"] = response.status_code == 409
    return json

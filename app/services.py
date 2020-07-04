# -*- coding: utf-8 -*-
"""
    app.services
    ~~~~~~~~~~~~

    Provides misc syncing services
"""
import pygogo as gogo

from app.helpers import get_provider
from app.providers.xero import ProjectTime

logger = gogo.Gogo(__name__, monolog=True).logger


def add_xero_time(source_prefix, project_id=None, position=None, **kwargs):
    dry_run = kwargs.get("dry_run")

    xero_time = ProjectTime(
        dictify=True,
        dry_run=dry_run,
        event_pos=position,
        source_project_id=project_id,
        source_prefix=source_prefix,
    )

    data = xero_time.get_post_data()

    if data:
        response = xero_time.post(**data)
        json = response.json
        status_code = response.status_code
        conflict = status_code == 409
    else:
        json = {"ok": False}
        status_code = xero_time.status_code
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


def mark_billed(source_prefix, rid, dry_run=False, **kwargs):
    provider = get_provider(source_prefix)
    time = provider.Time(dictify=True, dry_run=dry_run, rid=rid)
    data = time.get_patch_data()

    if data:
        response = time.patch(**data)
        json = response.json
        status_code = response.status_code
        conflict = status_code == 409
    else:
        json = {"ok": False}
        status_code = time.status_code
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

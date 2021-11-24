# -*- coding: utf-8 -*-
"""
    app.providers.Airtable
    ~~~~~~~~~~~~~~~~~~~~~

    Provides Airtable API related functions
"""
import pygogo as gogo

from app.routes.auth import Resource, process_result
from app.routes.webhook import Webhook
from app.helpers import flask_formatter as formatter, slugify, select_by_id

logger = gogo.Gogo(
    __name__, low_formatter=formatter, high_formatter=formatter, monolog=True
).logger
logger.propagate = False

PREFIX = __name__.split(".")[-1]


def events_filterer(item):
    has_minutes = item.get("duration.total_minutes")
    return has_minutes and item.get("day") and not item.get("billed")


def events_processor(result, fields, **kwargs):
    result = (
        {
            "id": r["id"],
            "billed": r["fields"].get("Billed"),
            "day": r["fields"]["Date"],
            "duration.total_minutes": r["fields"]["Minutes"],
            "task": r["fields"]["Task"][0],
            "label_id": slugify(r["fields"]["Task"][0]),
            "project": r["fields"]["Project"][0],
            "project.id": slugify(r["fields"]["Project"][0]),
            "note": r["fields"]["Description"],
            "user": r["fields"]["Staff"][0],
            "user.id": slugify(r["fields"]["Staff"][0]),
        }
        for r in result
    )
    return process_result(result, fields, **kwargs)


class Airtable(Resource):
    def __init__(self, prefix=PREFIX, **kwargs):
        super().__init__(prefix, **kwargs)


###########################################################################
# Resources
###########################################################################
class Hours(Airtable):
    def __init__(self, prefix=PREFIX, **kwargs):
        params = {"view": "Unbilled"}
        kwargs.update({"processor": events_processor, "params": params})
        super().__init__(prefix, resource="Employee%20Hours", **kwargs)


class Users(Airtable):
    def __init__(self, prefix=PREFIX, **kwargs):
        super().__init__(prefix, resource="users", **kwargs)

    def get_json_response(self):
        hours = Hours().extract_model(as_collection=True)
        _result = {(h["user.id"], h["user"]) for h in hours}
        result = [{"id": k, "name": v} for k, v in _result]

        if self.id:
            result = select_by_id(result, self.id, self.id_field)

        return {"result": result}


class Tasks(Airtable):
    def __init__(self, prefix=PREFIX, **kwargs):
        super().__init__(prefix, resource="tasks", **kwargs)

    def get_json_response(self):
        hours = Hours().extract_model(as_collection=True)
        _result = {(h["label_id"], h["task"]) for h in hours}
        result = [{"id": k, "name": v} for k, v in _result]

        if self.id:
            result = select_by_id(result, self.id, self.id_field)

        return {"result": result}


class Time(Airtable):
    def __init__(self, prefix=PREFIX, **kwargs):
        kwargs.update({"filterer": events_filterer})
        super().__init__(prefix, resource=Hours().resource, **kwargs)

    def set_patch_data(self):
        assert self.rid, ("No 'rid' given!", 500)

        patched = self.results.get(str(self.rid), {}).get("patched")
        assert not patched, (f"{self} already patched!", 409)

        self.source_event = self.extract_model(update_cache=True, strict=True)
        assert not self.source_event["billed"], (f"{self} already billed!", 409)

    def get_patch_data(self):
        try:
            self.set_patch_data()
        except AssertionError as err:
            self.error_msg, self.status_code = err.args[0]
            data = {}
        else:
            data = {"fields": {"Billed": True}, "typecast": True}

        return data

    def get_json_response(self):
        result = Hours().extract_model(as_collection=True)

        if self.id:
            result = select_by_id(result, self.id, self.id_field)

        return {"result": result}


class Projects(Airtable):
    def __init__(self, prefix=PREFIX, **kwargs):
        super().__init__(prefix, resource="projects", **kwargs)

    def get_json_response(self):
        hours = Hours().extract_model(as_collection=True)
        _result = {(h["project.id"], h["project"]) for h in hours}
        result = [{"id": k, "name": v} for k, v in _result]

        if self.id:
            result = select_by_id(result, self.id, self.id_field)

        return {"result": result}


class ProjectTasks(Airtable):
    def __init__(self, prefix=PREFIX, **kwargs):
        kwargs["fields"] = ["id", "name"]
        self.get_json_response = Tasks().get_json_response
        super().__init__(prefix, resource="projects", **kwargs)


class ProjectTime(Airtable):
    def __init__(self, prefix=PREFIX, **kwargs):
        kwargs.update({"subresource": "events", "filterer": events_filterer})
        super().__init__(prefix, resource="projects", **kwargs)

    def get_json_response(self):
        if self.rid:
            hours = Hours().extract_model(as_collection=True)
            result = [h for h in hours if self.rid == h["project.id"]]

            if self.id:
                result = select_by_id(result, self.id, self.id_field)

            json = {"result": result}
        else:
            json = {
                "result": [],
                "message": f"No {self} {self.resource} id provided!",
                "status_code": 404,
            }

        return json


class Hooks(Webhook):
    def __init__(self, prefix=PREFIX, **kwargs):
        super().__init__(prefix, **kwargs)

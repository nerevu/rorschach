# -*- coding: utf-8 -*-
"""
    app.providers.timely
    ~~~~~~~~~~~~~~~~~~~~

    Provides Timely API related functions
"""
from itertools import chain

import pygogo as gogo

from app.routes.auth import Resource, process_result
from app.mappings import POSITIONS

logger = gogo.Gogo(__name__, monolog=True).logger

BILLABLE = 1344430
NONBILLABLE = 1339635

events_filterer = lambda item: not (item.get("billed") or item.get("deleted"))


def tasks_processor(result, fields, **kwargs):
    _billable = (r["children"] for r in result if str(r["id"]) == str(BILLABLE))
    _non_billable = (r["children"] for r in result if str(r["id"]) == str(NONBILLABLE))

    try:
        billable_args = (next(_billable), fields)
    except StopIteration:
        billable = []
    else:
        billable = process_result(*billable_args, billable=True)

    try:
        non_billable_args = (next(_non_billable), fields)
    except StopIteration:
        non_billable = []
    else:
        non_billable = process_result(*non_billable_args, billable=False)

    return chain(billable, non_billable)


def get_label_id(label_ids):
    try:
        return next(
            label for label in label_ids if label not in {BILLABLE, NONBILLABLE}
        )
    except StopIteration:
        return 0


def events_processor(result, fields, **kwargs):
    result = ({**item, "label_id": get_label_id(item["label_ids"])} for item in result)
    return process_result(result, fields, **kwargs)


def get_position_user_ids(xero_task_name):
    position_name = xero_task_name.split("(")[1][:-1]

    try:
        user_ids = POSITIONS[position_name]
    except KeyError:
        logger.debug(f"Position map doesn't contain position '{position_name}'!")
        user_ids = []

    return user_ids


###########################################################################
# METHODVIEW ROUTES
###########################################################################
class Status(Resource):
    def __init__(self, **kwargs):
        super().__init__(__name__, "status", **kwargs)


class Projects(Resource):
    def __init__(self, **kwargs):
        fields = ["id", "name", "active", "billable", "client", "budget"]
        super().__init__(__name__, "projects", fields=fields, **kwargs)


class Users(Resource):
    def __init__(self, **kwargs):
        fields = ["id", "name"]
        super().__init__(__name__, "users", fields=fields, **kwargs)


class Tasks(Resource):
    def __init__(self, **kwargs):
        fields = ["id", "name"]
        kwargs.update({"processor": tasks_processor, "rid_hook": self.hook})
        super().__init__(__name__, "labels", fields=fields, **kwargs)

    def hook(self):
        if self.rid:
            self.processor = process_result


class Time(Resource):
    def __init__(self, **kwargs):
        fields = [
            "id",
            "day",
            "duration.total_minutes",
            "label_id",
            "project.id",
            "user.id",
            "note",
            "billed",
        ]

        processor = events_processor
        filterer = events_filterer
        kwargs.update({"processor": processor, "filterer": filterer})
        super().__init__(__name__, "events", fields=fields, **kwargs)

    def set_patch_data(self):
        assert self.rid, ("No 'rid' given!", 500)

        patched = self.results.get(str(self.rid), {}).get("patched")
        assert not patched, (f"{self} already patched!", 409)

        self.source_event = self.extract_model(update_cache=True, strict=True)
        assert not self.source_event["billed"], (f"{self} already billed!", 409)

    def get_patch_data(self):
        # url = 'http://localhost:5000/v1/timely-time'
        # r = requests.patch(url, data={"rid": 165829339, "dryRun": True})
        try:
            self.set_patch_data()
        except AssertionError as err:
            self.error_msg, self.status_code = err.args[0]
            data = {}
        else:
            total_minutes = self.source_event["duration.total_minutes"]

            data = {
                "id": self.id,
                "day": self.source_event["day"],
                "hours": total_minutes // 60,
                "minutes": total_minutes % 60,
                "billed": True,
                "user_id": self.source_event["user.id"],
            }

        return data


class ProjectTasks(Resource):
    def __init__(self, **kwargs):
        fields = ["id", "name"]
        kwargs.update({"subkey": "label_ids", "processor": None, "id_hook": self.hook})

        super().__init__(__name__, "projects", fields=fields, **kwargs)

    def project_tasks_processor(self, result, fields, **kwargs):
        tasks = Tasks(dictify=True)
        tasks.get(update_cache=True)
        result = map(str, result)
        result = (tasks[item] for item in result if tasks.data.get(item))
        return process_result(result, fields, projectId=self.rid, **kwargs)

    def hook(self):
        if self.id:
            self.processor = self.project_tasks_processor


class ProjectTime(Resource):
    def __init__(self, **kwargs):
        fields = Time().fields

        kwargs.update(
            {
                "subresource": "events",
                "processor": events_processor,
                "filterer": events_filterer,
            }
        )

        super().__init__(__name__, "projects", fields=fields, **kwargs)

# -*- coding: utf-8 -*-
"""
    app.providers.gsheets
    ~~~~~~~~~~~~~~~~~~~~~

    Provides Google Sheets API related functions
"""
from time import sleep

import pygogo as gogo
import gspread

from gspread.exceptions import APIError

from app.utils import parse
from app.routes.auth import Resource, process_result
from app.routes.webhook import Webhook
from app.helpers import flask_formatter as formatter, slugify, select_by_id, parse_date
from meza.fntools import chunk

logger = gogo.Gogo(
    __name__, low_formatter=formatter, high_formatter=formatter, monolog=True
).logger
logger.propagate = False

PREFIX = __name__.split(".")[-1]
# DEF_START_ROW = Config.DEF_START_ROW
DEF_START_ROW = 2  # Since the first row is header


def events_filterer(item):
    has_time = item.get("duration.total_minutes")
    has_date = item.get("day")
    unbilled = not item.get("billed")
    return has_time and has_date and unbilled


def events_processor(result, fields, **kwargs):
    result = (
        {
            **r,
            "billed": parse(r["billed"]),
            "day": parse_date(r["date"]),
            "duration.total_minutes": r["total minutes"],
            "label_id": slugify(r["task"]),
            "project.id": slugify(r["project"].split("(")[0]),
            "note": r["description"],
        }
        for r in result
    )
    return process_result(result, fields, **kwargs)


def add_id(record):
    return {**record, "id": f"{record['user.id']}-{record['row']}"}


class GSheets(Resource):
    def __init__(self, prefix=PREFIX, **kwargs):
        super().__init__(prefix, **kwargs)

        if self.client:
            self.gc = gspread.authorize(self.client.credentials)
            self._sheet_id = kwargs.get("sheet_id", self.client.sheet_id)
            self._worksheet_name = kwargs.get(
                "worksheet_name", self.client.worksheet_name
            )
        else:
            self._sheet_id = kwargs.get("sheet_id")
            self._worksheet_name = kwargs.get("worksheet_name")

        self.chunksize = kwargs.get("chunksize")
        self._sheet_name = kwargs.get("sheet_name")
        self._worksheet_pos = kwargs.get("worksheet_pos")
        self._sheet = None
        self._worksheet = None

    @property
    def sheet_id(self):
        return self._sheet_id

    @sheet_id.setter
    def sheet_id(self, value):
        self._sheet_id = value
        self._sheet = None

    @property
    def sheet_name(self):
        return self._sheet_name

    @sheet_name.setter
    def sheet_name(self, value):
        self._sheet_name = value
        self._sheet = None

    @property
    def sheet(self):
        if self._sheet is None:
            if self.sheet_id:
                self._sheet = self.gc.open_by_key(self.sheet_id)
            elif self.sheet_name:
                self._sheet = self.gc.open(self.sheet_name)

        return self._sheet

    @property
    def worksheet_pos(self):
        return self._worksheet_pos

    @worksheet_pos.setter
    def worksheet_pos(self, value):
        self._worksheet_pos = value
        self._worksheet = None

    @property
    def worksheet_name(self):
        return self._worksheet_name

    @worksheet_name.setter
    def worksheet_name(self, value):
        self._worksheet_name = value
        self._worksheet = None

    @property
    def worksheet(self):
        if self.sheet and self._worksheet is None:
            if self.worksheet_name:
                self._worksheet = self.retry_method(
                    "worksheet", self.worksheet_name, obj_attr="sheet"
                )
            elif self.worksheet_pos is not None:
                self._worksheet = self.retry_method(
                    "get_worksheet", self.worksheet_pos, obj_attr="sheet"
                )
            elif self.use_default:
                self._worksheet = self.retry_method(
                    "get_worksheet", 0, obj_attr="sheet"
                )

        return self._worksheet

    def retry_method(self, attr, *args, obj_attr="worksheet", **kwargs):
        obj = getattr(self, obj_attr)
        method = getattr(obj, attr)

        try:
            value = method(*args, **kwargs)
        except APIError as err:
            err_json = err.response.json()
            error = err_json["error"]
            status_code = error["code"]
            err_message = error["message"]

            # https://console.cloud.google.com/iam-admin/quotas?authuser=1
            if status_code == 429:
                logger.debug("Exceeded quota. Waiting 100 seconds...")
                sleep(100)
                logger.debug("Done waiting!")
                value = self.retry_method(attr, *args, obj_attr=obj_attr, **kwargs)
            else:
                logger.error(err_message)

        return value

    def create_range(self, end_row, end_col, start_row=DEF_START_ROW, start_col=1):
        if end_row > self.worksheet.row_count:
            logger.debug(f"Adding {self.additional_rows} additional rows...")
            rows = end_row + self.additional_rows
            self.worksheet.resize(rows=rows)

        args = (start_row, start_col, end_row, end_col)
        return self.retry_method("range", *args)

    def insert_row(self, *args, **kwargs):
        self.retry_method("insert_row", *args, **kwargs)

    def update_cells(self, cells, values):
        for cell, value in zip(cells, values):
            cell.value = value

        self.retry_method("update_cells", cells, value_input_option="USER_ENTERED")

    def add_data(self, data):
        start_row = DEF_START_ROW
        headers = []
        end_col = len(headers)

        # https://gspread.readthedocs.io/en/latest/api.html#gspread.models.Spreadsheet.values_update
        # https://developers.google.com/sheets/api/reference/rest/v4/spreadsheets/request#UpdateCellsRequest
        for _data in chunk(data, chunksize=self.chunksize):
            rows = list(_data)
            end_row = start_row + len(rows) - 1
            cells = self.create_range(end_row, end_col, start_row=start_row)
            self.update_cells(cells, rows)
            start_row = end_row + 1


###########################################################################
# Resources
###########################################################################
class Status(GSheets):
    def __init__(self, prefix=PREFIX, **kwargs):
        super().__init__(prefix, resource="status", **kwargs)


class Projects(GSheets):
    def __init__(self, prefix=PREFIX, **kwargs):
        super().__init__(prefix, resource="projects", **kwargs)

    def get_json_response(self):
        self.worksheet_name = "client projects"
        records = self.retry_method("get_all_records")

        result = [
            {
                "id": slugify(r["project"]),
                "name": r["project"],
                "client": {"id": slugify(r["client"]), "name": r["client"]},
                "row": pos + 2,
            }
            for (pos, r) in enumerate(records)
        ]

        if self.id:
            result = select_by_id(result, self.id, self.id_field)

        return {"result": result}


class Users(GSheets):
    def __init__(self, prefix=PREFIX, **kwargs):
        super().__init__(prefix, resource="users", **kwargs)

    def get_json_response(self):
        result = [
            {"id": "austin", "name": "Austin Dial"},
            {"id": "mitchell", "name": "Mitchell Sotto"},
        ]

        if self.id:
            result = select_by_id(result, self.id, self.id_field)

        return {"result": result}


class Contacts(GSheets):
    def __init__(self, prefix=PREFIX, **kwargs):
        super().__init__(prefix, resource="contacts", **kwargs)

    def get_json_response(self):
        result = self.retry_method("col_values", 1)[1:]

        if self.id:
            result = select_by_id(result, self.id, self.id_field)

        return {"result": result}


class Tasks(GSheets):
    def __init__(self, prefix=PREFIX, **kwargs):
        super().__init__(prefix, resource="tasks", **kwargs)

    def get_json_response(self):
        result = [
            {"name": v, "row": pos + 2, "id": slugify(v)}
            for (pos, v) in enumerate(self.retry_method("col_values", 3)[1:])
        ]

        if self.id:
            result = select_by_id(result, self.id, self.id_field)

        return {"result": result}


class Time(GSheets):
    def __init__(self, prefix=PREFIX, **kwargs):
        fields = [
            "id",
            "row",
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
        kwargs.update({"fields": fields, "processor": processor, "filterer": filterer})
        super().__init__(prefix, resource="events", **kwargs)

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
            row = self.source_event["row"]
            data = {"range_name": f"G{row}", "values": True}

        return data

    def get_json_response(self):
        self.worksheet_name = "austin (time)"
        austin_records = self.retry_method("get_all_records")
        austin_time = [
            {**r, "user.id": "austin", "row": pos + 2}
            for (pos, r) in enumerate(austin_records)
        ]

        self.worksheet_name = "mitchell (time)"
        mitchell_records = self.retry_method("get_all_records")
        mitchell_time = [
            {**r, "user.id": "mitchell", "row": pos + 2}
            for (pos, r) in enumerate(mitchell_records)
        ]

        _result = austin_time + mitchell_time
        result = map(add_id, _result)

        if self.id:
            result = select_by_id(result, self.id, self.id_field)

        return {"result": result}

    def patch_response(self, range_name="", values=None, **data):
        user_id = self.source_event["user.id"]
        self.worksheet_name = f"{user_id} (time)"
        result = self.retry_method("update", range_name, values, raw=False)
        return {"result": result}


class ProjectTasks(GSheets):
    def __init__(self, prefix=PREFIX, **kwargs):
        kwargs["fields"] = ["id", "name"]
        self.get_json_response = Tasks().get_json_response
        super().__init__(prefix, resource="projects", **kwargs)


class ProjectTime(GSheets):
    def __init__(self, prefix=PREFIX, **kwargs):
        processor = events_processor
        filterer = events_filterer
        kwargs.update(
            {
                "fields": Time().fields,
                "subresource": "events",
                "processor": processor,
                "filterer": filterer,
            }
        )

        super().__init__(prefix, resource="projects", **kwargs)

    def get_json_response(self):
        if self.rid:
            self.worksheet_name = "austin (time)"
            austin_records = self.retry_method("get_all_records")
            austin_time = [
                {**r, "user.id": "austin", "row": pos + 2}
                for (pos, r) in enumerate(austin_records)
                if self.rid == slugify(r["project"].split("(")[0])
            ]

            self.worksheet_name = "mitchell (time)"
            mitchell_records = self.retry_method("get_all_records")
            mitchell_time = [
                {**r, "user.id": "mitchell", "row": pos + 2}
                for (pos, r) in enumerate(mitchell_records)
                if self.rid == slugify(r["project"].split("(")[0])
            ]

            _result = austin_time + mitchell_time
            result = map(add_id, _result)

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

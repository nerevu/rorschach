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

from app.routes.auth import Resource
from app.helpers import flask_formatter as formatter

logger = gogo.Gogo(
    __name__, low_formatter=formatter, high_formatter=formatter, monolog=True
).logger
logger.propagate = False


class GSheets(Resource):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._gc = None

    @property
    def gc(self):
        if self.client and self._gc is None:
            self._gc = gspread.authorize(self.client.credentials)

        return self._gc

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


class Spreadsheet(GSheets):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._sheet = None

    @property
    def sheet(self):
        if self._sheet is None:
            # HACK: I should be doing this in the prop setter, but not sure how to
            # override the current props
            if self.resource:
                self._sheet = self.gc.open(self.resource)
                self.rid = self._sheet.id
            elif self.rid:
                self._sheet = self.gc.open_by_key(self.rid)
                self.resource = self._sheet.title

        return self._sheet


class Worksheet(Spreadsheet):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._worksheet = None

    @property
    def worksheet(self):
        if self.sheet and self._worksheet is None:
            # HACK: I should be doing this in the prop setter, but not sure how to
            # override the current props
            if self.subresource:
                self._worksheet = self.retry_method(
                    "worksheet", self.subresource, obj_attr="sheet"
                )
                self.subresource_id = self._worksheet.id
            elif self.subresource_id is not None:
                self._worksheet = self.retry_method(
                    "get_worksheet_by_id", self.subresource_id, obj_attr="sheet"
                )
                self.subresource = self._worksheet.title

        return self._worksheet

    def get_json_response(self):
        records = self.retry_method("get_all_records")
        return {
            "result": [
                {"row": pos + 2, **record} for (pos, record) in enumerate(records)
            ]
        }

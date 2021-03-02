# -*- coding: utf-8 -*-
"""
    app.housekeeping
    ~~~~~~~~~~~~~~~~

    Provides additional housekeeping endpoints
"""
from sys import exc_info

from flask import Blueprint, redirect, request, current_app as app
from werkzeug.exceptions import HTTPException

from app.helpers import exception_hook
from app.utils import jsonify

blueprint = Blueprint("Housekeeping", __name__)


@blueprint.before_app_request
def clear_trailing():
    request_path = request.path
    is_root = request_path == "/"
    is_admin = request_path.startswith("/admin")
    has_trailing = request_path.endswith("/")

    if not (is_root or is_admin) and has_trailing:
        return redirect(request_path[:-1])


@blueprint.app_errorhandler(Exception)
def handle_exception(error):
    if isinstance(error, HTTPException):
        status_code = error.code
        etype = error.__class__
    else:
        status_code = 500
        etype, value, tb = exc_info()
        exception_hook(etype, value, tb, debug=app.debug)

    json = {"status_code": status_code, "result": etype.__name__}
    return jsonify(**json)

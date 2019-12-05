# -*- coding: utf-8 -*-
"""
    app.utils
    ~~~~~~~~~

    Provides misc utility functions
"""
import random

from json import load, loads, dumps
from json.decoder import JSONDecodeError
from ast import literal_eval
from datetime import date, datetime as dt, timedelta
from time import gmtime
from functools import wraps, partial
from hashlib import md5
from http.client import responses

import requests
import pygogo as gogo

from requests import Response
from flask import make_response, request
from dateutil.relativedelta import relativedelta

from meza import fntools as ft, process as pr
from mezmorize import get_cache

from app import cache

logger = gogo.Gogo(__name__, monolog=True).logger

ENCODING = "utf-8"
EPOCH = dt(*gmtime(0)[:6])

MIMETYPES = [
    "application/json",
    "application/xml",
    "text/html",
    "text/xml",
    "image/jpg",
]


get_hash = lambda text: md5(str(text).encode(ENCODING)).hexdigest()


class CustomEncoder(ft.CustomEncoder):
    def default(self, obj):
        if "days" in set(dir(obj)):
            encoded = str(obj)
        else:
            encoded = super().default(obj)

        return encoded


def responsify(mimetype, status_code=200, indent=2, sort_keys=True, **kwargs):
    """ Creates a jsonified response. Necessary because the default
    flask.jsonify doesn't correctly handle sets, dates, or iterators

    Args:
        status_code (int): The status code (default: 200).
        indent (int): Number of spaces to indent (default: 2).
        sort_keys (bool): Sort response dict by keys (default: True).
        kwargs (dict): The response to jsonify.

    Returns:
        (obj): Flask response
    """
    encoding = kwargs.get("encoding", ENCODING)
    options = {"indent": indent, "sort_keys": sort_keys, "ensure_ascii": False}
    kwargs["status"] = responses[status_code]

    if mimetype.endswith("json"):
        content = dumps(kwargs, cls=CustomEncoder, **options)
    elif mimetype.endswith("csv") and kwargs.get(result):
        content = cv.records2csv(kwargs[result]).getvalue()
    else:
        content = ""

    resp = (content, status_code)
    response = make_response(resp)
    response.headers["Content-Type"] = f"{mimetype}; charset={encoding}"
    response.headers.mimetype = mimetype
    response.last_modified = dt.utcnow()
    response.add_etag()
    return response


jsonify = partial(responsify, "application/json")


def parse(string):
    """ Parses a string into an equivalent Python object

    Args:
        string (str): The string to parse

    Returns:
        (obj): equivalent Python object

    Examples:
        >>> parse('True')
        True
        >>> parse('{"key": "value"}')
        {'key': 'value'}
    """
    if string.lower() in {"true", "false"}:
        parsed = loads(string.lower())
    else:
        try:
            parsed = literal_eval(string)
        except (ValueError, SyntaxError):
            parsed = string

    return parsed


def make_cache_key(*args, **kwargs):
    """ Creates a memcache key for a url and its query/form parameters

    Returns:
        (obj): Flask request url
    """
    mimetype = get_mimetype(request)
    return f"{request.method}:{request.full_path}"


def fmt_elapsed(elapsed):
    """ Generates a human readable representation of elapsed time.

    Args:
        elapsed (float): Number of elapsed seconds.

    Yields:
        (str): Elapsed time value and unit

    Examples:
        >>> formatted = fmt_elapsed(1000)
        >>> formatted.next()
        u'16 minutes'
        >>> formatted.next()
        u'40 seconds'
    """
    # http://stackoverflow.com/a/11157649/408556
    # http://stackoverflow.com/a/25823885/408556
    attrs = ["years", "months", "days", "hours", "minutes", "seconds"]
    delta = relativedelta(seconds=elapsed)

    for attr in attrs:
        value = getattr(delta, attr)

        if value:
            yield "%d %s" % (value, attr[:-1] if value == 1 else attr)


# https://gist.github.com/glenrobertson/954da3acec84606885f5
# http://stackoverflow.com/a/23115561/408556
# https://github.com/pallets/flask/issues/637
def cache_header(max_age, **ckwargs):
    """
    Add Flask cache response headers based on max_age in seconds.

    If max_age is 0, caching will be disabled.
    Otherwise, caching headers are set to expire in now + max_age seconds
    If round_to_minute is True, then it will always expire at the start of a
    minute (seconds = 0)

    Example usage:

    @app.route('/map')
    @cache_header(60)
    def index():
        return render_template('index.html')

    """

    def decorator(view):
        f = cache.cached(max_age, **ckwargs)(view)

        @wraps(f)
        def wrapper(*args, **wkwargs):
            response = f(*args, **wkwargs)
            response.cache_control.max_age = max_age

            if max_age:
                response.cache_control.public = True
                extra = timedelta(seconds=max_age)
            else:
                response.headers["Pragma"] = "no-cache"
                response.cache_control.must_revalidate = True
                response.cache_control.no_cache = True
                response.cache_control.no_store = True
                extra = timedelta(0)

            response.expires = (response.last_modified or dt.utcnow()) + extra
            return response.make_conditional(request)

        return wrapper

    return decorator


def uncache_header(response):
    """
    Removes Flask cache response headers
    """
    response.cache_control.max_age = 0
    response.cache_control.public = False
    response.headers["Pragma"] = "no-cache"
    response.cache_control.must_revalidate = True
    response.cache_control.no_cache = True
    response.cache_control.no_store = True
    response.expires = response.last_modified or dt.utcnow()
    return response


# http://flask.pocoo.org/snippets/45/
def get_mimetype(request):
    best = request.accept_mimetypes.best_match(MIMETYPES)

    if not best:
        mimetype = "text/html"
    elif request.accept_mimetypes[best] > request.accept_mimetypes["text/html"]:
        mimetype = best
    else:
        mimetype = "text/html"

    return mimetype


def load_path(path, default=None):
    default = default or {}

    try:
        contents = load(path.open())
    except (JSONDecodeError, FileNotFoundError):
        contents = default

    return contents

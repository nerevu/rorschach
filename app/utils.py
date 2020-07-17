# -*- coding: utf-8 -*-
"""
    app.utils
    ~~~~~~~~~

    Provides misc utility functions
"""
import re
import hmac

from json import load, loads, dumps
from ast import literal_eval
from base64 import b64encode
from datetime import datetime as dt, date, timedelta
from time import gmtime
from functools import wraps, partial
from hashlib import md5
from http.client import responses
from json.decoder import JSONDecodeError
from subprocess import call

import pygogo as gogo

from flask import make_response, request
from dateutil.relativedelta import relativedelta

from riko.dotdict import DotDict
from meza.fntools import CustomEncoder
from meza.convert import records2csv
from config import Config

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

COMMON_ROUTES = {
    ("v1", "GET"): "home",
    ("ipsum", "GET"): "ipsum",
    ("memoization", "GET"): "memoize",
    ("memoization", "DELETE"): "reset",
}

AUTH_ROUTES = {
    ("auth", "GET"): "authenticate",
    ("auth", "DELETE"): "revoke",
    ("refresh", "GET"): "refresh",
    ("status", "GET"): "status",
}

CTYPES = {
    "pdf": "application/octet-stream",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "txt": "text/plain",
}

get_hash = lambda text: md5(str(text).encode(ENCODING)).hexdigest()

APP_CONFIG_WHITELIST = Config.APP_CONFIG_WHITELIST
TODAY = date.today()
YESTERDAY = TODAY - timedelta(days=1)


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

    if mimetype.endswith("json"):
        kwargs["status"] = responses[status_code]
        content = dumps(kwargs, cls=CustomEncoder, **options)
    elif mimetype.endswith("csv") and kwargs.get("result"):
        content = records2csv(kwargs["result"]).getvalue()
    elif mimetype.endswith("html") and kwargs.get("html"):
        content = kwargs["html"]
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
    cache_key = f"{mimetype}:{request.full_path}"
    logger.debug(cache_key)
    return cache_key


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

    Examples:
    >>> @app.route('/map')
    >>> @cache_header(60)
    >>> def index():
    ...     return render_template('index.html')

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


def _title_case(word):
    return f"{word[0].upper()}{word[1:].lower()}"


def title_case(text):
    text_words = text.split(" ")
    return " ".join(map(_title_case, text_words))


def get_common_rel(resourceName, method):
    key = (resourceName, method)
    return COMMON_ROUTES.get(key, AUTH_ROUTES.get(key))


def get_resource_name(rule):
    """ Returns resourceName from endpoint

    Args:
        rule (str): the endpoint path (e.g. '/v1/data')

    Returns:
        (str): the resource name

    Examples:
        >>> rule = '/v1/data'
        >>> get_resource_name(rule)
        'data'
    """
    url_path_list = [p for p in rule.split("/") if p]
    return url_path_list[:2].pop()


def get_params(rule):
    """ Returns params from the url

    Args:
        rule (str): the endpoint path (e.g. '/v1/data/<int:id>')

    Returns:
        (list): parameters from the endpoint path

    Examples:
        >>> rule = '/v1/random_resource/<string:path>/<status_type>'
        >>> list(get_params(rule))
        ['path', 'status_type']
    """
    # param regexes
    param_with_colon = r"<.+?:(.+?)>"
    param_no_colon = r"<(.+?)>"
    either_param = param_with_colon + r"|" + param_no_colon

    parameter_matches = re.findall(either_param, rule)
    return map("".join, parameter_matches)


def get_rel(href, method, rule):
    """ Returns the `rel` of an endpoint (see `Returns` below).

    If the rule is a common rule as specified in the utils.py file, then that rel is
    returned.

    If the current url is the same as the href for the current route, `self` is
    returned.

    Args:
        href (str): the full endpoint url (e.g. https://alegna-api.nerevu.com/v1/data)
        method (str): an HTTP method (e.g. 'GET' or 'DELETE')
        rule (str): the endpoint path (e.g. '/v1/data/<int:id>')

    Returns:
        rel (str): a string representing what the endpoint does

    Examples:
        >>> href = 'https://alegna-api.nerevu.com/v1/data'
        >>> method = 'GET'
        >>> rule = '/v1/data'
        >>> get_rel(href, method, rule)
        'data'

        >>> method = 'DELETE'
        >>> get_rel(href, method, rule)
        'data_delete'

        >>> method = 'GET'
        >>> href = 'https://alegna-api.nerevu.com/v1'
        >>> rule = '/v1
        >>> get_rel(href, method, rule)
        'home'
    """
    if href == request.url and method == request.method:
        rel = "self"
    else:
        # check if route is a common route
        resourceName = get_resource_name(rule)
        rel = get_common_rel(resourceName, method)

        # add the method if not common or GET
        if not rel:
            rel = resourceName

            if method != "GET":
                rel = f"{rel}_{method.lower()}"

        # get params and add to rel
        params = get_params(rule)
        joined_params = "_".join(params)

        if joined_params:
            rel = f"{rel}_{joined_params}"

    return rel


def get_url_root():
    return request.url_root.rstrip("/")


def get_request_base():
    return request.base_url.split("/")[-1]


def gen_links(rules):
    """ Makes a generator of all endpoints, their methods,
    and their rels (strings representing purpose of the endpoint)

    Yields: (dict)

    Examples:
    >>> gen_links(rules)
    {"rel": "data", "href": f"https://alegna-api.nerevu.com/v1/data", "method": "GET"}
    """
    url_root = get_url_root()

    for r in rules:
        if "static" not in r.rule and "callback" not in r.rule and r.rule != "/":
            for method in r.methods - {"HEAD", "OPTIONS"}:
                href = f"{url_root}{r.rule}".rstrip("/")
                rel = get_rel(href, method, r.rule)
                yield {"rel": rel, "href": href, "method": method}


def get_links(rules):
    """ Sorts endpoint links alphabetically by their href
    """
    links = gen_links(rules)
    return sorted(links, key=lambda link: link["href"])


def parse_kwargs(app):
    form = request.form or {}
    args = request.args.to_dict()
    _kwargs = {**form, **args}
    kwargs = {k: parse(v) for k, v in _kwargs.items()}

    with app.app_context():
        for k, v in app.config.items():
            if k in APP_CONFIG_WHITELIST:
                kwargs.setdefault(k.lower(), v)

    return kwargs


def gen_config(app):
    with app.app_context():
        for k, v in app.config.items():
            if k in APP_CONFIG_WHITELIST:
                yield (k.lower(), v)


def parse_request():
    values = request.values or {}
    json = request.json or {}
    kwargs = {**values, **json}
    return {k: parse(v) for k, v in kwargs.items()}


# https://github.com/bloomberg/python-github-webhook
# https://github.com/carlos-jenkins/python-github-webhooks
# https://github.com/nickfrostatx/flask-hookserver
def check_signature(digest="sha256", signature_header="", webhook_secret="", **kwargs):
    if signature_header and webhook_secret:
        signature = request.headers.get(signature_header).encode("utf-8")

        if kwargs.get("split_signature"):
            signature = signature.split("=")[1]

        secret = webhook_secret.encode("utf-8")

        if kwargs.get("b64_encode"):
            mac_digest = hmac.digest(secret, request.data, digest)
            calculated_hmac = b64encode(mac_digest)
        else:
            mac = hmac.new(secret, request.data, digest)
            calculated_hmac = mac.hexdigest()

        is_valid = hmac.compare_digest(calculated_hmac, signature)
    else:
        is_valid = False

    return is_valid


def hash_text(**kwargs):
    return get_hash("{email}:{list}:{secret}".format(**kwargs))


def verify(hash="", **kwargs):
    return hmac.compare_digest(hash, hash_text(**kwargs))


def load_path(path, default=None):
    default = default or {}

    try:
        contents = load(path.open())
    except (JSONDecodeError, FileNotFoundError):
        contents = default

    return contents


def fetch_choice(choices):
    call(["say", "enter a value"])
    pos = None

    while pos is None:
        answer = input(f"{choices}: ")

        try:
            pos = int(answer or "0")
        except ValueError:
            logger.error(f"Invalid selection: {answer}.")

    return pos


def fetch_bool(message):
    call(["say", "enter a value"])
    valid = False

    while not valid:
        answer = input(f"{message} [Y/n]: ") or "y"

        try:
            valid = answer.lower() in {"y", "n"}
        except AttributeError:
            logger.error(f"Invalid selection: {answer}.")

    return answer


def extract_fields(record, *fields, **kwargs):
    item = DotDict(record)

    for field in fields:
        if "[" in field:
            split_field = field.split("[")
            real_field = split_field[0]
            pos = int(split_field[1].split("]")[0])
            values = item.get(real_field, [])

            try:
                value = values[pos]
            except IndexError:
                value = None
        else:
            value = item.get(field)

        yield (field, value)

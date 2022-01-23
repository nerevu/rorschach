# -*- coding: utf-8 -*-
""" app.api
~~~~~~~~~~~~
Provides endpoints for pulling orders from OpenCart (pricecloser.com) into Cloze.

Live Site:

Endpoints:
    Visit the live site for a list of all available endpoints
"""
import json
import os
import time

from datetime import date, datetime, timedelta
from itertools import cycle, dropwhile, islice

import requests

from flask import Blueprint, Flask, current_app as app, request, url_for
from flask.views import MethodView

from app import cache
from app.utils import get_links, get_request_base, jsonify, parse
from config import Config

blueprint = Blueprint("API", __name__)

# these don't change based on mode, so no need to do app.config['...']
RESTADMIN_ID = Config.OPENCART_RESTADMIN_ID
PREFIX = Config.API_URL_PREFIX
CLOZE_BASE_URL = Config.CLOZE_BASE_URL
CLOZE_EMAIL = Config.CLOZE_EMAIL
CLOZE_API_KEY = Config.CLOZE_API_KEY
CLOZE_ACCOUNT_MAP = Config.CLOZE_ACCOUNT_MAP
CLOZE_STAGES = Config.CLOZE_STAGES
PRICECLOSER_BASE_URL = Config.PRICECLOSER_BASE_URL
DATE_FORMAT = Config.DATE_FORMAT
CLOZE_AUTH_PARAMS = {"user": CLOZE_EMAIL, "api_key": CLOZE_API_KEY}

CLOZE_STAGES_MAPPING = {
    "people": {
        # TODO: always set the person to active (for create and update).
        # Come up with a better way to assign people stages sometime.
        # Currently, the issue is that a person can have a pending order
        # and a different processed order, so which status should he/she be?
        # The first or the second?
        "processed": CLOZE_STAGES["people"]["active"],
        "pending": CLOZE_STAGES["people"]["active"],
    },
    "projects": {
        "processed": CLOZE_STAGES["projects"]["done"],
        "pending": CLOZE_STAGES["projects"]["potential"],
        # TODO: couldn't find where these numbers are defined in PriceCloser. Keep looking.
        # These are order_status_ids that were deduced by looking at the orders
        # that are retrieved from the REST Admin API
        "15": CLOZE_STAGES["projects"]["done"],  # 15 (processed)
        "1": CLOZE_STAGES["projects"]["potential"],  # 1 (pending)
    },
}


PRICECLOSER_APPLINK_BASE_URL = "https://pricecloser.com/admin/index.php?route="
PRICECLOSER_HEADERS = {
    "X-Oc-Restadmin-Id": RESTADMIN_ID,
    # OpenCart will send a 406 (Mod_Security) error without a user agent
    "User-Agent": "PostmanRuntime/7.20.1",
}
HEADERS = {"Accept": "application/json"}
SOURCE = "pricecloser.com"

SHARE_TO_TEAMS = Config.SHARE_TO_TEAMS
ROUTE_TIMEOUT = Config.ROUTE_TIMEOUT
LRU_CACHE_SIZE = Config.LRU_CACHE_SIZE
FAILURE_TTL = Config.FAILURE_TTL

share_to = import_to = "team" if SHARE_TO_TEAMS else ""


def post_to_cloze(resource, verb, headers=None, **kwargs):
    url = f"{CLOZE_BASE_URL}/{resource}/{verb}"
    name = kwargs["name"]
    headers = headers or {}

    params = {**CLOZE_AUTH_PARAMS, "team": str(SHARE_TO_TEAMS).lower()}
    request_headers = {**HEADERS, **headers, "Content-Type": "application/json"}
    data = json.dumps(kwargs)
    r = requests.post(url, data=data, params=params, headers=request_headers)
    resp = r.json()
    okay = not resp["errorcode"]

    if okay:
        message = f"Successfully {verb}d {resource} '{name}'!"
        status_code = 200
        result = kwargs
    else:
        message = f"Error trying to {verb} {resource} '{name}'. "
        message += resp["message"]
        status_code = 500 if r.status_code == 200 else r.status_code
        result = {}

    return {
        "ok": okay,
        "message": message,
        "status_code": status_code,
        "result": result,
    }


def get_from_cloze(resource, result_field, **kwargs):
    url = f"{CLOZE_BASE_URL}/{resource}/get"
    name = kwargs["uniqueid"]
    params = {**CLOZE_AUTH_PARAMS, **kwargs}
    r = requests.get(url, params=params)
    resp = r.json()
    okay = not resp["errorcode"]

    if okay:
        message = f"Successfully got {resource} '{name}'!"
        result = resp[result_field]
        status_code = 200
    else:
        message = f"Error trying to get {resource} '{name}'. "
        message += resp["message"]
        result = {}
        status_code = 500 if r.status_code == 200 else r.status_code

    return {
        "ok": not resp["errorcode"],
        "message": message,
        "result": result,
        "status_code": status_code,
    }


def gen_manufacturers(products):
    for product in products:
        product_url = f"{PRICECLOSER_BASE_URL}/products/{product['product_id']}"
        r = requests.get(product_url, headers=PRICECLOSER_HEADERS)
        resp = r.json()

        if not resp["error"]:
            yield resp["data"]["manufacturer"]


def get_stage(status, cloze_area):
    def_stage = CLOZE_STAGES[cloze_area]["active"]
    return CLOZE_STAGES_MAPPING[cloze_area].get(status.lower(), def_stage)


def get_cloze_customer(order):
    kwargs = {"uniqueid": order["email"], "team": str(SHARE_TO_TEAMS).lower()}
    return get_from_cloze("people", "person", **kwargs)


def get_cloze_order(order):
    kwargs = {
        "uniqueid": f"{SOURCE}:{order['order_id']}",
        "team": str(SHARE_TO_TEAMS).lower(),
    }
    return get_from_cloze("projects", "project", **kwargs)


def create_customer(**kwargs):
    return post_to_cloze("people", "create", **kwargs)


def create_order(**kwargs):
    return post_to_cloze("projects", "create", **kwargs)


def update_customer(**kwargs):
    return post_to_cloze("people", "update", **kwargs)


def update_order(**kwargs):
    return post_to_cloze("projects", "update", **kwargs)


def gen_order_ids(cloze_order):
    yield f"{SOURCE}:{cloze_order['name']}"

    if cloze_order.get("direct"):
        yield f"direct:{cloze_order['direct']}"


def get_order_value(cloze_order):
    return {
        "name": cloze_order["name"],
        "type": "project",
        "ids": list(gen_order_ids(cloze_order)),
    }


def get_order_data(cloze_order):
    return {
        "id": CLOZE_ACCOUNT_MAP["orders_link"],
        "type": "projects",
        "value": get_order_value(cloze_order),
    }


def get_order_status(order):
    # defaults to pending status (order_status_id=1)
    return order.get("order_status", str(order.get("order_status_id", 1)))


def create_customer_data(pricecloser_order, cloze_area):
    customer_id, email_is_id = get_customer_id(pricecloser_order)
    order_id = pricecloser_order["order_id"]
    order_status = get_order_status(pricecloser_order)
    first_name = pricecloser_order["payment_firstname"]
    last_name = pricecloser_order["payment_lastname"]

    customer_data = {
        "name": f"{first_name} {last_name}",
        "headline": f"PriceCloser Customer - Order {order_id}",
        "stage": get_stage(order_status, cloze_area),
        # shareTo must be set to team if you want your team
        # to be able to see this customer
        "shareTo": share_to,
        "segment": CLOZE_ACCOUNT_MAP["customer_segment"],
        "phones": [
            {
                # Telephone numbers are dropped if they are not a valid telephone number for the US.
                # This is based on a Google common library for checking phone numbers.
                "value": pricecloser_order["telephone"]
            }
        ],
        "emails": [
            {
                # Cloze automatically tries to determine if an email address is
                # a bulk email (like sales@technoformers.net) and it doesn't add it
                # if it determines that it's not a real-ish email address.
                "value": pricecloser_order["email"]
            }
        ],
        "customFields": [
            {
                "id": CLOZE_ACCOUNT_MAP["lead_source"],
                "type": "keywords",
                "value": "website",
            },
        ],
        "appLinks": [
            {
                "source": SOURCE,  # must always be the same
                "uniqueid": customer_id,
                "label": "PriceCloser Customer",
                "url": f"{PRICECLOSER_APPLINK_BASE_URL}customer/customer/edit&customer_id={customer_id}",
            }
        ],
    }

    if email_is_id:
        url = f"{PRICECLOSER_APPLINK_BASE_URL}sale/order/info&order_id={order_id}"
        customer_data["appLinks"][0]["url"] = url

    return customer_data


def customer_to_order_data(pricecloser_order, customer):
    # Multiple customers can't be associated with one order,
    # so we are ok to replace the value of the "customer" customField.
    order_id = str(pricecloser_order["order_id"])

    return {
        "importTo": import_to,
        "name": order_id,
        "customFields": [
            {
                "id": CLOZE_ACCOUNT_MAP["customer_link"],
                "type": "contact",
                "value": {
                    "name": customer["name"],
                    "email": pricecloser_order["email"],
                },
            }
        ],
        "appLinks": [
            {
                "source": SOURCE,  # must always be the same
                "uniqueid": order_id,
                "label": "PriceCloser Order",
                "url": f"{PRICECLOSER_APPLINK_BASE_URL}sale/order/info&order_id={order_id}",
            }
        ],
    }


def create_order_data(pricecloser_order, manufacturers, customer=None):
    # map order_status to cloze stage
    order_status = get_order_status(pricecloser_order)
    stage = get_stage(order_status, "projects")
    order_id = str(pricecloser_order["order_id"])
    customer_id = get_customer_id(pricecloser_order)[0]
    date_added = pricecloser_order["date_added"]
    total = pricecloser_order["total"]

    custom_fields = [
        {"id": CLOZE_ACCOUNT_MAP["value"], "type": "currency", "value": total},
        {"id": CLOZE_ACCOUNT_MAP["amount"], "type": "decimal", "value": total},
        {"id": CLOZE_ACCOUNT_MAP["order_num"], "type": "text", "value": order_id},
        {
            "id": CLOZE_ACCOUNT_MAP["manufacturers"],
            "type": "text",
            "value": manufacturers,
        },
    ]

    if CLOZE_ACCOUNT_MAP.get("planned_start"):
        custom_fields.append(
            {
                "id": CLOZE_ACCOUNT_MAP["planned_start"],
                "type": "date",
                "value": date_added,
            }
        )

    if CLOZE_ACCOUNT_MAP.get("customer_num"):
        custom_fields.append(
            {
                "id": CLOZE_ACCOUNT_MAP["customer_num"],
                "type": "text",
                "value": customer_id,
            }
        )

    if customer:
        custom_fields.append(
            {
                "id": CLOZE_ACCOUNT_MAP["customer_link"],
                "type": "contact",
                "value": {
                    "name": customer["name"],
                    "email": pricecloser_order["email"],
                },
            }
        )

    # get request parameters
    order_data = {
        "name": order_id,
        "summary": manufacturers,
        "importTo": import_to,
        # The project will only show up under your personal projects if you are a member of the `deal team`.
        # You can set `deal team` members by setting the projectTeam field to an array of email addresses
        # (e.g. "projectTeam": ["msotto@nerevu.com", "rcummings@nerevu.com"]).
        "projectTeam": [],
        "stage": stage,
        "segment": CLOZE_ACCOUNT_MAP["project_segment"],
        "createdDate": date_added,
        "customFields": custom_fields,
        "appLinks": [
            {
                "source": SOURCE,  # must always be the same
                "uniqueid": order_id,  # uniqueid must be a string
                "label": "PriceCloser Order",
                "url": f"{PRICECLOSER_APPLINK_BASE_URL}sale/order/info&order_id={order_id}",
            }
        ],
    }

    return order_data


def get_customer_id(pricecloser_order):
    email_is_id = pricecloser_order["customer_id"] in {"0", 0}
    key = "email" if email_is_id else "customer_id"
    customer_id = pricecloser_order[key]
    return str(customer_id), email_is_id


def add_customer(pricecloser_order):
    # check if customer exists, create if doesn't
    customer_response = get_cloze_customer(pricecloser_order)

    if customer_response["ok"]:
        # TODO: check that retrieved name is the same as pricecloser name (update if not)
        response = customer_response
    else:
        customer_data = create_customer_data(pricecloser_order, "people")
        response = create_customer(**customer_data)
        response["result"] = customer_data if response["ok"] else {}

    return response


def add_order(pricecloser_order, customer):
    # check if order exists, create if doesn't
    order_response = get_cloze_order(pricecloser_order)
    okay = order_response["ok"]

    if okay and customer:
        # make sure customer was added to order, add if not
        possible_ids = {
            f"direct:{customer.get('direct')}",
            pricecloser_order["email"],
            f"{SOURCE}:{get_customer_id(pricecloser_order)[0]}",
        }

        for field in order_response["result"].get("customFields", []):
            customer_link = CLOZE_ACCOUNT_MAP["customer_link"]

            if field["id"] == customer_link:
                if possible_ids.intersection(field["value"]["ids"]):
                    response = order_response
                    break
        else:
            order_data = customer_to_order_data(pricecloser_order, customer)
            response = update_order(**order_data)
    elif customer:
        _manufacturers = gen_manufacturers(pricecloser_order["products"])
        manufacturers = ", ".join(set(_manufacturers))
        order_data = create_order_data(pricecloser_order, manufacturers, customer)
        response = create_order(**order_data)
        response["result"] = order_data
    else:
        response = order_response
        response["result"] = {}

    return response


def add_order_to_customer(cloze_order, customer):
    # check if order is attached to cloze customer, attach if not
    order_name = cloze_order["name"]
    custom_fields = customer.get("customFields", [])
    pairs = enumerate(custom_fields)
    fields_by_id = {field["id"]: (pos, field) for pos, field in pairs}
    pos, orders = fields_by_id.get(CLOZE_ACCOUNT_MAP["orders_link"], (0, {}))
    message = ""

    if orders:
        unique_order_id = f"{SOURCE}:{order_name}"

        for attached_order in orders["value"]:
            contains_order_id = unique_order_id in attached_order["ids"]
            same_order_name = order_name == attached_order["name"]

            if contains_order_id or same_order_name:
                contains_order = True
                break
        else:
            contains_order = False
    else:
        contains_order = False

    if orders and not contains_order:
        order_value = get_order_value(cloze_order)
        customer["customFields"][pos]["value"].append(order_value)
    elif not orders:
        order_data = get_order_data(cloze_order)

        if not customer.get("customFields"):
            customer["customFields"] = []

        customer["customFields"].append(order_data)

    if not contains_order:
        customer["shareTo"] = share_to
        response = update_customer(**customer)
        contains_order = response["ok"]
        message = response["message"]

        if not response["ok"]:
            message += " Please add order manually."

    return {"ok": contains_order, "message": message}


def add_customer_and_order(pricecloser_order, sleep=0):
    ##################################################################
    # TODO: The Cloze system doesn't always update people and projects
    # before I call the `get person` or `get project` endpoints again.
    # This causes updates to either to get overwritten by the next
    # project/person that comes from pricecloser. The sleep function
    # below has solved the problem, but a more elegant solution should
    # eventually be created.
    ##################################################################
    time.sleep(sleep)

    customer_response = add_customer(pricecloser_order)

    if customer_response["ok"]:
        customer = customer_response["result"]
        order_response = add_order(pricecloser_order, customer)

        if order_response["ok"]:
            cloze_order = order_response["result"]
            response = add_order_to_customer(cloze_order, customer)
        else:
            response = order_response
    else:
        response = customer_response

    return response


def get_pc_orders(order_id=None, start=None, end=None):
    if order_id:
        order_url = f"{PRICECLOSER_BASE_URL}/orders/{order_id}"
        end_date = None
    else:
        # TODO: make sure this is working
        end = end or date.today().strftime(DATE_FORMAT)
        end_date = datetime.strptime(end, DATE_FORMAT)
        next_day = end_date + timedelta(days=1)
        pricecloser_end = (next_day).strftime(DATE_FORMAT)

        if not start:
            num_months_back = app.config["REPORT_MONTHS"]
            args = (end_date, num_months_back)
            start = get_start_date(*args).strftime(DATE_FORMAT)

        order_url = f"{PRICECLOSER_BASE_URL}/orders/details/added_from/{start}/added_to/{pricecloser_end}"

    r = requests.get(order_url, headers=PRICECLOSER_HEADERS)
    resp = r.json()
    result = resp["data"]
    okay = not resp["error"]

    if okay and order_id:
        message = f"Successfully fetched PriceCloser order '{order_id}'"
    elif okay:
        message = f"Successfully fetched PriceCloser orders from {start} to {pricecloser_end}!"
    elif order_id:
        message = f"PriceCloser order '{order_id}' not found!"
    else:
        message = f"No PriceCloser orders from {start} to {pricecloser_end} found!"

    if not okay:
        message += resp["error"][0]

    if okay:
        status_code = 200
    elif r.status_code == 200:
        status_code = 500
    else:
        status_code = r.status_code

    return {
        "ok": okay,
        "result": result,
        "message": message,
        "status_code": status_code,
        "end_date": end_date,
    }


def get_job_response(job):
    return {
        "job_id": job.id,
        "job_status": job.get_status(),
        # TODO: this doesn't list the port in when run without app context
        "url": url_for(".result", job_id=job.id, _external=True),
        "ok": job.get_status() != "failed",
    }


def transfer_orders(order_id=None, start=None, end=None, **kwargs):
    """NOTE: The REST Admin API is not inclusive of the end date that a person sends,
    so one day is added to the `end` parameter to make this endpoint inclusive.
    """
    # If a date range is provided as parameters to this endpoint (start and end),
    # then the dates will not be set in the cache. This is because a date range may
    # be specified that doesn't bring in orders that were created earlier than this
    # date range, and if the cache was set to start after the specified date range,
    # this endpoint would never bring in the older orders.
    order_response = get_pc_orders(order_id, start, end)
    enqueue = kwargs.get("enqueue")
    failure_ttl = kwargs.get("failure_ttl", FAILURE_TTL)

    if order_response["ok"]:
        result = order_response["result"]

        if order_id and enqueue:
            job = q.enqueue(add_customer_and_order, result, failure_ttl=failure_ttl)
            response = get_job_response(job)
        elif order_id:
            response = add_customer_and_order(result)
        else:
            num_orders = len(result)
            response = {}

            for pricecloser_order in result:
                order_id = str(pricecloser_order["order_id"])

                if cache.get(order_id):
                    continue
                elif enqueue:
                    job = q.enqueue(
                        add_customer_and_order,
                        pricecloser_order,
                        10,
                        failure_ttl=failure_ttl,
                    )
                    response = get_job_response(job)
                else:
                    response = add_customer_and_order(pricecloser_order, 10)

                if response["ok"]:
                    cache.set(order_id, True)
                else:
                    break
            else:
                # TODO: think about tracking by order number in the future so
                # we don't have to rerun a whole batch of successful orders if
                # one fails.
                verb = "enqueued" if enqueue else "added"
                message = f"Successfully {verb} {num_orders} orders to Cloze."
                response["message"] = message

    else:
        response = order_response

    return response


def last_day_of_month(month, year):
    """
    >>> last_day_of_month(12, 2020)
    31
    >>> last_day_of_month(11, 2020)
    30
    >>> last_day_of_month(10, 2020)
    31
    >>> last_day_of_month(1, 2020)
    31
    """
    _year = year + 1 if month == 12 else year
    _month = 1 if month == 12 else month + 1
    last_date = date(_year, _month, 1) - timedelta(days=1)
    return last_date.day


def get_start_date(end_date, num_months_back):
    """
    Get the same day 'X' number of months ago.

    >>> end_date = date(2019, 6, 13)
    >>> get_start_date(end_date, 1)
    datetime.date(2019, 5, 13)
    >>> get_start_date(end_date, 6)
    datetime.date(2018, 12, 13)
    >>> get_start_date(end_date, 12)
    datetime.date(2018, 6, 13)
    >>> get_start_date(end_date, 26)
    datetime.date(2017, 4, 13)
    """
    if num_months_back > end_date.month:
        _end_date = get_start_date(end_date, end_date.month)
        start_date = get_start_date(_end_date, num_months_back - end_date.month)
    else:
        if num_months_back == end_date.month:
            year, month = end_date.year - 1, 12
        else:
            year, month = end_date.year, end_date.month - num_months_back

        last_day = last_day_of_month(month, year)
        day = min(end_date.day, last_day)
        start_date = date(year, month, day)

    return start_date


###########################################################################
# ROUTES
###########################################################################
@blueprint.route("/")
@blueprint.route(PREFIX)
def root():
    response = {
        "message": "Welcome to the ClozeCart API!",
        "links": get_links(app.url_map.iter_rules()),
    }
    return jsonify(**response)


class Order(MethodView):
    def get(self, order_id):
        info = {
            "description": "Get a Cloze customer for a PriceCloser order",
            "links": get_links(app.url_map.iter_rules()),
        }

        order_response = get_pc_orders(order_id)

        if order_response["ok"]:
            pricecloser_order = order_response["result"]
            response = get_cloze_customer(pricecloser_order)
        else:
            response = order_response

        response.update(info)
        return jsonify(**response)

    def patch(self, order_id):
        info = {"description": "Transfer a PriceCloser order to Cloze"}
        kwargs = {k: parse(v) for k, v in request.args.to_dict().items()}
        response = transfer_orders(order_id, **kwargs)
        response.update(info)
        return jsonify(**response)

    def post(self, start=None, end=None):
        info = {"description": "Transfer PriceCloser orders to Cloze"}
        kwargs = {k: parse(v) for k, v in request.args.to_dict().items()}
        response = transfer_orders(start=start, end=end, **kwargs)
        response.update(info)
        return jsonify(**response)


@blueprint.route(f"{PREFIX}/result/<string:job_id>")
def result(job_id):
    """Displays a job result.

    Args:
        job_id (str): The job id.
    """
    job = q.fetch_job(job_id)
    statuses = {
        "queued": 202,
        "started": 202,
        "finished": 200,
        "failed": 500,
        "job not found": 404,
    }

    if job:
        job_status = job.get_status()
        job_result = job.result
    else:
        job_status = "job not found"
        job_result = {}

    response = {
        "status_code": statuses[job_status],
        "job_id": job_id,
        "job_status": job_status,
        "result": job_result,
        "links": get_links(app.url_map.iter_rules()),
    }

    return jsonify(**response)


@blueprint.route(f"{PREFIX}/update")
def update(pid=None):
    kwargs = {k: parse(v) for k, v in request.args.to_dict().items()}
    sync = kwargs.get("sync")

    with app.app_context():
        if sync:
            resp = {"result": func(*fargs, **fkwargs)}
        else:
            job = q.enqueue(func, *fargs, **fkwargs)
            result_url = "%s/result/%s/" % (base, job.id)

            resp = {
                "job_id": job.id,
                "job_status": job.get_status(),
                "result_url": result_url,
            }

        return jsonify(**resp)


# https://stackoverflow.com/a/13381847/408556
# https://api.cloze.com/api-docs/#!
user = "rcummings@nerevu.com"
api_key = "1d09549cde5082212e1c0fc1f0530d5c"
scope = "team"
stage = "lead"
segment = "customer"
changes = "false"
api_base = "https://api.cloze.com/v1"


@blueprint.route("/")
def companies():
    params = {
        "user": user,
        "api_key": api_key,
        "scope": scope,
        "stage": stage,
        "segment": segment,
        "includeauditedchanges": changes,
    }

    route = f"{api_base}/companies/feed"
    r = requests.get(route, params=params)
    return jsonify(r.json())


@blueprint.route("/people")
def people():
    params = {
        "user": user,
        "api_key": api_key,
        "scope": scope,
        "stage": stage,
        "segment": segment,
        "includeauditedchanges": changes,
    }

    route = f"{api_base}/people/feed"
    r = requests.get(route, params=params)
    return jsonify(r.json())


if __name__ == "__main__":
    app.run(debug=True)

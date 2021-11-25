# -*- coding: utf-8 -*-
""" app.api
~~~~~~~~~~~~
Provides endpoints for authenticating with and pulling data from quickbooks.

Live Site:
    https://alegna-api.nerevu.com/v1

Endpoints:
    Visit the live site for a list of all available endpoints
"""
import random
import re
import sys

import gspread
import requests

from datetime import date
from datetime import datetime as dt
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from functools import lru_cache
from pathlib import Path
from traceback import format_exception
from urllib.parse import parse_qsl, urlencode, urlparse
from json.decoder import JSONDecodeError

from faker import Faker
from flask import Blueprint, after_this_request
from flask import current_app as app
from flask import redirect, request, session, url_for
from flask.views import MethodView
from gspread.exceptions import APIError

from config import Config
from app import cache, __version__
from app.utils import (
    responsify,
    jsonify,
    parse,
    cache_header,
    make_cache_key,
    uncache_header,
    title_case,
    get_common_rel,
)

from oauth2client.service_account import ServiceAccountCredentials
from oauthlib.oauth2 import TokenExpiredError
from requests_oauthlib import OAuth2Session

from meza import io, process as pr, convert as cv
from app.authclient import get_auth_client

# https://requests-oauthlib.readthedocs.io/en/latest/index.html
# https://oauth-pythonclient.readthedocs.io/en/latest/index.html

DEF_NAME = "N/A"
DEF_PERIOD = "N/A"

# Create the API Blueprint
blueprint = Blueprint("API", __name__)
headers = {"Accept": "application/json"}
fake = Faker()

# Get credentials for Google Sheets
scope = [
    "https://spreadsheets.google.com/feeds",
    "https://www.googleapis.com/auth/drive",
]
p = Path("Clients-6c78ad96c4d5.json")
credentials = ServiceAccountCredentials.from_json_keyfile_name(p.resolve(), scope)
gc = gspread.authorize(credentials)

# Constants
ROUTE_TIMEOUT = Config.ROUTE_TIMEOUT
SET_TIMEOUT = Config.SET_TIMEOUT
LRU_CACHE_SIZE = Config.LRU_CACHE_SIZE
PREFIX = Config.API_URL_PREFIX
NUM_MONTHS = Config.REPORT_MONTHS


def get_request_base():
    """ Gets the resource name (e.g. if `https://alegna-api.nerevu.com/v1/status?param1=value' is the
    request.base_url, `status` is returned
    """
    route_path = urlparse(request.base_url).path.split("/")
    return next(rp for rp in route_path if rp and rp not in PREFIX)


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
        >>> get_params(rule)
        ['path', 'status_type']
    """
    # param regexes
    param_with_colon = r"<.+?:(.+?)>"
    param_no_colon = r"<(.+?)>"
    either_param = param_with_colon + r"|" + param_no_colon

    parameter_matches = re.findall(either_param, rule)
    return ["".join(match_tuple) for match_tuple in parameter_matches]


def get_rel(href, method, rule):
    """ Returns the `rel` of an endpoint (see `Returns` below).

    If the rule is a common rule as specified in the utils.py file, then that rel is returned.

    If the current url is the same as the href for the current route, `self` is returned.

    Args:
        href (str): the full url of the endpoint (e.g. https://alegna-api.nerevu.com/v1/data)
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
        if params:
            joined_params = "_".join(params)
            rel = f"{rel}_{joined_params}"

    return rel


def gen_links():
    """ Makes a generator of all endpoints, their methods, and their rels (strings representing purpose of the endpoint)

    Yields:
        (dict): Example - {"rel": "data", "href": f"https://alegna-api.nerevu.com/v1/data", "method": "GET"}
    """
    url_root = request.url_root.rstrip("/")
    # loop through endpoints
    for r in app.url_map.iter_rules():
        # don't show some routes
        if "static" not in r.rule and "callback" not in r.rule and r.rule != "/":
            # loop through relevant methods
            for method in r.methods - {"HEAD", "OPTIONS"}:
                href = url_root + r.rule
                rel = get_rel(href, method, r.rule)
                yield {"rel": rel, "href": href, "method": method}


def sort_links(links):
    """ Sorts endpoint links alphabetically by their href
    """
    return sorted(links, key=lambda link: link["href"])


@lru_cache(maxsize=LRU_CACHE_SIZE)
def parse_date(date_str):
    """ Creates a date object from a date string.

    Args:
        date_str (str): e.g. '2018-12-31'

    Returns:
        (date object): e.g.

    Examples:
        >>> parse_date('2018-12-01')
        datetime.date(2018, 12, 1)
    """
    return date(*map(int, date_str.split("-")))


#######################################################
# TODO: Continue DocBlocks and DocTests Below Here
#######################################################
def gen_records(response):
    """ Creates a simpler dictionary using the Headers and Data from the QuickBooks API.

    Args:
        response (dict): response object from QuickBooks with transaction data. The "links" attribute was added by our code.
            {
                "Columns": {
                    "Column": [
                        { "ColTitle": "Date", "ColType": "tx_date" },
                        {...}
                    ]
                },
                "Rows": {
                    "Row": [
                        {
                            "ColData": [
                                { "value": "30.18" },
                                {...}
                            ],
                            "type": "Data"

                        },
                        ...
                    ]
                }
                "Header": {...}
                "links": [{...},]
            }

    Yields:
        (dict): keys and values are matched from column headers and column row data.
            {
                'A/P Paid': '',
                'A/R Paid': '',
                'Account': 'Plum Card-01084',
                'Amount': '30.18',
                'Clr': 'R',
                'Date': '2018-12-01',
                'Memo/Description': 'JULIAN WASHINGTON-0...463978051',
                'Name': '',
                'Num': '',
                'PO #s': '',
                'Posting': 'Yes',
                'Rating/Interact': '',
                'Sales Rep': '',
                'Split': 'Cost of Goods Sold',
                'Taxable Amount': '.00',
                'Tracking #': '',
                "Transaction Type": "Expense"
            }
    """
    keys = [column["ColTitle"] for column in response["Columns"]["Column"]]

    for row in response["Rows"]["Row"]:
        values = [r["value"] for r in row["ColData"]]
        yield dict(zip(keys, values))


def gen_ranges(start=None, prev_end=None, num_months=NUM_MONTHS):
    """ A recursive generator function that yields tuples containing the
    starting and ending dates of each month for the past `num_months` months.

    Args:
        start (date or None): the starting date
        prev_end (date or None): the previous ending date of the month
            of the last month calculated
        num_months (int): how many months back to calculate

    Yields:
        (tuple):
            month_start (str): the start of a month
            month_start (date): the start of a month
            month_end (str): the end of a month or the
                current date (if for this month)
    """
    month_end = start or prev_end - timedelta(days=prev_end.day)
    month_start = date(month_end.year, month_end.month, 1)

    if num_months:
        yield (month_start.strftime("%m-%Y"), month_start, month_end)

    if num_months > 1:
        yield from gen_ranges(prev_end=month_end, num_months=num_months - 1)


def get_period(invoice_date, date_ranges):
    """ Returns the period ('month-year') that the invoice_date falls into.

    Args:
        invoice_date (datetime.date): the date the invoice was retrieved
            Example: datetime.date(2018, 12, 31)
        date_ranges (list of tuples): a period ('month-year'), and date ranges for that period
            Example: [
                ('11-2019', datetime.date(2019, 11, 1), datetime.date(2019, 11, 1)),
                ...
            ]

    Returns:
        period (str): the period that the invoice_date is a part of (e.g. '12-2018')
    """
    for period, month_start, month_end in date_ranges:
        if month_end >= invoice_date >= month_start:
            return period


def extract_nums(raw_range):
    start, end = map(int, raw_range.split("-"))
    num_range = range(start, end + 1)
    return map(str, num_range)


def gen_po_nums(numbers):
    for num in numbers:
        stripped = num.lstrip("tf-").strip()

        if "-" in stripped:
            yield from extract_nums(stripped)
        elif stripped:
            yield stripped


def parse_custom_fields(invoice):
    try:
        sales_rep, contract_num = invoice.get("Sales Rep/Ord #").split(",")
    except (ValueError, AttributeError):
        sales_rep = invoice.get("Sales Rep/Ord #") or DEF_NAME
        contract_num = None
    else:
        sales_rep = sales_rep or DEF_NAME

    try:
        _rating, _interact = invoice.get("Rating/Interact").split(",")
    except (ValueError, AttributeError):
        rating = interaction_score = None
    else:
        rating = Decimal(_rating.strip()) if _rating else None
        interaction_score = Decimal(_interact.strip()) if _interact else None

    parsed = {
        "Sales Rep": title_case(sales_rep),
        "Contract #": contract_num,
        "Rating": rating,
        "Interaction Score": interaction_score,
    }

    return {**invoice, **parsed}


def process_invoices(invoices, purchases_by_num, source):
    date_ranges = list(gen_ranges(date.today()))
    sheet = gc.open_by_key(app.config["GOOGLE_SHEET_ID"])

    try:
        worksheet = sheet.worksheet("plans")
    except APIError as err:
        # This version of the Google Sheets API has a limit of 500 requests per 100 seconds per project, and 100 requests per 100 seconds per user.
        print(err)
        # error = e.errors[0]
        # return {"status_code": error.code, "message": error.message}
        commission_rate = Decimal("0.14")
    else:
        commission_rate = Decimal(worksheet.acell("G11").value.strip("%")) / 100

    rating_weight, interaction_weight = get_commission_score_weights()
    standardized_transactions = map(parse_custom_fields, invoices)
    weighted_sales_transactions = calculate_weighted_avg_sales(
        standardized_transactions
    )

    for invoice in weighted_sales_transactions:
        invoice_date = parse_date(invoice["Date"])
        period = get_period(invoice_date, date_ranges)

        if period:
            errors = []
            paid = invoice["A/R Paid"] == "Paid"

            if not paid:
                errors.append("Invoice unpaid.")

            numbers = invoice.get("PO #s", "").split(",")
            po_nums = list(gen_po_nums(numbers))

            if not po_nums:
                errors.append("No purchase order.")

            contract_num = invoice["Contract #"]

            if not contract_num:
                errors.append("No contract.")

            invoice_amount = Decimal(invoice["Amount"])

            try:
                invoice_number = int(invoice["Num"]) if invoice.get("Num") else None
            except ValueError:
                print(f"Error converting '{invoice_number}' to int.")
                invoice_number = None

            invoice_purchases = [
                purchases_by_num[num] for num in po_nums if purchases_by_num.get(num)
            ]

            missing_po_nums = [num for num in po_nums if not purchases_by_num.get(num)]

            if missing_po_nums:
                errors.append("Purchase order missing.")

            cost = sum(Decimal(purchase["Amount"]) for purchase in invoice_purchases)
            profit = invoice_amount - cost
            if profit < 0:
                profit = 0
            commission = profit * commission_rate

            yield {
                "Paid": invoice["A/R Paid"] == "Paid",
                "Invoice Number": invoice_number,
                "Invoice Source": source,
                "Invoice Amount": str(invoice_amount),
                "Cost of Goods": str(cost),
                "Profit": str(profit),
                "Commission Due": str(commission),
                "Invoice Date": invoice["Date"],
                "Invoice Month Num": invoice_date.month,
                "Invoice Month": invoice_date.strftime("%B"),
                "Invoice Period": period,
                "PO Numbers": ", ".join(po_nums),
                "Contract Number": contract_num,
                "Missing POs": ", ".join(missing_po_nums),
                # "Payment Date": payment["Date"],
                # "Payment Period": payment["Date"],
                "Sales Rep": invoice["Sales Rep"],
                "Rating": invoice["Rating"],
                "Rating Weight": rating_weight,
                "Interaction Score": invoice["Interaction Score"],
                "Interaction Weight": interaction_weight,
                "Errors": " ".join(errors),
                "Sale": invoice["Sale"],
                "Upsell": invoice["Upsell"],
                "Sales Weight": invoice["Sales Weight"],
                "Upsell Weight": invoice["Upsell Weight"],
                "Period Sales": invoice["Period Sales"],
                "Period Upsells": invoice["Period Upsells"],
                "Period Weighted Sales": invoice["Period Weighted Sales"],
                "Period Weighted Upsells": invoice["Period Weighted Upsells"],
                "Period Weighted Average Sales": invoice[
                    "Period Weighted Average Sales"
                ],
                "Rep Period Sales": invoice["Rep Period Sales"],
                "Rep Period Upsells": invoice["Rep Period Upsells"],
                "Rep Period Weighted Sales": invoice["Rep Period Weighted Sales"],
                "Rep Period Weighted Upsells": invoice["Rep Period Weighted Upsells"],
                "Rep Period Weighted Average Sales": invoice[
                    "Rep Period Weighted Average Sales"
                ],
            }


def get_sales_upsell_weights():
    sheet = gc.open_by_key(app.config["GOOGLE_SHEET_ID"])

    try:
        worksheet = sheet.worksheet("factors")
    except APIError as err:
        # This version of the Google Sheets API has a limit of 500 requests per 100 seconds per project, and 100 requests per 100 seconds per user.
        print(err)
        # error = e.errors[0]
        # return {"status_code": error.code, "message": error.message}
        sales_weight = Decimal("0.7")
        upsell_weight = Decimal("0.3")
    else:
        sales_weight = Decimal(worksheet.acell("F2").value.strip("%")) / 100
        upsell_weight = Decimal(worksheet.acell("F3").value.strip("%")) / 100

    return sales_weight, upsell_weight


def get_commission_score_weights():
    sheet = gc.open_by_key(app.config["GOOGLE_SHEET_ID"])

    try:
        worksheet = sheet.worksheet("factors")
    except APIError as err:
        # This version of the Google Sheets API has a limit of 500 requests per 100 seconds per project, and 100 requests per 100 seconds per user.
        print(err)
        rating_weight = Decimal(2 / 3)
        number_interactions_weight = Decimal(1 / 3)
    else:
        rating_weight = Decimal(worksheet.acell("F4").value.strip("%")) / 100
        number_interactions_weight = (
            Decimal(worksheet.acell("F5").value.strip("%")) / 100
        )

    return rating_weight, number_interactions_weight


def get_qb_error(fault):
    error = fault["error"][0]
    detail = error["detail"]
    expired = detail and detail.startswith("Token expired")
    unauthenticated = fault["type"] == "AUTHENTICATION"

    if expired or unauthenticated:
        auth_client = get_auth_client("QB", **app.config)
        auth_client.renew_token()
        # TODO: do these errors ever get cleared out? Is this a good check?
        if auth_client.error:
            response = {"status_code": 401, "message": f"Error: {auth_client.error}"}
        else:
            response = {"status_code": 200, "message": "Token was renewed!"}
    else:
        err_message = error["message"]
        _response = dict(pair.split("=") for pair in err_message.split("; "))
        _message = _response["message"]
        message = f"{_message}: {detail}" if detail else _message
        response = {"status_code": int(_response["statusCode"]), "message": message}

    return response


def get_status(status_type, retries=3):
    auth_client = get_auth_client("QB", **app.config)
    base_uri = f"{app.config['QB_API_BASE_URL']}/company/{auth_client.realm_id}"

    routes = {
        "company": f"{base_uri}/companyinfo/{auth_client.realm_id}",
        "auth": None,
    }

    if status_type in routes:
        route = routes[status_type]

        if route:
            qbo = auth_client.oauth_session

            if qbo:
                r = qbo.get(route, headers=headers)
                response = r.json()

                if response.get("fault"):
                    response = get_qb_error(response["fault"])

                    if response["status_code"] == 200 and retries:
                        response = get_status(status_type, retries - 1)
                else:
                    response["status_code"] = 200
            else:
                response = {
                    "status_code": 401,
                    "message": f"auth_client.oauth_session failed. Error: {auth_client.error}",
                }
        else:
            response = {"status_code": 200, "stream": auth_client.oauth_session.stream}
    else:
        response = {"status_code": 404, "message": "Route not found"}

    return response


def get_realtime_report_data(report_type, retries=3):
    auth_client = get_auth_client("QB", **app.config)
    #######################################################
    # TODO: allow this to be set
    date_ranges = list(gen_ranges(date.today()))
    start = date_ranges[0][2].strftime("%Y-%m-%d")
    end = date_ranges[len(date_ranges) - 1][1].strftime("%Y-%m-%d")
    #######################################################

    # https://developer.intuit.com/app/developer/qbo/docs/api/accounting/report-entities/transactionlist
    # sales_cust1 - PO #s
    # sales_cust2 - Sales Rep/Ord # (comma separated - e.g. "Reuben,abcdefg")
    # sales_cust3 - Rating/Interact (comma separated - e.g. ".7,.8")
    options = f"start_date={start}&end_date={end}&columns=account_name,doc_num,is_ar_paid,is_ap_paid,is_cleared,is_no_post,memo,name,other_account,sales_cust1,sales_cust2,sales_cust3,tracking_num,tx_date,txn_type,subt_nat_amount,net_amount"

    base_uri = f"{app.config['QB_API_BASE_URL']}/company/{auth_client.realm_id}/reports/TransactionList?{options}"

    routes = {
        "all": base_uri,
        "invoice": f"{base_uri}&transaction_type=Invoice&arpaid=All",
        # po only returns payments for some reason
        "po": f"{base_uri}&transaction_type=PurchaseOrder&appaid=All",
        "payment": f"{base_uri}&transaction_type=ReceivePayment",
    }

    if report_type in routes:
        route = routes[report_type]
        qbo = auth_client.oauth_session

        if qbo and auth_client.realm_id:
            r = qbo.get(route, headers=headers)

            try:
                response = r.json()
            except JSONDecodeError:
                status_code = 401 if "Authentication Failure" in r.text else 500
                response = {"status_code": status_code, "message": r.text}
            else:
                if response.get("fault"):
                    response = get_qb_error(response["fault"])

                    if response["status_code"] == 200 and retries:
                        response = get_realtime_report_data(report_type, retries - 1)
                else:
                    response["status_code"] = 200
        else:
            response = {
                "status_code": 500,
                "message": f"auth_client.oauth_session failed. Error: {auth_client.error}",
            }
    else:
        response = {"status_code": 404, "message": "Route not found"}

    response["links"] = sort_links(gen_links())
    return response


@lru_cache(maxsize=LRU_CACHE_SIZE)
def get_report_data(report_type):
    return get_realtime_report_data(report_type)


def process_report_data(report_data, **kwargs):
    report_type = kwargs.get("report_type") or "dashboard"
    report_format = kwargs.get("report_format") or "processed"
    is_dashboard = report_type == "dashboard"
    report_data_ok = report_data.get("status_code") == 200

    if report_data_ok:
        if is_dashboard or report_format == "processed":
            transactions = list(gen_records(report_data))
        else:
            transactions = report_data

        if is_dashboard:
            status = get_status("company")

            if status["status_code"] == 200:
                company_info = status["CompanyInfo"]
                company = company_info["CompanyName"]
                groups = {}

                for key, group in pr.group(transactions, "Transaction Type"):
                    if key in {"Invoice", "Payment", "Purchase Order"}:
                        groups[key] = group

                invoices = groups.get("Invoice", [])
                purchases = groups.get("Purchase Order", [])
                purchases_by_num = {purchase["Num"]: purchase for purchase in purchases}

                result = list(process_invoices(invoices, purchases_by_num, company))

                if result[0].get("status_code"):
                    response = result[0]
                else:
                    response = {"result": result}
            else:
                response = status
        else:
            response = {"result": transactions}
    else:
        response = report_data

    return response


def create_weighted_sales_dict(*args, prefix=None):
    sales, upsells, sales_weight, upsell_weight = args
    weighted_sales = sales * sales_weight
    weighted_upsells = upsells * upsell_weight

    return {
        "Sales Weight": sales_weight,
        "Upsell Weight": upsell_weight,
        f"{prefix} Sales": sales,
        f"{prefix} Upsells": upsells,
        f"{prefix} Weighted Sales": weighted_sales,
        f"{prefix} Weighted Upsells": weighted_upsells,
        f"{prefix} Weighted Average Sales": weighted_sales + weighted_upsells,
    }


# TODO: This should probably be broken out into multiple functions
def calculate_weighted_avg_sales(transactions):
    """ Orders QB transactions by salesrep, then customer by earliest
    date to latest and adds the Upsell: True/False field.

    Upsells are calculated per period per sales person.

    For example, if a sales rep named Josh sells 5 times to ABC corporation
    (thrice in 08-2019 and twice in 08-2019), then the first sale in 08-2019 is
    a "Sale" and the next two in 08-2019 are "Upsells." Of the remaining two
    sales in 09-2019, the first is a "Sale" and the next is an "Upsell."

    Args:
        transactions (list of dicts): the dictionaries have the following fields:
            {
                "A/P Paid": "",
                "A/R Paid": "Paid",
                "Account": "Accounts Receivable",
                "Amount": "51437.94",
                "Clr": "",
                "Contract #": "",
                "Date": "2018-07-30",
                "Memo/Description": "",
                "Name": "ALEGNA INC. - AR",
                "Num": "3227",
                "PO #s": "",
                "Posting": "Yes",
                "Sales Rep": "John Wayne",
                "Split": "-Split-",
                "Taxable Amount": ".00",
                "Transaction Type": "Invoice"
            }

    Returns:
        final_response (list of dicts): the dicts have the same fields that were
            present in the `transactions` argument, plus several more related to
            weighted average sales.
            Example of extra fields:
                {
                    ...
                    'Sale': False,
                    'Upsell': False,
                    'Sales Weight': Decimal('0.7'),
                    'Upsell Weight': Decimal('0.3'),
                    'Period Sales': Decimal('14747.50'),
                    'Period Upsells': Decimal('13788.00'),
                    'Period Weighted Sales': Decimal('10323.250'),
                    'Period Weighted Upsells': Decimal('4136.400'),
                    'Period Weighted Average Sales': Decimal('14459.650'),
                    'Rep Period Sales': Decimal('0'),
                    'Rep Period Upsells': Decimal('0'),
                    'Rep Period Weighted Sales': Decimal('0.0'),
                    'Rep Period Weighted Upsells': Decimal('0.0'),
                    'Rep Period Weighted Average Sales': Decimal('0.0')
                },
            # TODO: describe more how each of these is calculated
    """
    invoices_by_period = {}
    invoices_by_rep = {}
    date_ranges = list(gen_ranges(date.today()))

    # CALCULATE SALES AND UPSELLS BY PERIOD
    for transaction in transactions:
        period = get_period(parse_date(transaction["Date"]), date_ranges) or DEF_PERIOD
        rep_name = transaction["Sales Rep"]
        company = transaction["Name"] or DEF_NAME

        # this function changes invoices_by_period in place
        build_invoice_dict_by_keys(
            [period, rep_name, company], invoices_by_period, transaction
        )

    response = []
    sales_weight, upsell_weight = get_sales_upsell_weights()

    for period, period_reps_dict in invoices_by_period.items():
        period_sales = Decimal(0)
        period_upsells = Decimal(0)
        temp_response = []

        for rep_name, rep_customers_dict in period_reps_dict.items():
            for transactions_arr in rep_customers_dict.values():
                transactions_arr.sort(key=lambda t: t["Num"])

                for pos, transaction in enumerate(transactions_arr):
                    amount = Decimal(transaction["Amount"] or 0)
                    transaction["Sale"] = False
                    transaction["Upsell"] = False

                    # For something to be considered a Sale or an Upsell,
                    # 'A/R Paid' must be 'Paid'
                    if transaction["A/R Paid"] == "Paid":
                        if pos:
                            transaction["Upsell"] = True
                            period_upsells += amount
                        else:
                            transaction["Sale"] = True
                            period_sales += amount

                temp_response += transactions_arr

        args = (period_sales, period_upsells, sales_weight, upsell_weight)
        weighted_sales_dict = create_weighted_sales_dict(*args, prefix="Period")

        for sorted_transactions in temp_response:
            response.append({**sorted_transactions, **weighted_sales_dict})

    # CALCULATE SALES AND UPSELLS BY REP
    for transaction in response:
        sales_rep = transaction["Sales Rep"]
        period = get_period(parse_date(transaction["Date"]), date_ranges)

        if sales_rep in invoices_by_rep:
            if period in invoices_by_rep[sales_rep]:
                invoices_by_rep[sales_rep][period].append(transaction)
            else:
                invoices_by_rep[sales_rep][period] = [transaction]
        else:
            invoices_by_rep[sales_rep] = {}
            invoices_by_rep[sales_rep][period] = [transaction]

    final_response = []

    for rep_name, rep_period_dict in invoices_by_rep.items():
        for period, transactions_arr in rep_period_dict.items():
            rep_period_sales = Decimal(0)
            rep_period_upsells = Decimal(0)

            for transaction in transactions_arr:
                amount = Decimal(transaction["Amount"] or 0)

                if transaction["Sale"]:
                    rep_period_sales += amount
                elif transaction["Upsell"]:
                    rep_period_upsells += amount

            args = (rep_period_sales, rep_period_upsells, sales_weight, upsell_weight)
            weighted_sales_dict = create_weighted_sales_dict(*args, prefix="Rep Period")

            for transaction in transactions_arr:
                final_response.append({**transaction, **weighted_sales_dict})

    return final_response


# TODO: this could likely be implemented more cleanly as a generator
# (talk about at team meeting)
def build_invoice_dict_by_keys(keys, obj, transaction):
    """ Takes a transaction and adds a nested dictionary of the keys
    provided in order (with the first key as the top level and the
    last key as the bottom level of the dictionary). If the keys exist
    in the `obj` parameter, then transaction is added under the appropriate
    keys.

    Args:
        keys (list of strings): ordered keys of a future nested dictionary
            Example - ["Period", "Sales Rep", "Customer"]
        obj (dict): a dictionary that recursively adds transaction data to it in a nested dictionary format
        transaction (dict):
            {
                'A/P Paid': '',
                'A/R Paid': '',
                'Account': 'Plum Card-01084',
                'Amount': '30.18',
                'Clr': 'R',
                'Date': '2018-12-01',
                'Memo/Description': 'JULIAN WASHINGTON-0...463978051',
                'Name': '',
                'Num': '',
                'PO #s': '',
                'Posting': 'Yes',
                'Rating/Interact': '',
                'Sales Rep': '',
                'Split': 'Cost of Goods Sold',
                'Taxable Amount': '.00',
                'Tracking #': '',
                "Transaction Type": "Expense"
            }

    Returns: a nested dictionary using the keys list provided (the example
    below assumes that the `obj` parameter is empty to start)
        {
            'key[0]': {
                'key[1]': {
                    'key[2]': [
                        transaction parameter
                    ]
                }
            }
        }

    Examples:
        >>> keys = [
        ...     ["bob", "cat", "bill"],
        ...     ["bob", "jeff", "frank"],
        ...     ["denice", "elaina", "jessica"],
        ...     ["denice", "elaina", "porqua"],
        ... ]
        >>> obj = {}
        >>> transactions = [
        ...     {'franky': 3},
        ...     {'nessie': 8},
        ...     {'josephine': 6},
        ...     {'shantee': 72},
        ... ]
        >>> for pos, transaction in enumerate(transactions):
        ...     build_invoice_dict_by_keys(keys[pos], obj, transaction)
        >>> obj
        { "bob": { "cat": { "bill": [{ "franky": 3 }] }, "jeff": { "frank": [{ "nessie": 8 }] } }, "denice": { "elaina": { "jessica": [{ "josephine": 6 }], "porqua": [{ "shantee": 72 }] } } }
    """
    if keys[0] in obj:
        if len(keys) > 1:
            build_invoice_dict_by_keys(keys[1:], obj[keys[0]], transaction)
        else:
            obj[keys[0]].append(transaction)
    else:
        if len(keys) > 1:
            obj[keys[0]] = {}
            build_invoice_dict_by_keys(keys[1:], obj[keys[0]], transaction)
        else:
            obj[keys[0]] = [transaction]
    return obj


def gen_commission_score(sales_reps):
    """ Yields
        {
            "Sales Rep": "Hugh Jackman",
            "Commission Score": ".56",
        }
    """
    sales_reps_lower = {s.lower() for s in sales_reps}
    # query cloze for rating, number_interactions, and first_call_resolution
    api_key = app.config.get("CLOZE_API_KEY")
    user = app.config["CLOZE_USER_EMAIL"]
    r = requests.get(
        f"https://api.cloze.com/v1/people/find?user={user}&api_key={api_key}&countonly=false&scope=local",
        headers={"Accept": "application/json"},
    )

    return obj


def _clear_cache():
    cache.delete(f"GET:{PREFIX}/data")
    cache.delete(f"GET:{PREFIX}/data?reportType=dashboard")
    get_report_data.cache_clear()


def _data(report_type="dashboard", report_format="processed", realtime=False):
    """
    report_type: one of ["invoice", "po", "payment", "all", "dashboard"]
    report_format: one of ["raw", "processed"]
    """
    auth_client = get_auth_client("QB", **app.config)
    qbo = auth_client.oauth_session

    if qbo and auth_client.realm_id:
        is_dashboard = report_type == "dashboard"
        report_data_func = get_realtime_report_data if realtime else get_report_data

        if is_dashboard:
            report_data = report_data_func("all")
        else:
            report_data = report_data_func(report_type)
    else:
        report_data = {
            "status_code": 500,
            "message": f"auth_client.oauth_session failed. Error: {auth_client.error}",
        }

    kwargs = {"report_type": report_type, "report_format": report_format}
    response = process_report_data(report_data, **kwargs)
    # The status_code only gets set if it is NOT 200 (200 is the default)
    if response.get("status_code") and response["status_code"] != 200:

        @after_this_request
        def clear_cache(response):
            _clear_cache()
            response = uncache_header(response)
            return response

    return response


###########################################################################
# ROUTES
###########################################################################
@blueprint.route("/")
def index():
    return redirect(url_for(".home"))


@blueprint.route(PREFIX)
@cache_header(ROUTE_TIMEOUT)
def home():
    response = {
        "description": "Returns API documentation",
        "message": "Welcome to the Alegna Commission Calculator API!",
        "links": sort_links(gen_links()),
    }

    return jsonify(**response)


@blueprint.route(f"{PREFIX}/refresh")
def refresh():
    auth_client = get_auth_client("QB", **app.config)
    auth_client.renew_token()
    return redirect(url_for(".status"))


@blueprint.route(f"{PREFIX}/callback")
def callback():
    query = urlparse(request.url).query
    response = dict(parse_qsl(query))
    auth_client = get_auth_client(
        "QB", state=response["state"], realm_id=response["realmId"], **app.config
    )
    session["QB_state"] = auth_client.state
    session["QB_realm_id"] = auth_client.realm_id
    auth_client.fetch_token()
    url = cache.get("callback_url")

    if url:
        cache.delete("callback_url")
    else:
        url = url_for(".status")

    return redirect(url)


@blueprint.route(f"{PREFIX}/status", defaults={"status_type": "auth"})
@blueprint.route(f"{PREFIX}/status/<status_type>")
def status(status_type):
    response = get_status(status_type)
    auth_client = get_auth_client("QB", **app.config)
    response.update(
        {
            "links": sort_links(gen_links()),
            "token": auth_client.token,
            "state": auth_client.state,
            "realm_id": auth_client.realm_id,
        }
    )
    return jsonify(**response)


@blueprint.route(f"{PREFIX}/realtime_data")
def realtime_data():
    """
    reportType: one of ["invoice", "po", "payment", "all", "dashboard"]
    reportFormat: one of ["raw", "processed"]
    fileType: one of ["json", "csv"]

    note:
      reportType of "dashboard" ignores the "reportFormat" option
      reportFormat of "raw" ignores the "fileType" option
    """
    report_type = request.args.get("reportType", "dashboard")

    if report_type == "dashboard":
        report_format = "processed"
    else:
        report_format = request.args.get("reportFormat", "processed")

    if report_format == "raw":
        file_type = "json"
    else:
        file_type = request.args.get("fileType", "json")

    response = _data(report_type, report_format, True)
    response["links"] = sort_links(gen_links())

    if file_type == "json":
        return jsonify(**response)
    elif file_type == "csv":
        return responsify("text/csv", **response)


@blueprint.route(f"{PREFIX}/data")
@cache_header(ROUTE_TIMEOUT, key_prefix=make_cache_key)
def data():
    """
    reportType: one of ["invoice", "po", "payment", "all", "dashboard"]
    reportFormat: one of ["raw", "processed"]
    fileType: one of ["json", "csv"]

    note:
      reportType of "dashboard" ignores the "reportFormat" option
      reportFormat of "raw" ignores the "fileType" option
    """
    report_type = request.args.get("reportType", "dashboard")

    if report_type == "dashboard":
        report_format = "processed"
    else:
        report_format = request.args.get("reportFormat", "processed")

    if report_format == "raw":
        file_type = "json"
    else:
        file_type = request.args.get("fileType", "json")

    response = _data(report_type, report_format)
    response["links"] = sort_links(gen_links())

    if file_type == "json":
        return jsonify(**response)
    elif file_type == "csv":
        return responsify("text/csv", **response)


@blueprint.route(f"{PREFIX}/ipsum")
@cache_header(ROUTE_TIMEOUT, key_prefix="%s")
def ipsum():
    response = {
        "description": "Displays a random sentence",
        "links": sort_links(gen_links()),
        "message": fake.sentence(),
    }

    return jsonify(**response)


###########################################################################
# METHODVIEW ROUTES
###########################################################################
class Auth(MethodView):
    def get(self):
        cache.set("callback_url", request.args.get("callback_url"))
        auth_client = get_auth_client("QB", **app.config)
        # Look into headless browser authentication for a user
        # instead of the user needing to do it (for CLI projects
        # or projects without a browser involved).
        # webbrowser.open_new_tab(auth_url)
        return redirect(auth_client.authorization_url[0])

    def delete(self, base=None):
        auth_client = get_auth_client("QB", **app.config)
        response = {"status_code": 200, "message": auth_client.revoke_token()}

        return jsonify(**response)


class Memoization(MethodView):
    def get(self):
        base_url = get_request_base()
        message = f"The {request.method}:{base_url} route is not yet complete."

        response = {
            "description": "Deletes a cache url",
            "links": sort_links(gen_links()),
            "message": message,
        }

        return jsonify(**response)

    def delete(self, path=None):
        if path:
            url = f"{PREFIX}/{path}"
            cache.delete(url)
            message = f"Deleted cache for {url}"
        else:
            cache.clear()
            message = "Caches cleared!"

        response = {"links": sort_links(gen_links()), "message": message}

        return jsonify(**response)


memo_view = Memoization.as_view("memoization")
memo_url = f"{PREFIX}/memoization"
memo_path_url = f"{memo_url}/<string:path>"

add_rule = blueprint.add_url_rule

add_rule(f"{PREFIX}/auth", view_func=Auth.as_view("auth"))
add_rule(memo_url, view_func=memo_view)
add_rule(memo_path_url, view_func=memo_view, methods=["DELETE"])

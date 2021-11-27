# -*- coding: utf-8 -*-
"""
    app.providers.xero
    ~~~~~~~~~~~~~~~~~~

    Provides Xero API related functions
"""
import re

from functools import partial
from datetime import date, datetime as dt, timezone, timedelta
from decimal import Decimal

import pygogo as gogo

from app.utils import fetch_choice
from app.helpers import get_collection, get_provider, flask_formatter as formatter
from app.mappings import USERS, POSITIONS, gen_task_mapping
from app.routes.webhook import Webhook
from app.routes.auth import Resource, process_result

logger = gogo.Gogo(
    __name__, low_formatter=formatter, high_formatter=formatter, monolog=True
).logger
logger.propagate = False

PREFIX = __name__.split(".")[-1]


def events_processor(result, fields, **kwargs):
    result = process_result(result, fields, **kwargs)
    return ({**item, "day": item["dateUtc"].split("T")[0]} for item in result)


def get_position_user_ids(xero_task_name):
    position_name = xero_task_name.lower()

    if "(" in position_name:
        position_name = position_name.split("(")[1][:-1]

    try:
        user_ids = POSITIONS[position_name]
    except KeyError:
        logger.debug(f"Xero position map doesn't contain '{position_name}'!")
        user_ids = []

    return user_ids


def get_user_name(user_id, prefix=PREFIX):
    Users = get_collection(prefix, "users")
    users = Users(dry_run=True, rid=user_id)
    user = users.extract_model(update_cache=True, strict=False)
    return user.get(users.name_field, "User Not Found")


def parse_date(date_str):
    # "2009-05-27T00:00:00"
    year, month, day = map(int, date_str.split("T")[0].split("-"))
    date_obj = date(year, month, day)
    return date_obj.strftime("%b %-d, %Y")


def parse_ts(date_str):
    # "\/Date(1518685950940+0000)\/"
    # https://developer.xero.com/documentation/api/accounting/requests-and-responses#json-responses-and-date-formats
    # https://stackoverflow.com/a/37097784/408556
    ms, sign, hours, minutes = re.search(
        r"[\D+](\d+)([+\-])(\d{2})(\d{2})", date_str
    ).groups(0)
    ts = int(ms) / 1000
    sign = -1 if sign == "-" else 1
    tz = timezone(sign * timedelta(hours=int(hours), minutes=int(minutes)))
    date_obj = dt.fromtimestamp(ts, tz=tz)
    return date_obj.strftime("%b %-d, %Y")


def gen_address(City="", Region="", PostalCode="", **kwargs):
    for k, v in kwargs.items():
        if v and k.startswith("AddressLine"):
            yield v

    last_line = f"{City}, {Region}" if City and Region else City or Region

    if PostalCode:
        last_line += f" {PostalCode}"

    yield last_line


class Xero(Resource):
    def __init__(self, prefix=PREFIX, **kwargs):
        super().__init__(prefix, **kwargs)


###########################################################################
# Resources
###########################################################################
class Projects(Xero):
    def __init__(self, prefix=PREFIX, **kwargs):
        fields = ["projectId", "name", "status"]
        kwargs.update({"fields": fields, "id_field": "projectId", "subkey": "items"})
        super().__init__(prefix, resource="projects", **kwargs)

    def get_post_data(self, project, project_name, rid, **kwargs):
        client = project["client"]
        kwargs.update({"dry_run": self.dry_run, "dest_prefix": self.prefix})
        xero_contact = Contacts.from_source(client, **kwargs)

        if xero_contact:
            project_data = {
                "contactId": xero_contact["ContactID"],
                "name": project_name,
            }

            if project.get("budget"):
                project_data["estimateAmount"] = project["budget"]
        else:
            project_data = {}

        return project_data

    def id_func(self, project, proj_name, rid, prefix=PREFIX):
        matching = list(enumerate(x["name"] for x in self))
        none_of_prev = [(len(matching), "None of the previous projects")]
        choices = matching + none_of_prev
        pos = fetch_choice(choices) if choices else None

        try:
            item = self[pos]
        except (IndexError, TypeError):
            proj_id = None
        else:
            proj_id = item["projectId"]

        return proj_id


class Users(Xero):
    def __init__(self, prefix=PREFIX, **kwargs):
        fields = ["userId", "name"]
        kwargs.update({"fields": fields, "id_field": "userId", "subkey": "items"})
        super().__init__(prefix, resource="projectsusers", **kwargs)

    def id_func(self, user, user_name, rid, prefix=PREFIX):
        matching = list(enumerate(x["name"] for x in self))
        none_of_prev = [(len(matching), "None of the previous users")]
        choices = matching + none_of_prev
        pos = fetch_choice(choices) if choices else None

        try:
            item = self[pos]
        except (IndexError, TypeError):
            user_id = None
        else:
            user_id = item["userId"]

        return user_id


class Contacts(Xero):
    def __init__(self, prefix=PREFIX, **kwargs):
        kwargs.update(
            {
                "fields": ["ContactID", "Name", "FirstName", "LastName"],
                "id_field": "ContactID",
                "subkey": "Contacts",
                "domain": "api",
            }
        )
        super().__init__(prefix, resource="Contacts", **kwargs)

    def id_func(self, contact, contact_name, rid, prefix=PREFIX):
        matching = list(enumerate(x["Name"] for x in self))
        none_of_prev = [(len(matching), "None of the previous contacts")]
        choices = matching + none_of_prev
        pos = fetch_choice(choices) if choices else None

        try:
            item = self[pos]
        except (IndexError, TypeError):
            contact_id = None
        else:
            contact_id = item["ContactID"]

        return contact_id


class Payments(Xero):
    def __init__(self, prefix=PREFIX, **kwargs):
        kwargs.update(
            {
                "fields": [],
                "id_field": "PaymentID",
                "subkey": "Payments",
                "domain": "api",
            }
        )

        super().__init__(prefix, resource="Payments", **kwargs)


class Invoices(Xero):
    def __init__(self, prefix=PREFIX, **kwargs):
        kwargs.update(
            {
                "fields": [],
                "id_field": "InvoiceID",
                "subkey": "Invoices",
                "domain": "api",
                "name_field": "InvoiceNumber",
            }
        )

        super().__init__(prefix, resource="Invoices", **kwargs)

    def get_address(self, Addresses=None, **customer):
        address = []

        if Addresses:
            try:
                _address = next(x for x in Addresses if x.get("AddressLine1"))
            except StopIteration:
                pass
            else:
                address = list(gen_address(**_address))

        return address

    def get_cc(self, email, ContactPersons=None, **customer):
        contacts = ContactPersons or []

        try:
            cced = next(
                x["EmailAddress"]
                for x in contacts
                if x.get("IncludeInEmails") and x["EmailAddress"] != email
            )
        except StopIteration:
            cced = ""

        return cced


class OnlineInvoices(Xero):
    def __init__(self, prefix=PREFIX, **kwargs):
        kwargs.update(
            {
                "id_field": "OnlineInvoiceUrl",
                "subkey": "OnlineInvoices",
                "domain": "api",
                "subresource": "OnlineInvoice",
            }
        )

        super().__init__(prefix, resource="Invoices", **kwargs)


class EmailTemplate(Xero):
    def __init__(self, prefix=PREFIX, **kwargs):
        kwargs["get_json_response"] = self.get_json_response
        super().__init__(prefix, **kwargs)
        self.recipient_name = kwargs.get("recipient_name")
        self.recipient_email = kwargs.get("recipient_email")
        self.copied_email = kwargs.get("copied_email")
        self.blind_copied_email = kwargs.get("blind_copied_email")


class InvoiceEmailTemplate(EmailTemplate):
    def __init__(self, prefix=PREFIX, **kwargs):
        super().__init__(prefix, resource="Invoices", **kwargs)

    def get_line_item(self, LineAmount=0, DiscountAmount=0, Quantity=1, **kwargs):
        item_price = Decimal(LineAmount) + Decimal(DiscountAmount)
        item_qty = Decimal(Quantity)

        line_item = {
            "description": kwargs["Description"],
            "item_price": "{:,.2f}".format(item_price),
            "item_qty": "{:,.1f}".format(item_qty),
        }
        return line_item

    def get_json_response(self):
        # https://developer.xero.com/documentation/api/accounting/invoices#get-invoices
        invoices = Invoices(rid=self.id)
        invoice = invoices.extract_model()
        assert invoice, (f"Invoice {self.id} doesn't exist!", 404)

        invoice_num = invoice[invoices.name_field]
        items = [self.get_line_item(**item) for item in invoice["LineItems"]]
        customer = invoice["Contact"]
        address = invoices.get_address(**customer)
        email = self.recipient_email or customer["EmailAddress"]
        cced = invoices.get_cc(email, **customer)
        due_date = parse_date(invoice["DueDateString"])
        invoice_date = parse_date(invoice["DateString"])
        due = Decimal(invoice["AmountDue"])
        discount = Decimal(invoice.get("TotalDiscount", 0))
        subtotal = due + discount

        online_invoices = OnlineInvoices(rid=self.id)
        online_invoice = online_invoices.extract_model()
        def_name = "{FirstName} {LastName}".format(**customer)
        name = def_name if self.recipient_name is None else self.recipient_name

        model = {
            "contact_name": name.split(" ")[0],
            "reference": invoice["Reference"],
            "due": "{:,.2f}".format(due),
            "currency": invoice["CurrencyCode"],
            "due_date": due_date,
            "link": online_invoice[online_invoices.id_field],
            "customer_name": customer["Name"],
            "invoice_num": invoice_num,
            "invoice_date": invoice_date,
            "items": items,
            "subtotal": "{:,.2f}".format(subtotal),
            "discount": "{:,.2f}".format(discount) if discount else "",
            "address": address,
        }

        result = {
            "model": model,
            "name": name,
            "email": email,
            "copied_email": cced if self.copied_email is None else self.copied_email,
            "blind_copied_email": self.blind_copied_email,
            "filename": "Nerevu Invoice {invoice_num}.pdf".format(**model),
            "pdf": invoices.extract_model(headers={"Accept": "application/pdf"}),
            "metadata": {"client-id": customer["ContactID"]},
        }

        return {"result": result}


class PaymentEmailTemplate(EmailTemplate):
    def __init__(self, prefix=PREFIX, **kwargs):
        super().__init__(prefix, resource="Payments", **kwargs)

    def get_json_response(self):
        # https://developer.xero.com/documentation/api/accounting/payments#get-payments
        payments = Payments(rid=self.id)
        payment = payments.extract_model()
        assert payment, (f"Payment {self.id} doesn't exist!", 404)

        payment_date = parse_ts(payment["Date"])
        paid = Decimal(payment["Amount"])

        invoice_id = payment["Invoice"]["InvoiceID"]
        invoices = Invoices(rid=invoice_id)
        invoice = invoices.extract_model()
        invoice_num = invoice[invoices.name_field]
        customer = invoice["Contact"]
        address = invoices.get_address(**customer)
        email = self.recipient_email or customer["EmailAddress"]
        cced = invoices.get_cc(email, **customer)
        remaining = Decimal(invoice["AmountDue"])
        previous = paid + remaining

        online_invoices = OnlineInvoices(rid=invoice_id)
        online_invoice = online_invoices.extract_model()
        def_name = "{FirstName} {LastName}".format(**customer)
        name = def_name if self.recipient_name is None else self.recipient_name

        model = {
            "contact_name": name.split(" ")[0],
            "reference": invoice["Reference"],
            "paid": "{:,.2f}".format(paid),
            "currency": invoice["CurrencyCode"],
            "link": online_invoice[online_invoices.id_field],
            "customer_name": customer["Name"],
            "invoice_num": invoice_num,
            "payment_date": payment_date,
            "previous": "{:,.2f}".format(previous),
            "remaining": "{:,.2f}".format(remaining),
            "address": address,
        }

        result = {
            "model": model,
            "name": name,
            "email": email,
            "copied_email": cced if self.copied_email is None else self.copied_email,
            "blind_copied_email": self.blind_copied_email,
            "filename": "Nerevu Payment (Invoice {invoice_num}).pdf".format(**model),
            "pdf": invoices.extract_model(headers={"Accept": "application/pdf"}),
            "metadata": {"client-id": customer["ContactID"]},
        }

        return {"result": result}


class Inventory(Xero):
    def __init__(self, prefix=PREFIX, **kwargs):
        kwargs.update(
            {
                "fields": ["ItemID", "Name", "Code", "Description", "SalesDetails"],
                "id_field": "ItemID",
                "subkey": "Items",
                "domain": "api",
                "name_field": "Name",
            }
        )

        super().__init__(prefix, resource="Items", **kwargs)

    def get_matching_xero_postions(self, user_id, task_name, user_name=None):
        logger.debug(f"Loading {self} choices for {user_name}…")
        return [t for t in self if user_id in get_position_user_ids(t[self.name_field])]


class ProjectTasks(Xero):
    def __init__(self, prefix=PREFIX, **kwargs):
        # TODO: filter by active xero tasks
        kwargs.update(
            {
                "fields": ["taskId", "name", "status", "rate.value", "projectId"],
                "id_field": "taskId",
                "subkey": "items",
                "map_factory": None,
                "entry_factory": None,
                "rid_hook": self.hook,
                "subresource": "tasks",
            }
        )

        super().__init__(prefix, resource="projects", **kwargs)

    def get_task_entry(self, rid, source_rid, prefix=PREFIX):
        (project_id, user_id, label_id) = source_rid
        entry = {}
        entry[prefix.lower()] = {
            "task": label_id,
            "project": project_id,
            "users": USERS[user_id],
        }
        entry[self.lowered] = {"task": rid, "project": self.rid}
        return entry

    def hook(self):
        if self.rid:
            xero_users = Users(dry_run=self.dry_run)
            xero_projects = Projects(dry_run=True)

            self.entry_factory = self.get_task_entry
            self.map_factory = partial(
                gen_task_mapping,
                user_mappings=xero_users.mappings,
                project_mappings=xero_projects.mappings,
            )

    def get_matching_xero_postions(self, user_id, task_name, user_name=None):
        logger.debug(f"Loading {self} choices for {user_name}…")
        positions = [
            t for t in self if user_id in get_position_user_ids(t[self.name_field])
        ]

        return positions

    def get_post_data(self, task, task_name, rid, prefix=PREFIX, **kwargs):
        (project_id, user_id, label_id) = rid
        args = (user_id, task_name, get_user_name(user_id, prefix=prefix))
        matching_task_positions = self.get_matching_xero_postions(*args)
        task_position_names = {t["name"] for t in matching_task_positions}

        xero_inventory = Inventory(dry_run=self.dry_run)
        matching_inventory_positions = xero_inventory.get_matching_xero_postions(*args)
        matching_positions = [
            m
            for m in matching_inventory_positions
            if m["Name"] not in task_position_names
        ]

        matching = list(
            enumerate(
                f"{m['Name']} - {m['SalesDetails']['UnitPrice']}"
                for m in matching_positions
            )
        )

        none_of_prev = [(len(matching), "None of the previous tasks")]
        choices = matching + none_of_prev
        pos = fetch_choice(choices) if choices else None

        try:
            item = matching_positions[pos]
        except (IndexError, TypeError):
            item = {}

        try:
            rate = item["SalesDetails"]["UnitPrice"]
        except KeyError:
            task_data = {}
        else:
            task_data = {
                "name": item["Name"],
                "rate": {"currency": "USD", "value": rate},
                "chargeType": "TIME" if rate else "NON_CHARGEABLE",
            }

        return task_data

    def id_func(self, task, task_name, rid, prefix=PREFIX):
        (project_id, user_id, label_id) = rid
        args = (user_id, task_name, get_user_name(user_id, prefix=prefix))
        matching_task_positions = self.get_matching_xero_postions(*args)
        matching = list(enumerate(m["name"] for m in matching_task_positions))
        none_of_prev = [(len(matching), "None of the previous tasks")]
        choices = matching + none_of_prev
        pos = fetch_choice(choices) if choices else None

        try:
            item = matching_task_positions[pos]
        except (IndexError, TypeError):
            task_id = None
        else:
            task_id = item["taskId"]

        return task_id


class ProjectTime(Xero):
    def __init__(self, prefix=PREFIX, source_prefix="timely", **kwargs):
        self.source_prefix = source_prefix
        self.event_pos = int(kwargs.pop("event_pos", 0))
        self.event_id = kwargs.pop("event_id", None)
        self.source_event = None
        self.eof = False
        self.source_project_id = kwargs.pop("source_project_id", None)
        kwargs.update(
            {
                "id_field": "timeEntryId",
                "subkey": "items",
                "subresource": "time",
                "processor": events_processor,
            }
        )

        super().__init__(prefix, resource="projects", **kwargs)

    def set_post_data(self, **kwargs):
        prefix = self.source_prefix
        provider = get_provider(prefix)
        assert provider, (f"Provider {prefix.lower()} doesn't exist!", 404)
        self.source_project_id = self.values.get(
            "sourceProjectId", self.source_project_id
        )
        source_projects = provider.Projects(
            rid=self.source_project_id,
            use_default=True,
            dry_run=self.dry_run,
            start=self.start,
            end=self.end,
        )
        source_project = source_projects.extract_model(update_cache=True, strict=True)
        self.source_project_id = source_project[source_projects.id_field]

        self.event_pos = int(self.values.get("eventPos", self.event_pos))
        source_project_events = provider.ProjectTime(
            rid=self.source_project_id,
            use_default=True,
            dry_run=self.dry_run,
            start=self.start,
            end=self.end,
            pos=self.event_pos,
        )
        self.source_event = source_project_events.extract_model(update_cache=True)
        self.eof = source_project_events.eof
        assert self.source_event, (f"{source_project_events} doesn't exist!", 404)
        self.event_id = self.source_event[source_project_events.id_field]
        added = self.results.get(self.event_id, {}).get("added")
        assert not added, (f"{source_project_events} already added!", 409)

        label_id = self.source_event.get("label_id")
        assert label_id, (f"{source_project_events} missing label!", 500)
        self.source_event["label_id"] = label_id

        unbilled = not self.source_event["billed"]
        assert unbilled, (f"{source_project_events} is already billed!", 409)

        self.day = self.source_event["day"]
        assert self.day, (f"{source_project_events} has no day!", 500)

        self.duration = self.source_event["duration.total_minutes"]
        assert self.duration, (f"{source_project_events} has no duration!", 500)
        skwargs = {
            "dry_run": self.dry_run,
            "dest_prefix": self.prefix,
            "source_prefix": prefix,
        }
        xero_project = Projects.from_source(source_project, **skwargs)
        self.rid = xero_project["projectId"]

        source_user_id = self.source_event["user.id"]

        mapping = {
            933370: "a76380db-eb5f-4fe4-8975-99ad2fabbd13",
            2014349: "929e6f75-6fae-42f1-8d99-bcda9565d906",
            2014908: "9dffcd83-581d-4a02-bdde-317c0c334e68",
        }

        xero_user_id = mapping.get(source_user_id)

        if not xero_user_id:
            logger.debug(f"User ID {source_user_id} doesn't exist in mapping!")
            source_users = provider.Users(dry_run=self.dry_run, rid=source_user_id)
            source_user = source_users.extract_model(update_cache=True)
            source_user_name = source_user["name"]
            xero_user = Users.from_source(source_user, **skwargs)
            assert xero_user, (f"User {source_user_name} doesn't exist in Xero!", 404)
            xero_user_id = xero_user["userId"]

        source_tasks = provider.Tasks(dry_run=self.dry_run)
        source_task = source_tasks.extract_model(
            label_id, update_cache=True, strict=True
        )
        source_rid = (self.source_project_id, source_user_id, label_id)
        xero_task = ProjectTasks.from_source(
            source_task, rid=self.rid, source_rid=source_rid, **skwargs,
        )
        assert xero_task, (f"Task {source_rid} doesn't exist in Xero!", 404)

        self.xero_user_id = xero_user_id
        self.xero_task_id = xero_task["taskId"]

        xero_tunc_user_id = self.xero_user_id.split("-")[0]
        xero_trunc_task_id = self.xero_task_id.split("-")[0]

        key = (self.day, self.duration, self.xero_user_id, self.xero_task_id)
        truncated_key = (self.day, self.duration, xero_tunc_user_id, xero_trunc_task_id)

        fields = ["day", "duration", "userId", "taskId"]
        event_keys = {tuple(event[f] for f in fields) for event in self}
        error = (f"Xero time entry {truncated_key} already exists!", 409)
        assert key not in event_keys, error

    def get_post_data(self, **kwargs):
        # url = 'http://localhost:5000/v1/xero-time'
        # r = requests.post(url, data={"sourceProjectId": 2389295, "dryRun": True})
        try:
            self.set_post_data(**kwargs)
        except AssertionError as err:
            self.error_msg, self.status_code = err.args[0]
            data = {}
        else:
            date_utc = f"{self.day}T12:00:00Z"
            note = self.source_event["note"]
            description = f"{note[:64]}…" if len(note) > 64 else note

            data = {
                "userId": self.xero_user_id,
                "taskId": self.xero_task_id,
                "dateUtc": date_utc,
                "duration": self.duration,
                "description": description,
            }

        return data


class Hooks(Webhook):
    def __init__(self, prefix=PREFIX, **kwargs):
        super().__init__(prefix, **kwargs)

    def process_value(self, value, **kwargs):
        result = {}

        for event in value:
            event_category = event["eventCategory"].lower()
            event_type = event["eventType"].lower()
            activity_name = f"{event_category}_{event_type}"
            action = self.actions.get(activity_name)

            if action:
                json = action(event["ResourceId"], **kwargs)
                result[event["eventId"]] = json.get("response")
            else:
                logger.warning(f"Activity {activity_name} doesn't exist!")

        return result

# -*- coding: utf-8 -*-
""" app.routes.auth
~~~~~~~~~~~~~~~~~~~
Provides Auth routes.

"""
from pathlib import Path
from datetime import date, timedelta
from json import loads, dumps, dump
from json.decoder import JSONDecodeError
from itertools import islice

import pygogo as gogo

from flask import (
    current_app as app,
    request,
    url_for,
    redirect,
    session,
)

from flask.views import MethodView

from config import Config

from app import cache
from app.authclient import get_auth_client, get_response, callback
from app.utils import (
    jsonify,
    get_links,
    parse_request,
    parse_kwargs,
    fetch_bool,
    HEADERS,
)
from app.mappings import reg_mapper
from app.helpers import singularize

from riko.dotdict import DotDict

logger = gogo.Gogo(__name__, monolog=True).logger

APP_DIR = Path(__file__).parents[1]
DATA_DIR = APP_DIR.joinpath("data")
MAPPINGS_DIR = APP_DIR.joinpath("mappings")
PREFIX = Config.API_URL_PREFIX
API_PREFIXES = Config.API_PREFIXES


def extract_fields(record, fields, **kwargs):
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


def remove_fields(record, black_list):
    for key, value in record.items():
        if key not in black_list:
            yield (key, value)


def process_result(result, fields=None, black_list=None, **kwargs):
    filterer = kwargs.pop("filterer", None)

    if filterer:
        result = filter(filterer, result)

    if black_list:
        result = (dict(remove_fields(item, black_list)) for item in result)

    if fields:
        result = (dict(extract_fields(item, fields)) for item in result)

    if kwargs:
        result = ({**item, **kwargs} for item in result)

    return result


def store(prefix, Collection, *args, **kwargs):
    collection = Collection(prefix, *args, **kwargs)
    response = collection.get(update_cache=True)
    json = response.json

    if json["ok"]:
        logger.debug(f"Success storing {collection}!")
    else:
        logger.error(json["message"])


class BaseView(MethodView):
    def __init__(self, prefix, **kwargs):
        self.START_PARMS = {
            "TIMELY": "since",
            "XERO": "dateAfterUtc",
            "QB": "start_date",
        }

        self.END_PARMS = {
            "TIMELY": "upto",
            "XERO": "dateBeforeUtc",
            "QB": "end_date",
        }

        self.prefix = prefix
        self.lowered = self.prefix.lower()
        self.is_timely = self.prefix == "TIMELY"
        self.is_xero = self.prefix == "XERO"
        self.is_opencart = self.prefix == "OPENCART"
        self.is_cloze = self.prefix == "CLOZE"
        self.is_qb = self.prefix == "QB"
        self._dry_run = kwargs.get("dry_run")

        def_end = date.today()

        if self._dry_run:
            self.client = None
            self._params = {}
            self.domain = None
            def_start = def_end - timedelta(days=Config.REPORT_DAYS)
        else:
            self.client = get_auth_client(self.prefix, **app.config)
            self._params = {**kwargs.get("params", {}), **self.client.auth_params}
            self.domain = kwargs.get("domain", self.client.domain)
            def_start = def_end - timedelta(days=app.config["REPORT_DAYS"])

        self._end = kwargs.get("end", def_end.strftime("%Y-%m-%d"))
        self._start = kwargs.get("start", def_start.strftime("%Y-%m-%d"))
        self.headers = HEADERS

        if self.is_xero and self.client and self.client.oauth2:
            self.headers["Xero-tenant-id"] = self.client.tenant_id


class Callback(BaseView):
    def __init__(self, prefix):
        super().__init__(prefix)

    def get(self):
        return callback(self.prefix)


class Auth(BaseView):
    def __init__(self, prefix):
        super().__init__(prefix)

        if self.client.oauth1:
            xero_url = f"{self.client.api_base_url}/projects.xro/2.0/projectsusers"
        else:
            xero_url = f"{self.client.api_base_url}/connections"

        qb_url = f"{self.client.api_base_url}/company/{self.client.realm_id}/"
        qb_url += f"companyinfo/{self.client.realm_id}"

        status_urls = {
            # TODO: Timely Headless Auth returns an error message
            # saying "invalid_grant", but it also returns the valid
            # credentials with the error message. Authentication is
            # working fine I guess, but we should really look into
            # making this work a little smoother.
            #
            # Resource("TIMELY", "accounts").api_url
            # Resource("XERO", "projects", subresource=users).get()
            "TIMELY": f"{self.client.api_base_url}/accounts",
            "XERO": xero_url,
            "QB": qb_url,
        }
        self.status_url = status_urls.get(prefix)

    def get(self):
        """Step 1: User Authorization.

        Redirect the user/resource owner to the OAuth provider (i.e. Github)
        using an URL with a few key OAuth parameters.
        """
        cache.set(f"{self.prefix}_callback_url", request.args.get("callback_url"))

        # https://gist.github.com/ib-lundgren/6507798#gistcomment-1006218
        # State is used to prevent CSRF, keep this for later.
        authorization_url, state = self.client.authorization_url
        self.client.state = session[f"{self.prefix}_state"] = state
        self.client.save()

        # Step 2: User authorization, this happens on the provider.
        if self.client.verified and not self.client.expired:
            response = get_response(self.status_url, self.client, **app.config)

            if self.is_xero and not self.client.tenant_id:
                # TODO: figure out why this keeps getting cleared
                self.client.tenant_id = response["result"][0].get("tenantId")

                if self.client.tenant_id:
                    self.client.save()

            response.update(
                {
                    "token": self.client.token,
                    "state": self.client.state,
                    "realm_id": self.client.realm_id,
                    "tenant_id": self.client.tenant_id,
                }
            )
            result = jsonify(**response)
        else:
            if self.client.oauth1:
                # clear previously cached token
                self.client.renew_token()
                authorization_url = self.client.authorization_url[0]

            redirect_url = authorization_url
            logger.info("redirecting to %s", redirect_url)
            result = redirect(redirect_url)

        return result

    def patch(self):
        self.client.renew_token()
        return redirect(url_for(f".{self.prefix}-auth".lower()))

    def delete(self, base=None):
        # TODO: find out where this was implemented
        response = {"status_code": 200, "message": self.client.revoke_token()}
        return jsonify(**response)


class Resource(BaseView):
    def __repr__(self):
        name = f"{self.lowered}-{self.lowered_resource}"

        if self.subresource:
            if self.rid:
                trunc_rid = str(self.rid).split("-")[0]
                prefix = f"[id:{trunc_rid}]"
            else:
                prefix = f"[pos:{self.pos}]" if self.use_default else "[id:None]"

            name += f"{prefix}-{self.lowered_subresource}"

        if self.id:
            trunc_id = str(self.id).split("-")[0]
            name += f"[id:{trunc_id}]"
        else:
            name += f"[pos:{self.pos}]" if self.use_default else "[id:None]"

        return name

    def __init__(self, prefix, resource=None, **kwargs):
        """ An API Resource.

        Args:
            prefix (str): The API.
            resource (str): The API resource.

        Kwargs:
            rid (str): The API resource_id.
            subkey (str): The API result field to return.

        Examples:
            >>> kwargs = {"subkey": "manufacturer"}
            >>> opencart_manufacturer = Resource("OPENCART", "products", **kwargs)
            >>>
            >>> kwargs = {"subkey": "person"}
            >>> cloze_person = Resource("CLOZE", "people", **kwargs)
            >>>
            >>> options = f"start_date={start}&end_date={end}&columns=name,net_amount"
            >>> kwargs = {"options": options}
            >>> qb_transactions = Resource("QB", "TransactionList", **kwargs)
        """
        self.resource = resource
        self.subresource = kwargs.get("subresource", "")
        self.subresource_id = kwargs.get("subresource_id")
        self.lowered_resource = self.resource.lower()
        self.lowered_subresource = self.subresource.lower()
        super().__init__(prefix, **kwargs)

        def_counterpart = set(API_PREFIXES).difference([self.prefix]).pop().lower()
        self.counterpart = kwargs.get("counterpart", def_counterpart)
        self.fields = kwargs.get("fields", [])
        self.map_factory = kwargs.get("map_factory", reg_mapper)
        self.entry_factory = kwargs.get("entry_factory")
        self.eof = False

        lowered_class = type(self).__name__.lower()
        self.path = f"{PREFIX}/{self.lowered}-{lowered_class}"

        try:
            def_id_field = next(f for f in self.fields if "id" in f.lower())
        except StopIteration:
            def_id_field = "id"

        try:
            def_name_field = next(f for f in self.fields if "name" in f.lower())
        except StopIteration:
            def_name_field = "name"

        self.id_field = kwargs.get("id_field", def_id_field)
        self.name_field = kwargs.get("name_field", def_name_field)
        self.processor = kwargs.get("processor", process_result)
        self.black_list = set(kwargs.get("black_list", []))
        self.options = kwargs.get("options", "")
        self.populate = kwargs.get("populate")
        self.filterer = kwargs.get("filterer")
        self.id_hook = kwargs.get("id_hook")
        self.rid_hook = kwargs.get("rid_hook")
        self._rid = kwargs.get("rid")
        self._use_default = kwargs.get("use_default")
        self._dictify = kwargs.get("dictify")
        self._subkey = kwargs.get("subkey")
        self._pos = kwargs.get("pos", 0)
        self._data = None
        self._mappings = None
        self._results = None
        self._values = None
        self._kwargs = None
        self._mapper = None
        self.verb = "get"
        self.error_msg = ""

        self.start_param = self.START_PARMS.get(self.prefix, "start")
        self.end_param = self.END_PARMS.get(self.prefix, "end")

        results_filename = kwargs.get("results_filename", "sync_results.json")
        self.results_p = DATA_DIR.joinpath(results_filename)

        if self.id and self.id_hook:
            self.id_hook()

        if self.rid and self.rid_hook:
            self.rid_hook()

    def __iter__(self):
        yield from self.data.values() if self.dictify else self.data

    def __getitem__(self, key):
        return self.data[key]

    @property
    def results(self):
        if self._results is None:
            results_content = self.results_p.read_text()

            try:
                results = loads(results_content)
            except JSONDecodeError as e:
                results = {}
                self.error_msg = f"{self.results_p} {e}!"

            if self.error_msg:
                logger.error(self.error_msg)

            self._results = results

        return self._results

    @results.setter
    def results(self, value):
        if value:
            with self.results_p.open(mode="w+", encoding="utf8") as results_f:
                dump(value, results_f, indent=2, sort_keys=True, ensure_ascii=False)
                results_f.write("\n")
                self._results = None

    @property
    def mappings(self):
        if self._mappings is None:
            if self.subresource:
                mappings_filename = f"{self.lowered_subresource}.json"
            else:
                mappings_filename = f"{self.lowered_resource}.json"

            self.mappings_p = MAPPINGS_DIR.joinpath(mappings_filename)
            mappings_content = self.mappings_p.read_text()

            try:
                mappings = loads(mappings_content)
            except JSONDecodeError as e:
                mappings = []
                self.error_msg = f"{self.mappings_p} {e}!"

            if self.error_msg:
                logger.error(self.error_msg)

            self._mappings = mappings

        return self._mappings

    @mappings.setter
    def mappings(self, value):
        if value:
            with self.mappings_p.open(mode="w+", encoding="utf8") as mappings_f:
                dump(value, mappings_f, indent=2, sort_keys=True, ensure_ascii=False)
                mappings_f.write("\n")
                self._mappings = None

    @property
    def mapper(self):
        if self._mapper is None:
            if self.mappings and self.map_factory:
                map_factory_args = (self.mappings, self.counterpart, self.lowered)
                _mapper = dict(self.map_factory(*map_factory_args))
            else:
                _mapper = {} if self.map_factory else None

            self._mapper = _mapper

        return self._mapper

    @property
    def id(self):
        def_id = self.subresource_id if self.subresource else self.rid
        return self.values.get("id", def_id)

    @id.setter
    def id(self, value):
        if self.subresource:
            self.subresource_id = value
        else:
            self.rid = value

        if self.id_hook:
            self.id_hook()

    @property
    def rid(self):
        if self.use_default and not self._rid:
            name = f"{self.lowered}-{self.lowered_resource}"

            if self.subresource:
                name += f"-{self.lowered_subresource}"

            msg = f"{name}[{self.pos}]"

            try:
                item = list(islice(self, self.pos, self.pos + 1))[0]
            except (IndexError, TypeError):
                self.eof = True
                logger.error(f"{msg} not found in cache!")

                if not self.data:
                    logger.error(f"No {name} cached data available!")
            else:
                self._rid = item.get(self.id_field)

        return self._rid

    @rid.setter
    def rid(self, value):
        self._rid = value

        if self.rid_hook:
            self.rid_hook()

    @property
    def data_p(self):
        if self.subresource and self._rid:
            try:
                split_id = self._rid.split("-")[0]
            except AttributeError:
                split_id = self._rid

            self.data_filename = (
                f"{self.lowered}_{split_id}_{self.lowered_subresource}.json"
            )
        elif self.subresource:
            self.data_filename = None
            self.error_msg = f"No {self} ID given!"
            logger.error(self.error_msg)
        else:
            self.data_filename = f"{self.lowered}_{self.lowered_resource}.json"

        try:
            data_p = DATA_DIR.joinpath(self.data_filename)
        except TypeError:
            data_p = None

        return data_p

    @property
    def data(self):
        if self._data is None:
            try:
                self.data_content = self.data_p.read_text()
            except (AttributeError, FileNotFoundError):
                self.data_content = None

            try:
                data = loads(self.data_content)
            except (JSONDecodeError, TypeError):
                data = []

            if self.dictify:
                self._data = dict((item.get(self.id_field), item) for item in data)
            else:
                self._data = data

        return self._data

    @data.setter
    def data(self, value):
        if value:
            with self.data_p.open(mode="w+", encoding="utf8") as data_f:
                dump(value, data_f, indent=2, sort_keys=True, ensure_ascii=False)
                data_f.write("\n")
                self._data = None

    @property
    def params(self):
        params = self._params or {}

        if self.is_cloze and self.id:
            params["uniqueid"] = self.id

        if self.is_qb and self.fields:
            params["columns"] = ",".join(self.fields)

        if self.start:
            params[self.start_param] = self.start

        if self.end:
            params[self.end_param] = self.end

        return params

    @property
    def api_url(self):
        client = self.client
        url = client.api_base_url

        if self.is_qb:
            # https://developer.intuit.com/app/developer/qbo/docs/api/accounting/report-entities/transactionlist
            url += f"/company/{client.realm_id}/reports"
        if self.is_cloze:
            url += f"/{self.verb}"
        elif self.is_xero:
            url += f"/{self.domain}.xro/2.0"
        elif self.is_timely:
            url += f"/{self.client.account_id}"

        url += f"/{self.resource}"

        if self.subresource:
            if self.rid:
                url += f"/{self.rid}/{self.subresource}"
            elif not self.eof:
                assert self.rid, (f"No {self}:{self.resource} id provided!", 404)

        if self.options:
            url += f"?{self.options}"

        if self.dry_run:
            url = ""

        if self.resource == "status":
            url = Auth(self.prefix).status_url

        return url

    @property
    def values(self):
        if self._values is None:
            try:
                if self.path == request.path:
                    self._values = parse_request()
                else:
                    self._values = {}
                    logger.debug(
                        f"path:{self.path} doesn't match request:{request.path}"
                    )
            except RuntimeError:
                self._values = {}

        return self._values

    @property
    def kwargs(self):
        if self._kwargs is None:
            try:
                if self.path == request.path:
                    self._kwargs = parse_kwargs(app)
                else:
                    self._kwargs = {}
                    logger.debug(
                        f"path:{self.path} doesn't match request:{request.path}"
                    )
            except RuntimeError:
                self._kwargs = {}

        return self._kwargs

    @property
    def dry_run(self):
        return self.values.get("dryRun", self._dry_run)

    @dry_run.setter
    def dry_run(self, value):
        self._values["dryRun"] = value

    @property
    def use_default(self):
        return self.values.get("useDefault", self._use_default)

    @use_default.setter
    def use_default(self, value):
        self._values["useDefault"] = value

    @property
    def dictify(self):
        return self.values.get("dictify", self._dictify)

    @dictify.setter
    def dictify(self, value):
        self._values["dictify"] = value

    @property
    def subkey(self):
        return self.values.get("subkey", self._subkey)

    @subkey.setter
    def subkey(self, value):
        self._values["subkey"] = value

    @property
    def result_key(self):
        _result_key = "result"

        return _result_key

    @property
    def pos(self):
        return int(self.values.get("pos", self._pos))

    @pos.setter
    def pos(self, value):
        self._values["pos"] = value

    @property
    def start(self):
        return self.values.get("start", self._start)

    @start.setter
    def start(self, value):
        self._values["start"] = value

    @property
    def end(self):
        return self.values.get("end", self._end)

    @end.setter
    def end(self, value):
        self._values["end"] = value

    def get_post_data(self, source_item, source_name, source_rid):
        data = {}
        data[self.name_field] = source_name
        return data

    def create_model(self, data):
        model = {}

        if data:
            response = self.post(**data)
            json = response.json

            if json["ok"]:
                model = DotDict(json).get(self.result_key)
            else:
                logger.error(json.get("message"))

        return model

    def extract_model(self, id=None, strict=False, *args, **kwargs):
        response = self.get(id, *args, **kwargs)
        json = response.json
        result = [] if self.eof else json["result"]

        try:
            model = result[0]
        except (IndexError, TypeError):
            model = {}
        except KeyError:
            model = result

        if json["ok"]:
            error = (f"{self} doesn't exist!", 404)
        else:
            message = json.get("message") or json["status"]
            error = (message, response.status_code)

        if strict:
            assert model, error
            assert model.get(self.id_field), (f"{self} has no ID!", 500)

        return model

    def refresh_values(self):
        """
        HACK: Not sure if this is pythonic, but this is in case there is a new matching
        request that needs to set self.values after it was already set to {}
        """
        self._values = None
        self.values

    def refresh_kwargs(self):
        """
        HACK: Not sure if this is pythonic, but this is in case there is a new matching
        request that needs to set self.kwargs after it was already set to {}
        """
        self._kwargs = None
        self.kwargs

    def update_mappings(self, source_rid):
        entry = {}

        if self.entry_factory:
            entry = self.entry_factory(self.id, source_rid)
        elif source_rid:
            entry[self.counterpart] = source_rid
            entry[self.lowered] = self.id

        if entry:
            self.mappings = self.mappings + [entry]

    def update_data(self, **kwargs):
        if kwargs:
            entry = dict(extract_fields(kwargs, self.fields))
            self.data = list(self.data) + [entry]

    def map_rid(self, rid, name=None):
        return self.mapper.get(rid)

    def convert(self, source):
        if self.subresource:
            assert self.rid, (f"No rid entered for {self}.", 404)

        try:
            has_id_func = self.id_func
        except AttributeError:
            has_id_func = False

        def converter(source_item, source_rid=None):
            dry_run, self.dry_run = self.dry_run, True
            source_name = name = source_item[source.name_field]

            if source_rid:
                name += f" {source_rid}"
                ekwargs = {"source_rid": source_rid}
            else:
                source_rid = source_item[source.id_field]
                ekwargs = {"source_rid": source_rid, "source_name": source_name}

            dest_item = self.extract_model(**ekwargs)
            needs_update = not dest_item

            if has_id_func and needs_update:
                logger.info(f"{name} not found in {self} cache. Select a mapping.")
                dest_id = self.id_func(source_item, source_name, source_rid)

                if dest_id:
                    dest_item = self.extract_model(id=dest_id, update_cache=True)

            self.dry_run = dry_run

            if not (dest_item or dry_run):
                message = f"No mapping available for {name} in {self}. "
                message += f"Do you want to create it?"
                answer = fetch_bool(message)

                if answer == "y":
                    data = self.get_post_data(source_item, source_name, source_rid)
                else:
                    data = {}

                if data:
                    dest_item = self.create_model(data)

            if dry_run:
                error_msg = f"Disable dry_run mode to create {self} mapping."
            else:
                error_msg = f"Manually add {name} to {self}."

            assert dest_item, (error_msg, 404)

            if needs_update:
                self.id = dest_item[self.id_field]
                self.update_mappings(source_rid)
                self.update_data(**dest_item)

            return dest_item

        return converter

    @classmethod
    def xero_from_timely(cls, source_item, dry_run=True, source_rid=None, **kwargs):
        dest = cls("XERO", dry_run=dry_run, **kwargs)
        source = cls("TIMELY", dry_run=dry_run)
        converter = dest.convert(source)
        return converter(source_item, source_rid=source_rid)

    def get(self, id=None, source_rid=None, source_name=None, update_cache=False):
        """ Get an API Resource.
        Kwargs:
            rid (str): The API resource_id.

        Examples:
            >>> kwargs = {"rid": "abc", "subkey": "manufacturer"}
            >>> opencart_manufacturer = Resource("OPENCART", "products", **kwargs)
            >>> opencart_manufacturer.get()
            >>>
            >>> kwargs = {"subkey": "person"}
            >>> cloze_person = Resource("CLOZE", "people", **kwargs)
            >>> cloze_person.get(rid="name@company.com")
            >>>
            >>> kwargs = {"fields": ["name", "net_amount"], "start": start}
            >>> qb_transactions = Resource("QB", "TransactionList", **kwargs)
            >>> qb_transactions.get()
        """
        self.id = self.values.pop("id", id) or self.id

        if self.data and not self.id and source_name is not None:
            try:
                result = next(x for x in self if source_name == x[self.name_field])
            except StopIteration:
                pass
            else:
                self.id = result[self.id_field]

        if not self.id and source_rid:
            self.id = self.map_rid(source_rid)

        if self.dry_run:
            if self.id and self.dictify:
                try:
                    result = self.data.get(int(self.id), {})
                except ValueError:
                    result = self.data.get(str(self.id), {})
            elif self.id:
                try:
                    result = next(
                        x for x in self if str(self.id) == str(x[self.id_field])
                    )
                except StopIteration:
                    result = {}
            elif source_name or source_rid:
                result = {}
            else:
                result = self.data

            status_code = 200 if result else 404
            ok = status_code == 200
            response = {"result": result, "ok": ok, "status_code": status_code}
        else:
            if self.id:
                url = f"{self.api_url}/{self.id}"
            elif source_name or source_rid:
                url = None
            else:
                try:
                    url = self.api_url
                except AssertionError as err:
                    url = None
                    self.error_msg, status_code = err.args[0]

            if url:
                rkwargs = {"headers": self.headers, "params": self.params, **app.config}
                response = get_response(url, self.client, **rkwargs)
            else:
                response = {"result": {}, "ok": False, "status_code": 404}

        if response["ok"] and not self.dry_run:
            result = response.get("result")

            if self.subkey:
                try:
                    result = result.get(self.subkey, {})
                except AttributeError:
                    pass

            if self.use_default and not self.id:
                try:
                    result = result[self.pos]
                except (IndexError, TypeError):
                    self.eof = True
                else:
                    self.id = result.get(self.id_field)

            if hasattr(result, "get"):
                result = [result]

            pkwargs = {"black_list": self.black_list}

            if not self.id:
                pkwargs["filterer"] = self.filterer

            result = list(self.processor(result, self.fields, **pkwargs))

            if result is not None and update_cache and not self.id:
                self.data = result
        else:
            result = response.get("result")

            if hasattr(result, "get"):
                result = [result]

        if self.error_msg:
            logger.error(self.error_msg)
            response["message"] = self.error_msg

        response["result"] = result
        return jsonify(**response)

    def post(self, **kwargs):
        """ Create an API Resource.

        Args:
            kwargs (dict): The data to post.

        Examples:
            >>> url = 'http://localhost:5000/v1/xero-project'
            >>> requests.post(url, data={})
            >>>
            >>> cloze_person = Resource("CLOZE", "people")
            >>> kwargs = {"name": "name", "emails": ["value": "email"]}
            >>> cloze_person.post(**kwargs)
        """
        rkwargs = {"headers": self.headers, "method": "post", **app.config}
        black_list = {
            "dryRun",
            "start",
            "end",
            "pos",
            "dictify",
            "useDefault",
            "subkey",
        }
        values = dict(remove_fields(self.values, black_list))
        data = {**values, **kwargs}

        if self.is_cloze:
            self.verb = "create"
        elif self.is_timely:
            data = {singularize(self.resource): data}

        if self.dry_run:
            response = {
                "result": data,
                "ok": True,
                "message": f"Disable dry_run mode to POST {self}.",
            }
        else:
            rkwargs[self.data_key] = dumps(data) if self.data_key == "data" else data
            response = get_response(self.api_url, self.client, **rkwargs)

        if self.error_msg:
            logger.error(self.error_msg)
            response["message"] = self.error_msg

        if not self.dry_run:
            try:
                response["links"] = get_links(app.url_map.iter_rules())
            except RuntimeError:
                pass

        return jsonify(**response)

    def patch(self, id=None, **kwargs):
        """ Upate an API Resource.
        Kwargs:
            rid (str): The API resource_id.
            data (dict): The data to patch.

        Examples:
            >>> url = 'http://localhost:5000/v1/xero-project/id'
            >>> requests.patch(url, data={})
            >>>
            >>> kwargs = {"use_default": True}
            >>> cloze_person = Resource("CLOZE", "people", **kwargs)
            >>> data = {"name": "name", "emails": ["value": "email"]}
            >>> cloze_person.patch(**data)
            >>>
            >>> url = 'http://localhost:5000/v1/timely-time'
            >>> requests.patch(url, data={"rid": 165829339, "dryRun": True})
        """
        self.id = self.values.pop("id", id) or self.id
        rkwargs = {"headers": self.headers, "method": "post", **app.config}
        black_list = {
            "dryRun",
            "start",
            "end",
            "pos",
            "dictify",
            "useDefault",
            "subkey",
        }
        values = dict(remove_fields(self.values, black_list))
        data = {**values, **kwargs}
        data[self.id_field] = self.id
        response = {}

        if not self.id:
            self.error_msg = f"No {self} ID given!"
            response = {"status_code": 404}

        if self.is_timely:
            rkwargs["method"] = "put"
            data = {singularize(self.resource): data}

        if self.dry_run:
            response = {
                "result": data,
                "ok": True,
                "message": f"Disable dry_run mode to PATCH {self}.",
            }

        if not response:
            url = f"{self.api_url}/{self.id}"
            rkwargs[self.data_key] = dumps(data) if self.data_key == "data" else data
            response = get_response(url, self.client, **rkwargs)

        response["id"] = self.id

        if not self.dry_run:
            try:
                response["links"] = get_links(app.url_map.iter_rules())
            except RuntimeError:
                pass

        if self.error_msg:
            logger.error(self.error_msg)
            response["message"] = self.error_msg

        return jsonify(**response)

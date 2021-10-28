# -*- coding: utf-8 -*-
""" app.routes.auth
~~~~~~~~~~~~~~~~~~~
Provides Auth routes.

"""
from pathlib import Path
from datetime import date, timedelta
from json import loads, dumps, dump
from itertools import islice
from json.decoder import JSONDecodeError

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

from meza.fntools import listize, remove_keys

from app import cache
from app.routes import ProviderMixin
from app.authclient import get_auth_client, get_json_response, callback
from app.utils import jsonify, get_links, fetch_bool, extract_fields
from app.mappings import reg_mapper
from app.helpers import singularize, get_collection

from riko.dotdict import DotDict

logger = gogo.Gogo(__name__, monolog=True).logger
logger.propagate = False

APP_DIR = Path(__file__).parents[1]
DATA_DIR = APP_DIR.joinpath("data")
MAPPINGS_DIR = APP_DIR.joinpath("mappings")


def process_result(result, fields=None, black_list=None, **kwargs):
    if black_list:
        result = (remove_keys(item, *black_list) for item in result)

    if fields:
        result = (dict(extract_fields(item, *fields)) for item in result)

    if kwargs:
        result = ({**item, **kwargs} for item in result)

    return result


def store(prefix, collection_name, **kwargs):
    Collection = get_collection(prefix, collection_name)
    collection = Collection(prefix, **kwargs)
    response = collection.get(update_cache=True)
    json = response.json

    if json["ok"]:
        logger.debug(f"Success storing {collection}!")
    else:
        logger.error(json["message"])


class BaseView(ProviderMixin, MethodView):
    def __init__(self, prefix=None, **kwargs):
        super().__init__(prefix)

        self.START_PARMS = {
            "timely": "since",
            "xero": "dateAfterUtc",
            "qb": "start_date",
        }

        self.END_PARMS = {
            "timely": "upto",
            "xero": "dateBeforeUtc",
            "qb": "end_date",
        }

        self._dry_run = kwargs.get("dry_run")
        self.ignore_domain = kwargs.get("ignore_domain")
        def_end = date.today()

        if self._dry_run:
            self.client = None
            self.data_key = None
            self.json_data = True
            self.dump_data = False
            self._params = {}
            self.domain = None
            def_start = def_end - timedelta(days=Config.REPORT_DAYS)
        else:
            self.client = get_auth_client(self.prefix, **app.config, **kwargs)
            self.data_key = self.client.data_key
            self.json_data = self.client.json_data
            self.dump_data = self.client.dump_data
            self._params = {**kwargs.get("params", {}), **self.client.auth_params}
            self.domain = kwargs.get("domain", self.client.domain)
            def_start = def_end - timedelta(days=app.config["REPORT_DAYS"])

        self._end = kwargs.get("end", def_end)
        self._start = kwargs.get("start", def_start)
        self.headers = kwargs.get("headers", {})

        if self.is_xero and self.client and self.client.oauth2:
            self.headers["Xero-tenant-id"] = self.client.tenant_id


class Callback(BaseView):
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
            # Resource("timely", "accounts").api_url
            # Resource("xero", "projects", subresource=users).get()
            "timely": f"{self.client.api_base_url}/accounts",
            "xero": xero_url,
            "qb": qb_url,
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
            json = get_json_response(self.status_url, self.client, **app.config)

            if self.is_xero and not self.client.tenant_id:
                # TODO: figure out why this keeps getting cleared
                self.client.tenant_id = json["result"][0].get("tenantId")

                if self.client.tenant_id:
                    self.client.save()

            json.update(
                {
                    "token": self.client.token,
                    "state": self.client.state,
                    "realm_id": self.client.realm_id,
                    "tenant_id": self.client.tenant_id,
                }
            )
            result = jsonify(**json)
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
        json = {"status_code": 200, "message": self.client.revoke_token()}
        return jsonify(**json)


class Resource(BaseView):
    def __repr__(self):
        name = f"{self.lowered}-{self.lowered_resource}"

        if self.subresource:
            if self.rid and len(str(self.rid)) > 16:
                trunc_rid = str(self.rid).split("-")[0]
                prefix = f"[id:{trunc_rid}]"
            elif self.rid:
                prefix = f"[id:{self.rid}]"
            else:
                prefix = f"[pos:{self.pos}]" if self.use_default else "[id:None]"

            name += f"{prefix}-{self.lowered_subresource}"

        if self.id and len(str(self.id)) > 16:
            trunc_id = str(self.id).split("-")[0]
            name += f"[id:{trunc_id}]"
        elif self.id:
            name += f"[id:{self.id}]"
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
            >>> qb_transactions = Resource("qb", "TransactionList", **kwargs)
        """
        super().__init__(prefix, **kwargs)
        self.resource = resource
        self.subresource = kwargs.get("subresource", "")
        self.subresource_id = kwargs.get("subresource_id")
        self.lowered_resource = self.resource.lower()
        self.lowered_subresource = self.subresource.lower()

        self.fields = kwargs.get("fields", [])
        self.map_factory = kwargs.get("map_factory", reg_mapper)
        self.entry_factory = kwargs.get("entry_factory")
        self.eof = False

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
        self._result_key = kwargs.get("result_key", "result")
        self._rid = kwargs.get("rid")
        self._use_default = kwargs.get("use_default")
        self._dictify = kwargs.get("dictify")
        self._subkey = kwargs.get("subkey")
        self._pos = kwargs.get("pos", 0)
        self._mapper = {}
        self._data = None
        self._mappings = None
        self._results = None
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

    def patch_response(self, *args, **kwargs):
        raise NotImplementedError

    def get_json_response(self, *args, **kwargs):
        raise NotImplementedError

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
    def result_key(self):
        _result_key = self._result_key

        if self.subkey:
            _result_key += f".{self.subkey}.0"

        return _result_key

    @property
    def single_result_key(self):
        return self._result_key

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
                logger.error(f"{self.data_p} not found!")
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
        if value is not None:
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

        if self.domain and not self.ignore_domain:
            url += f"/{self.domain}"

        if self.is_xero:
            url += ".xro/2.0"

        if self.is_qb:
            # https://developer.intuit.com/app/developer/qbo/docs/api/accounting/report-entities/transactionlist
            url += f"/company/{client.realm_id}/reports"
        if self.is_cloze:
            url += f"/{self.verb}"
        elif self.is_timely:
            url += f"/{self.client.account_id}"

        if url:
            url += f"/{self.resource}"

        if self.subresource and url:
            if self.rid:
                url += f"/{self.rid}/{self.subresource}"
            elif not self.eof:
                assert self.rid, (f"No {self} {self.resource} id provided!", 404)

        if self.options and url and not self.id:
            url += f"?{self.options}"

        if self.dry_run:
            url = ""

        if self.resource == "status":
            url = Auth(self.prefix).status_url

        return url

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
    def pos(self):
        return int(self.values.get("pos", self._pos))

    @pos.setter
    def pos(self, value):
        self._values["pos"] = value

    @property
    def start(self):
        value = self.values.get("start", self._start)

        try:
            value = value.strftime("%Y-%m-%d")
        except AttributeError:
            pass

        return value

    @start.setter
    def start(self, value):
        self._values["start"] = value

    @property
    def end(self):
        value = self.values.get("end", self._end)

        try:
            value = value.strftime("%Y-%m-%d")
        except AttributeError:
            pass

        return value

    @end.setter
    def end(self, value):
        self._values["end"] = value

    def mapper(self, prefix):
        _mapper = self._mapper.get(prefix)

        if _mapper is None:
            if self.mappings and self.map_factory:
                map_factory_args = (self.mappings, prefix.lower(), self.lowered)
                _mapper = dict(self.map_factory(*map_factory_args))
            else:
                _mapper = {} if self.map_factory else None

            self._mapper[prefix] = _mapper

        return _mapper

    def get_post_data(self, item, name, rid, prefix=None, **kwargs):
        data = {}
        data[self.name_field] = name
        return data

    def create_model(self, data):
        model = {}

        if data:
            response = self.post(**data)
            json = response.json

            if json["ok"]:
                model = DotDict(json).get(self.single_result_key)
            else:
                logger.error(json.get("message"))

        return model

    def extract_model(self, _id=None, strict=False, **kwargs):
        response = self.get(_id, **kwargs)
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

    def update_mappings(self, rid, prefix=None):
        entry = {}

        if self.entry_factory:
            entry = self.entry_factory(self.id, rid, prefix=prefix)
        elif rid:
            entry[prefix.lower()] = rid
            entry[self.lowered] = self.id

        if entry:
            self.mappings = self.mappings + [entry]

            if self._mapper.get(prefix):
                self._mapper[prefix] = None

    def update_data(self, **kwargs):
        if kwargs:
            entry = dict(extract_fields(kwargs, *self.fields))

            for _entry in self.data:
                if entry == _entry:
                    break
            else:
                self.data = list(self.data) + [entry]

    def map_rid(self, rid, prefix=None, **kwargs):
        return self.mapper(prefix).get(rid)

    def convert(self, source):
        if self.subresource:
            assert self.rid, (f"No rid entered for {self}.", 404)

        try:
            has_id_func = self.id_func
        except AttributeError:
            has_id_func = False

        def converter(source_item, rid=None):
            dry_run, self.dry_run = self.dry_run, True
            source_name = dispaly_name = source_item[source.name_field]
            ekwargs = {"prefix": source.prefix}

            if rid:
                dispaly_name += f" {rid}"
            else:
                rid = source_item[source.id_field]
                ekwargs["source_name"] = source_name

            dest_id = self.map_rid(rid, prefix=source.prefix)
            needs_update = not dest_id
            ekwargs.update({"_id": dest_id, "source_rid": rid})
            dest_item = self.extract_model(**ekwargs)

            args = (source_item, source_name, rid)

            if has_id_func and not dest_item:
                logger.info(
                    f"{dispaly_name} not found in {self} cache. Select a mapping."
                )
                dest_id = self.id_func(*args, prefix=source.prefix)

                if dest_id:
                    dest_item = self.extract_model(dest_id, update_cache=True)
            elif not dest_item:
                logger.warning(
                    f"Unable to present {self.prefix} {self.resource} mapping choices without an id_func!"
                )

            self.dry_run = dry_run

            if not (dest_item or dry_run):
                message = f"No mapping available for {dispaly_name} in {self}. "
                message += f"Do you want to create a new {self.prefix} {self.resource}"

                if self.subresource:
                    message += f"-{self.subresource}"

                message += " entry for it?"
                answer = fetch_bool(message)

                if answer == "y":
                    data = self.get_post_data(
                        *args, prefix=source.prefix, source_prefix=source.prefix
                    )
                else:
                    data = {}

                if data:
                    dest_item = self.create_model(data)

            if dry_run:
                error_msg = f"Disable dry_run mode to create {self} mapping."
            else:
                error_msg = f"Manually add {dispaly_name} to {self}."

            assert dest_item, (error_msg, 404)

            if needs_update:
                self.id = dest_item[self.id_field]
                self.update_mappings(rid, prefix=source.prefix)
                self.update_data(**dest_item)

            return dest_item

        return converter

    @classmethod
    def from_source(
        cls, source_item, dry_run=True, rid=None, source_rid=None, **kwargs
    ):
        dest_prefix = kwargs["dest_prefix"]
        dest_collection = get_collection(dest_prefix, cls.__name__)
        dest = dest_collection(dry_run=dry_run, prefix=dest_prefix, rid=rid)

        source_prefix = kwargs["source_prefix"]
        source_collection = get_collection(source_prefix, cls.__name__)
        source = source_collection(dry_run=dry_run, prefix=source_prefix)
        converter = dest.convert(source)
        return converter(source_item, rid=source_rid)

    def get(self, _id=None, rid=None, source_rid=None, source_name=None, **kwargs):
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
            >>> qb_transactions = Resource("qb", "TransactionList", **kwargs)
            >>> qb_transactions.get()
        """
        self.id = self.values.pop("id", _id) or self.id
        self.rid = self.values.pop("rid", rid) or self.rid

        if self.data and not self.id and source_name is not None:
            try:
                result = next(x for x in self if source_name == x[self.name_field])
            except StopIteration:
                pass
            else:
                self.id = result[self.id_field]

        if not self.id and source_rid:
            self.id = self.map_rid(source_rid, **kwargs)

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
            json = {"result": result, "ok": ok, "status_code": status_code}
        else:
            try:
                self.client.json = self.get_json_response()
            except NotImplementedError:
                try:
                    url = self.api_url
                except AssertionError as err:
                    url = None
                    self.error_msg, status_code = err.args[0]
                else:
                    if url and self.id:
                        url += f"/{self.id}"
                    elif source_name or source_rid:
                        url = None

                if url:
                    headers = {**self.headers, **kwargs.get("headers", {})}
                    rkwargs = {"headers": headers, "params": self.params, **app.config}
                    json = get_json_response(url, self.client, **rkwargs)
                else:
                    json = {
                        "message": "No API url provided!",
                        "result": {},
                        "ok": False,
                        "status_code": 404,
                    }
            else:
                json = get_json_response(None, self.client)

        result = json.get("result")

        if self.dry_run:
            result = listize(result)

            if self.filterer and not self.id:
                result = list(filter(self.filterer, result))
        elif json["ok"]:
            if self.subkey:
                try:
                    result = result.get(self.subkey, result)
                except AttributeError:
                    pass

            result = listize(result)
            pkwargs = {"black_list": self.black_list}
            result = list(self.processor(result, self.fields, **pkwargs))

            if self.filterer and not self.id:
                result = list(filter(self.filterer, result))

            if self.use_default and not self.id:
                try:
                    result = result[self.pos]
                except (IndexError, TypeError):
                    self.eof = True
                else:
                    self.id = result.get(self.id_field)

            if result is not None and kwargs.get("update_cache") and not self.id:
                self.data = result

        if self.error_msg:
            logger.error(self.error_msg)
            json["message"] = f"{self.error_msg}: {url}"

        json["result"] = result
        return jsonify(**json)

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
        values = remove_keys(self.values, black_list)
        data = {**values, **kwargs}

        if self.is_cloze:
            self.verb = "create"
        elif self.is_timely:
            data = {singularize(self.resource): data}

        if self.dry_run:
            json = {
                "result": data,
                "ok": True,
                "message": f"Disable dry_run mode to POST {self}.",
            }
        else:
            rkwargs[self.data_key] = dumps(data) if self.dump_data else data
            json = get_json_response(self.api_url, self.client, **rkwargs)

        if self.error_msg:
            logger.error(self.error_msg)
            json["message"] = self.error_msg

        if not self.dry_run:
            try:
                json["links"] = get_links(app.url_map.iter_rules())
            except RuntimeError:
                pass

        return jsonify(**json)

    def patch(self, _id=None, rid=None, **kwargs):
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
        self.id = self.values.pop("id", _id) or self.id
        self.rid = self.values.pop("rid", rid) or self.rid

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
        values = remove_keys(self.values, black_list)
        data = {**values, **kwargs}
        data[self.id_field] = self.id
        json = {}

        if not self.id:
            self.error_msg = f"No {self} ID given!"
            json = {"status_code": 404}

        if self.is_timely:
            rkwargs["method"] = "put"
            data = {singularize(self.resource): data}

        if self.dry_run:
            json = {
                "result": data,
                "ok": True,
                "message": f"Disable dry_run mode to PATCH {self}.",
            }
        else:
            try:
                self.client.response = self.patch_response(**data)
            except NotImplementedError:
                pass
            else:
                json = get_json_response(None, self.client)

        if not json:
            url = f"{self.api_url}/{self.id}"
            rkwargs[self.data_key] = dumps(data) if self.dump_data else data
            json = get_json_response(url, self.client, **rkwargs)

        json["id"] = self.id

        if not self.dry_run:
            try:
                json["links"] = get_links(app.url_map.iter_rules())
            except RuntimeError:
                pass

        if self.error_msg:
            logger.error(self.error_msg)
            json["message"] = self.error_msg

        return jsonify(**json)

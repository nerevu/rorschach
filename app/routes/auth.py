# -*- coding: utf-8 -*-
""" app.routes.auth
~~~~~~~~~~~~~~~~~~~
Provides Auth routes.

"""
from datetime import date, datetime as dt, timedelta
from itertools import islice
from json import dump, dumps, loads
from json.decoder import JSONDecodeError
from pathlib import Path

import pygogo as gogo

from flask import (
    current_app as app,
    has_app_context,
    redirect,
    request,
    session,
    url_for,
)
from flask.views import MethodView
from meza.fntools import listize, remove_keys
from riko.dotdict import DotDict

from app import cache
from app.authclient import callback, get_auth_client, get_json_response
from app.helpers import flask_formatter as formatter, get_collection, singularize
from app.routes import ProviderMixin
from app.utils import extract_field, extract_fields, get_links, jsonify
from config import Config

logger = gogo.Gogo(
    __name__, low_formatter=formatter, high_formatter=formatter, monolog=True
).logger
logger.propagate = False

APP_DIR = Path(__file__).parents[1]
DATA_DIR = APP_DIR.joinpath("data")
RESOURCES = Config.RESOURCES


def process_result(result, fields=None, black_list=None, **kwargs):
    if black_list:
        result = (remove_keys(item, *black_list) for item in result)

    if fields:
        result = (dict(extract_fields(item, *fields)) for item in result)

    if kwargs:
        result = ({**item, **kwargs} for item in result)

    return result


def store(prefix, collection_name, verbose=0, **kwargs):
    logger.setLevel(LOG_LEVELS[verbose])
    Collection = get_collection(prefix, collection_name)

    if Collection:
        collection = Collection(prefix, **kwargs)
        response = collection.get(update_cache=True)
        json = response.json
    else:
        message = f"Collection `{collection_name}` doesn't exist in `{prefix}`."
        json = {"ok": False, "message": message}

    if json["ok"]:
        logger.debug(f"Success storing {collection}!")
    else:
        logger.error(json["message"])


class BaseView(ProviderMixin, MethodView):
    def __init__(self, prefix=None, **kwargs):
        super().__init__(prefix)
        self._client = None
        self.rkwargs = kwargs

    @property
    def client(self):
        if has_app_context() and self._client is None:
            self._client = get_auth_client(self.prefix, **app.config, **self.rkwargs)

        return self._client

    @property
    def tenant_path(self):
        if self.client:
            return self.client.tenant_path


class Callback(BaseView):
    def get(self):
        return callback(self.prefix)


class Auth(BaseView):
    def get(self):
        """Step 1: User Authorization.

        Redirect the user/resource owner to the OAuth provider (i.e. Github)
        using a URL with a few key OAuth parameters.
        """
        cache.set(f"{self.prefix}_callback_url", request.args.get("callback_url"))
        Status = Resource._registry[self.prefix]["Status"]
        status = Status(prefix=self.prefix, resource="status")
        json = status.get_live_json()
        client = self.client

        if client.oauth_version:
            # https://gist.github.com/ib-lundgren/6507798#gistcomment-1006218
            # State is used to prevent CSRF, keep this for later.
            authorization_url, state = client.authorization_url
            client.state = session[f"{self.prefix}_state"] = state
            client.save()

        # Step 2: User authorization, this happens on the provider.
        if client.oauth_version and client.verified and not client.expired:
            json.update({k: getattr(client, k) for k in ["token", "state", "realm_id"]})

            if self.tenant_path:
                client.tenant_id = extract_field(json, self.tenant_path)

                if client.tenant_id:
                    client.save()
                    json.update({"tenant_id": client.tenant_id})
                    logger.debug(f"Set {client} tenant_id to {client.tenant_id}.")
                else:
                    client.error = "{tenant_path} not found!"

            result = jsonify(**json)
        elif client.oauth_version:
            if client.oauth1:
                # clear previously cached token
                client.renew_token()
                authorization_url = client.authorization_url[0]

            redirect_url = authorization_url
            logger.info("redirecting to %s", redirect_url)
            result = redirect(redirect_url)
        else:
            result = jsonify(**json)

        return result

    def patch(self):
        self.client.renew_token()
        return redirect(url_for(f".{self.prefix}-auth".lower()))

    def delete(self, base=None):
        # TODO: find out where this was implemented
        json = {"status_code": 200, "message": self.client.revoke_token()}
        return jsonify(**json)


class Resource(BaseView):
    _registry = {prefix: {} for prefix in RESOURCES}
    rkwargs = {}
    prefix = None
    resource = None
    auth_key = None

    @classmethod
    def __init_subclass__(cls, prefix=None, resource=None, auth_key=None, **kwargs):
        if prefix is not None:
            cls.rkwargs = kwargs
            cls.prefix = prefix
            cls.resource = resource
            cls.auth_key = auth_key
            cls._registry[prefix][cls.__name__] = cls

    def __init__(self, prefix=None, resource=None, **kwargs):
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
            >>> params = {
            ...     "start_date: start,
            ...     "end_date": end,
            ...     "columns": "name,net_amount"
            ... }
            >>> kwargs = {"params": params}
            >>> qb_transactions = Resource("qb", "TransactionList", **kwargs)
        """
        self.prefix = prefix or self.prefix
        self.rkwargs["resource"] = resource or self.resource
        super().__init__(self.prefix, **self.rkwargs, **kwargs)

        self._data = None
        self._results = None
        self._result_key = self.rkwargs.get("result_key", "result")
        self._dictify = self.rkwargs.get("dictify")
        self._all_params = None
        self._rid = self.rkwargs.get("rid")
        self._dry_run = self.rkwargs.get("dry_run")
        self._use_default = self.rkwargs.get("use_default")
        self._singularize = self.rkwargs.get("singularize")
        self._dump_data = self.rkwargs.get("dump_data")
        self._json_data = self.rkwargs.get("json_data")
        self._params = self.rkwargs.get("params", {})
        self._start = self.rkwargs.get("start")
        self._end = self.rkwargs.get("end", date.today())
        self._pos = self.rkwargs.get("pos", 0)
        self._subkey = self.rkwargs.get("subkey")

        self.url = None
        self.eof = False
        self.error_msg = ""
        self.resource = self.resource or resource or ""
        self.lowered_resource = self.resource.lower()
        self.processor = self.rkwargs.get("processor", process_result)
        self.black_list = set(self.rkwargs.get("black_list", []))
        self.populate = self.rkwargs.get("populate")
        self.filterer = self.rkwargs.get("filterer")
        self.subresource = self.rkwargs.get("subresource", "")
        self.subresource_id = self.rkwargs.get("subresource_id")
        self.lowered_subresource = self.subresource.lower()
        self.name = f"{self.lowered}-{self.lowered_resource}"
        self.datefmt = self.rkwargs.get("datefmt", "%Y-%m-%d")
        self.fields = self.rkwargs.get("fields", [])
        self.headers = self.rkwargs.get("headers", {})

        try:
            def_id_field = next(f for f in self.fields if "id" in f.lower())
        except StopIteration:
            def_id_field = "id"

        try:
            def_name_field = next(f for f in self.fields if "name" in f.lower())
        except StopIteration:
            def_name_field = "name"

        self.id_field = self.rkwargs.get("id_field", def_id_field)
        self.name_field = self.rkwargs.get("name_field", def_name_field)

        results_filename = self.rkwargs.get("results_filename", "sync_results.json")
        self.results_p = DATA_DIR.joinpath(results_filename)

    def __iter__(self):
        yield from self.data.values() if self.dictify else self.data

    def __getitem__(self, key):
        return self.data[key]

    def __repr__(self):
        name = f"{self.lowered}-{self.lowered_resource}"

        if self.subresource:
            if self.rid and "-" in str(self.rid):
                trunc_rid = self.rid.split("-")[0]
                prefix = f"[id:{trunc_rid}]"
            elif self.rid:
                prefix = f"[id:{self.rid}]"
            else:
                prefix = f"[pos:{self.pos}]" if self.use_default else "[all ids]"

            name += f"{prefix}-{self.lowered_subresource}"

        if self.id and "-" in str(self.id):
            trunc_id = self.id.split("-")[0]
            name += f"[id:{trunc_id}]"
        elif self.id:
            name += f"[id:{self.id}]"
        else:
            name += f"[pos:{self.pos}]" if self.use_default else "[all ids]"

        return name

    @property
    def fkwargs(self):
        fkwargs = {**self.client.__dict__, **self.client.attrs} if self.client else {}
        fkwargs.update({**self.__dict__, **self.rkwargs})
        return fkwargs

    @property
    def default_rid(self):
        try:
            item = list(islice(self, self.pos, self.pos + 1))[0]
        except (IndexError, TypeError):
            item = None

        return item.get(self.id_field) if item else None

    @property
    def rid(self):
        if self.use_default and not self._rid:
            if rid := self.default_rid:
                self._rid = rid
            else:
                name = self.name
                self.eof = True

                if self.subresource:
                    name += f"-{self.lowered_subresource}"

                if self.data:
                    logger.error(f"{name}[{self.pos}] not found in cache!")
                else:
                    logger.error(f"No {name} cached data available!")

        return self._rid

    @rid.setter
    def rid(self, value):
        self._rid = value

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

    @property
    def api_url(self):
        client = self.client

        if client.api_base_url and not self.dry_run:
            assert self.resource, (f"No {self} resource provided!", 404)
            api_base_url = client.api_base_url.format(**self.fkwargs)
            url = f"{api_base_url}/{self.resource}"

            if self.subresource:
                if self.rid and client.rid_last:
                    url += f"/{self.subresource}/{self.rid}"
                elif self.rid:
                    url += f"/{self.rid}/{self.subresource}"
                elif not self.eof:
                    message = f"No {self} {self.resource} id provided!"
                    assert self.rid, (message, 404)

            if client.api_ext:
                url += f".{client.api_ext}"
        else:
            url = ""

        return url

    @property
    def json_data(self):
        if self.client and self._json_data is None:
            self._json_data = self.client.attrs.get("json_data", True)

        return self._json_data

    @property
    def data_key(self):
        return "json" if self.json_data else "data"

    @property
    def singularize(self):
        if self.client and self._singularize is None:
            self._singularize = self.client.attrs.get("singularize")

        return self._singularize

    @property
    def dump_data(self):
        if self.client and self._dump_data is None:
            self._dump_data = self.client.attrs.get("dump_data")

        return self._dump_data

    @property
    def verb_map(self):
        if self.client:
            return self.client.verb_map

    @property
    def method_map(self):
        if self.client:
            return self.client.method_map

    @property
    def dry_run(self):
        return self.values.get("dryRun", self._dry_run)

    @property
    def use_default(self):
        return self.values.get("useDefault", self._use_default)

    @property
    def dictify(self):
        return self.values.get("dictify", self._dictify)

    @property
    def pos(self):
        return int(self.values.get("pos", self._pos))

    @property
    def end(self):
        end = self.values.get("end", self._end)

        try:
            return end.strftime(self.datefmt)
        except AttributeError:
            return end

    @property
    def start(self):
        start = self.values.get("start", self._start)

        if start is None:
            days = app.config["REPORT_DAYS"] if self.client else Config.REPORT_DAYS
            start = dt.strptime(self.end, (self.datefmt)) - timedelta(days=days)

        try:
            return start.strftime(self.datefmt)
        except AttributeError:
            return start

    @property
    def subkey(self):
        if self.client and self._subkey is None:
            self._subkey = self.client.attrs.get("subkey", self._subkey)

        return self.values.get("subkey", self._subkey)

    @property
    def all_params(self):
        if self._all_params is None:
            params = self.client.params if self.client else {}
            self._all_params = {**params, **self._params}

        return self._all_params

    @property
    def params(self):
        params = self.all_params or {}

        if self.client and self.id:
            id_param = self.client.param_map.get("id")
            params[id_param] = self.id

        if self.client and self.fields:
            fields_param = self.client.param_map.get("fields")
            params[fields_param] = ",".join(self.fields)

        if self.client and self.start:
            start_param = self.client.param_map.get("start")
            params[start_param] = self.start

        if self.client and self.end:
            end_param = self.client.param_map.get("end")
            params[end_param] = self.end

        return params

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
        if self.subresource:
            rid = self._rid

            if self.use_default and not rid:
                rid = self.fetch_cls()().default_rid

            if rid:
                split_id = rid.split("-")[0] if "-" in str(rid) else rid

                self.data_filename = (
                    f"{self.lowered}_{split_id}_{self.lowered_subresource}.json"
                )
            else:
                self.data_filename = None
                self.error_msg = f"No {self.name} ID given!"
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
            except FileNotFoundError:
                logger.warning(f"{self.data_p} not found!")
                self.data_content = None
            except AttributeError:
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

    def fetch_cls(self, cls_name=None):
        cls_name = cls_name or self.resource.title()
        return self._registry[self.prefix].get(cls_name)

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

    def extract_model(self, _id=None, strict=False, as_collection=False, **kwargs):
        response = self.get(_id, **kwargs)
        json = response.json
        result = [] if self.eof else json["result"]

        if as_collection:
            model = result
        else:
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

            if not as_collection:
                assert model.get(self.id_field), (f"{self} has no ID!", 500)

        return model

    def update_data(self, **kwargs):
        if kwargs:
            entry = dict(extract_fields(kwargs, *self.fields))

            for _entry in self.data:
                if entry == _entry:
                    break
            else:
                self.data = list(self.data) + [entry]

    def filter_result(self, *args):
        if self.filterer and not self.id:
            result = list(filter(self.filterer, args))
        else:
            result = args

        return result

    def parse_result(self, *args):
        try:
            result = args[self.pos]
        except (IndexError, TypeError):
            result = None
            self.eof = True
        else:
            self.id = result.get(self.id_field)

        return result

    def get_response(self, *args, **kwargs):
        raise NotImplementedError

    def patch_response(self, *args, **kwargs):
        raise NotImplementedError

    def get_dry_run_json(self, **kwargs):
        if self.id and self.dictify:
            try:
                result = self.data.get(int(self.id), {})
            except ValueError:
                result = self.data.get(str(self.id), {})
        elif self.id:
            try:
                result = next(x for x in self if str(self.id) == str(x[self.id_field]))
            except StopIteration:
                result = {}
        else:
            result = self.data

        status_code = 200 if result else 404
        ok = status_code == 200
        return {"result": result, "ok": ok, "status_code": status_code}

    def get_live_json(self, **kwargs):
        try:
            self.client.json = self.get_response()
        except NotImplementedError:
            try:
                self.url = self.api_url
            except AssertionError as err:
                self.url = None
                self.error_msg, status_code = err.args[0]
            else:
                if self.url and self.id:
                    self.url += f"/{self.id}"

            if self.url:
                headers = {**self.headers, **kwargs.get("headers", {})}
                rkwargs = {"headers": headers, "params": self.params, **self.kwargs}
                json = get_json_response(self.url, self.client, **rkwargs)
            else:
                json = {
                    "message": "No API url provided!",
                    "result": {},
                    "ok": False,
                    "status_code": 404,
                }
        else:
            json = get_json_response(None, self.client)

        return json

    def patch_live_json(self, data=None, **kwargs):
        try:
            self.client.json = self.patch_response(**data)
        except NotImplementedError:
            try:
                self.url = self.api_url
            except AssertionError as err:
                self.url = None
                self.error_msg, status_code = err.args[0]
            else:
                if self.url and self.id:
                    self.url += f"/{self.id}"

            if self.url:
                headers = {**self.headers, **kwargs.get("headers", {})}
                method = self.method_map.get("patch", "patch")
                rkwargs = {"headers": headers, "method": method, **self.kwargs}
                rkwargs[self.data_key] = dumps(data) if self.dump_data else data
                json = get_json_response(self.url, self.client, **rkwargs)
            else:
                json = {
                    "message": "No API url provided!",
                    "result": {},
                    "ok": False,
                    "status_code": 404,
                }
        else:
            json = get_json_response(None, self.client)

        return json

    def get(self, _id=None, rid=None, **kwargs):
        """Get an API Resource.
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
        if self.verb_map:
            self.client.verb = self.verb_map.get("get")

        self.id = self.values.pop("id", _id) or self.id
        self.rid = self.values.pop("rid", rid) or self.rid

        if self.dry_run:
            json = self.get_dry_run_json(**kwargs)
        else:
            json = self.get_live_json(**kwargs)

        result = json.get("result")

        if self.dry_run:
            result = self.filter_result(*listize(result))
        elif json["ok"]:
            if self.subkey:
                result = DotDict(result).get(self.subkey, result)

            pkwargs = {"black_list": self.black_list}
            _result = list(self.processor(listize(result), self.fields, **pkwargs))
            result = self.filter_result(*_result)

            if self.use_default and not self.id:
                result = self.parse_result(*result)

            if result is not None and kwargs.get("update_cache") and not self.id:
                self.data = result

        if self.error_msg:
            logger.error(self.error_msg)
            json["message"] = f"{self.error_msg}: {self.url}"

        json["result"] = result
        return jsonify(**json)

    def post(self, **kwargs):
        """Create an API Resource.

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
        if self.verb_map:
            self.client.verb = self.verb_map.get("post")

        rkwargs = {"headers": self.headers, "method": "post", **self.kwargs}
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

        if self.singularize:
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
        """Upate an API Resource.
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
        if self.verb_map:
            self.client.verb = self.verb_map.get("patch")

        self.id = self.values.pop("id", _id) or self.id
        self.rid = self.values.pop("rid", rid) or self.rid

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
        json = {}

        if not self.id:
            self.error_msg = f"No {self} ID given!"
            json = {"status_code": 404}

        if self.singularize:
            data = {singularize(self.resource): data}

        if self.dry_run:
            json = {
                "result": data,
                "ok": True,
                "message": f"Disable dry_run mode to PATCH {self}.",
            }
        else:
            json = self.patch_live_json(data=data, **kwargs)

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

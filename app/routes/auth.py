from flask import (
    after_this_request,
    current_app as app,
    request,
    url_for,
    redirect,
    session,
)

from flask.views import MethodView

from app.authclient import get_auth_client, get_response, callback
from app.utils import HEADERS


class BaseView(MethodView):
    def __init__(self, prefix, **kwargs):
        values = request.values or {}
        json = request.json or {}

        self.prefix = prefix
        self.values = {**values, **json}
        self.lowered = self.prefix.lower()
        self.is_timely = self.prefix == "TIMELY"
        self.is_xero = self.prefix == "XERO"

        self.dry_run = self.values.pop("dryRun", "").lower() == "true"

        if self.dry_run:
            self.client = None
            self._headers = None
        else:
            self.client = get_auth_client(self.prefix, **app.config)
            self._headers = {**kwargs.get("headers", HEADERS), **self.client.headers}
            self._params = {**kwargs.get("params", {}), **self.client.auth_params}


    @property
    def headers(self):
        headers = self._headers

        if self.is_xero and self.client.oauth2:
            headers["Xero-tenant-id"] = self.client.tenant_id

        return headers


class Callback(BaseView):
    def __init__(self, prefix):
        super().__init__(prefix)

    def get(self):
        return callback(prefix)


class Auth(BaseView):
    def __init__(self, prefix):
        super().__init__(prefix)

        self.status_urls = {
            # TODO: Timely Headless Auth returns an error message
            # saying "invalid_grant", but it also returns the valid
            # credentials with the error message. Authentication is
            # working fine I guess, but we should really look into
            # making this work a little smoother.
            "TIMELY": f"{self.client.api_base_url}/accounts"
            "XERO": f"{self.client.api_base_url}/projects.xro/2.0/projectsusers"
            "QB": f"{self.client.api_base_url}/company/{self.client.realm_id}/companyinfo/{self.client.realm_id}"
        }

    def get(self):
        """Step 1: User Authorization.

        Redirect the user/resource owner to the OAuth provider (i.e. Github)
        using an URL with a few key OAuth parameters.
        """
        cache.set(f"{self.prefix}_callback_url") = request.args.get("callback_url")

        # https://gist.github.com/ib-lundgren/6507798#gistcomment-1006218
        # State is used to prevent CSRF, keep this for later.
        authorization_url, state = self.client.authorization_url
        self.client.state = session[f"{self.prefix}_state"] = state
        self.client.save()

        # Step 2: User authorization, this happens on the provider.
        if self.client.verified and not self.client.expired:
            status_url = self.status_urls[self.prefix]
            response = get_response(status_url, self.client, **app.config)
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
        return redirect(url_for(f".{self.prefix}_auth".lower()))


    def delete(self, base=None):
        # TODO: find out where this was implemented
        response = {"status_code": 200, "message": self.client.revoke_token()}
        return jsonify(**response)


class Resource(BaseView):
    def __init__(self, prefix, **kwargs):
        """ An API Resource.

        Args:
            prefix (str): The API.

        Kwargs:
            resource (str): The API resource.
            rid (str): The API resource_id.
            result_field (str): The API result field to return.

        Examples:
            >>> kwargs = {
            >>>     "resource": "products",
            >>>     "result_field": "manufacturer",
            >>> }
            >>> opencart_manufacturer = Resource("OPENCART", **kwargs)
            >>>
            >>> kwargs = {
            >>>     "resource": "people",
            >>>     "result_field": "person",
            >>> }
            >>> cloze_person = Resource("CLOZE", **kwargs)
            >>>
            >>> kwargs = {
            >>>     "resource": "TransactionList",
            >>>     "options": f"start_date={start}&end_date={end}&columns=name,net_amount",
            >>> }
            >>> qb_transactions = Resource("QB", **kwargs)
        """
        super().__init__(prefix)
        self.resource = kwargs.get("resource")
        self.rid = kwargs.get("rid", "")
        self.id_field = kwargs.get("id_field", "id")
        self._result_field = kwargs.get("result_field")
        self.options = kwargs.get("options", "")
        self.verb = "get"
        self.error_msg = ""

    @property
    def params(self):
        params = self._params

        if self.is_cloze and self.rid:
            params["uniqueid"] = self.rid

        return params

    @property
    def api_base_url(self):
        client = self.client
        api_base_url = client.api_base_url

        if self.dry_run:
            url = ""
        elif self.is_timely:
            url = f"{api_base_url}/{self.resource}/{self.rid}"
        elif self.is_xero:
            url = f"{api_base_url}/{self.resource}.xro/2.0"
        elif self.is_opencart:
            url = f"{api_base_url}/{self.resource}/{self.rid}"
        elif self.is_cloze:
            url = f"{api_base_url}/{self.resource}/{self.verb}"
        elif self.is_qb:
            # https://developer.intuit.com/app/developer/qbo/docs/api/accounting/report-entities/transactionlist
            url = f"{api_base_url}/company/{client.realm_id}/reports/{self.resource}?{self.options}"

        return url

    @property
    def dictify(self):
        return self.values.get("dictify", "").lower() == "true"

    @property
    def result_fields(self):
        return list(self.gen_result_fields())

    def gen_result_fields(self):
        if self.client.api_subkey:
            yield self.client.api_subkey

        if self._result_field
            yield self._result_field

    def get(self, rid=None):
        """ Get an API Resource.
        Kwargs:
            resource (str): The API resource.
            rid (str): The API resource_id.

        Examples:
            >>> kwargs = {
            >>>     "resource": "products",
            >>>     "rid": "abc",
            >>>     "result_field": "manufacturer",
            >>> }
            >>> opencart_manufacturer = Resource("OPENCART", **kwargs)
            >>> opencart_manufacturer.get()
            >>>
            >>> kwargs = {
            >>>     "resource": "people",
            >>>     "result_field": "person",
            >>> }
            >>> cloze_person = Resource("CLOZE", **kwargs)
            >>> cloze_person.get(rid="name@company.com")
            >>>
            >>> kwargs = {
            >>>     "resource": "TransactionList",
            >>>     "options": f"start_date={start}&end_date={end}&columns=name,net_amount",
            >>> }
            >>> qb_transactions = Resource("QB", **kwargs)
            >>> qb_transactions.get()
        """
        self.rid = rid or self.rid

        if self.dry_run:
            response = {"result": []}
        else:
            response = get_response(
                self.api_url,
                self.client,
                headers=self.headers,
                params=self.params,
                result_fields=self.result_fields,
                **app.config,
            )

        result = response.get("result")

        if self.dictify and result:
            result = ((item.get(self.id_field), item) for item in result)
            response["result"] = dict(result)
        else:
            response["result"] = result

        return jsonify(**response)

    def post(self, **data):
        """ Create an API Resource.
        Args:
            data (dict): The data to post.

        Examples:
            >>> kwargs = {"resource": "products"}
            >>> opencart_product = Resource("XERO", **kwargs)
            >>> url = 'http://localhost:5000/v1/opencart-resource'
            >>> requests.post(url, data={})
            >>>
            >>> kwargs = {"resource": "people"}
            >>> cloze_person = Resource("CLOZE", **kwargs)
            >>> data = {"name": "name", "emails": ["value": "email"]}
            >>> cloze_person.post(**data)
        """
        kwargs = {**app.config, "headers": self.headers, "method": "post"}
        props = {"dictify", "contacts"}
        values = {k: v for k, v in self.values.items() if k not in props}
        values.update(data)
        data_key = "data"

        if self.dry_run:
            response = {"result": {}}
        elif self.is_cloze:
            self.verb = "create"
            kwargs[data_key] = dumps(values)
            kwargs[headers]["Content-Type"] = "application/json"
            response = get_response(self.api_url, self.client, **kwargs)
        elif self.is_xero:
            if self.resource == "api":
                data_key = "json"

            kwargs[data_key] = values
            response = get_response(self.api_url, self.client, **kwargs)
        elif self.is_timely:
            data_key = "json"
            kwargs[data_key] = {singularize(self.resource): values}
            response = get_response(self.api_url, self.client, **kwargs)
        else:
            base_url = get_request_base()
            self.error_msg = (
                f"The {request.method}:{base_url} route is not yet enabled."
            )
            response = {"status_code": 404}

        response["links"] = get_links(app.url_map.iter_rules())

        if self.error_msg:
            response["message"] = self.error_msg

        return jsonify(**response)

# To use this code, make sure you
#
#     import json
#
# and then, to convert JSON from a string, do
#
#     result = provider_from_dict(json.loads(json_string))

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Type, TypeVar, Union, cast

T = TypeVar("T")


def from_list(f: Callable[[Any], T], x: Any) -> List[T]:
    assert isinstance(x, list)
    return [f(y) for y in x]


def from_str(x: Any) -> str:
    assert isinstance(x, str)
    return x


def from_none(x: Any) -> Any:
    assert x is None
    return x


def from_union(fs, x):
    for f in fs:
        try:
            return f(x)
        except:
            pass
    assert False


def to_class(c: Type[T], x: Any) -> dict:
    assert isinstance(x, c)
    return cast(Any, x).to_dict()


def from_dict(f: Callable[[Any], T], x: Any) -> Dict[str, T]:
    assert isinstance(x, dict)
    return {k: f(v) for (k, v) in x.items()}


def from_bool(x: Any) -> bool:
    assert isinstance(x, bool)
    return x


def from_int(x: Any) -> int:
    assert isinstance(x, int) and not isinstance(x, bool)
    return x


@dataclass
class Conditional:
    """description"""

    """description"""
    results: Optional[List[str]]
    """description"""
    test: Optional[str]

    @staticmethod
    def from_dict(obj: Any) -> "Conditional":
        assert isinstance(obj, dict)
        results = from_union(
            [lambda x: from_list(from_str, x), from_none], obj.get("results")
        )
        test = from_union([from_none, from_str], obj.get("test"))
        return Conditional(results, test)

    def to_dict(self) -> dict:
        result: dict = {}
        result["results"] = from_union(
            [lambda x: from_list(from_str, x), from_none], self.results
        )
        result["test"] = from_union([from_none, from_str], self.test)
        return result


@dataclass
class AttrClass:
    """description"""

    conditional: Optional[Conditional]
    """Function to apply to the Status resource json response"""
    func: Optional[str]
    """Path to the attribute relative to the Status resource json response"""
    path: Optional[str]

    @staticmethod
    def from_dict(obj: Any) -> "AttrClass":
        assert isinstance(obj, dict)
        conditional = from_union(
            [Conditional.from_dict, from_none], obj.get("conditional")
        )
        func = from_union([from_none, from_str], obj.get("func"))
        path = from_union([from_none, from_str], obj.get("path"))
        return AttrClass(conditional, func, path)

    def to_dict(self) -> dict:
        result: dict = {}
        result["conditional"] = from_union(
            [lambda x: to_class(Conditional, x), from_none], self.conditional
        )
        result["func"] = from_union([from_none, from_str], self.func)
        result["path"] = from_union([from_none, from_str], self.path)
        return result


@dataclass
class Headers:
    """HTTP headers to include with requests (case sensitive)"""

    """Include in all requests"""
    all: Optional[Dict[str, Union[bool, AttrClass, int, str]]]
    """Include only in DELETE requests"""
    delete: Optional[Dict[str, Union[bool, AttrClass, int, str]]]
    """Include only in GET requests"""
    get: Optional[Dict[str, Union[bool, AttrClass, int, str]]]
    """Include only in PATCH requests"""
    patch: Optional[Dict[str, Union[bool, AttrClass, int, str]]]
    """Include only in POST requests"""
    post: Optional[Dict[str, Union[bool, AttrClass, int, str]]]
    """Include only in PUT requests"""
    put: Optional[Dict[str, Union[bool, AttrClass, int, str]]]

    @staticmethod
    def from_dict(obj: Any) -> "Headers":
        assert isinstance(obj, dict)
        all = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [from_bool, AttrClass.from_dict, from_int, from_str], x
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("ALL"),
        )
        delete = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [from_bool, AttrClass.from_dict, from_int, from_str], x
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("DELETE"),
        )
        get = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [from_bool, AttrClass.from_dict, from_int, from_str], x
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("GET"),
        )
        patch = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [from_bool, AttrClass.from_dict, from_int, from_str], x
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("PATCH"),
        )
        post = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [from_bool, AttrClass.from_dict, from_int, from_str], x
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("POST"),
        )
        put = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [from_bool, AttrClass.from_dict, from_int, from_str], x
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("PUT"),
        )
        return Headers(all, delete, get, patch, post, put)

    def to_dict(self) -> dict:
        result: dict = {}
        result["ALL"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            self.all,
        )
        result["DELETE"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            self.delete,
        )
        result["GET"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            self.get,
        )
        result["PATCH"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            self.patch,
        )
        result["POST"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            self.post,
        )
        result["PUT"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            self.put,
        )
        return result


@dataclass
class HeadlessElement:
    """An element on a provider's application login page"""

    """User friendly identification of the element"""
    description: str
    """CSS selector of the element"""
    selector: str
    """Action to perform on the element"""
    action: Optional[str]
    """Text to send to the element (can't be mixed with `prompt`)"""
    content: Optional[str]
    """Text to display when requesting user input (can't be mixed with `content`)."""
    prompt: Optional[str]
    """Amount of seconds to wait before executing action"""
    wait: Optional[int]

    @staticmethod
    def from_dict(obj: Any) -> "HeadlessElement":
        assert isinstance(obj, dict)
        description = from_str(obj.get("description"))
        selector = from_str(obj.get("selector"))
        action = from_union([from_none, from_str], obj.get("action"))
        content = from_union([from_none, from_str], obj.get("content"))
        prompt = from_union([from_none, from_str], obj.get("prompt"))
        wait = from_union([from_int, from_none], obj.get("wait"))
        return HeadlessElement(description, selector, action, content, prompt, wait)

    def to_dict(self) -> dict:
        result: dict = {}
        result["description"] = from_str(self.description)
        result["selector"] = from_str(self.selector)
        result["action"] = from_union([from_none, from_str], self.action)
        result["content"] = from_union([from_none, from_str], self.content)
        result["prompt"] = from_union([from_none, from_str], self.prompt)
        result["wait"] = from_union([from_int, from_none], self.wait)
        return result


@dataclass
class MethodMap:
    """Maps standard HTTP methods to API specific methods (case sensitive)"""

    """Map DELETE requests"""
    delete: Optional[str]
    """Map GET requests"""
    get: Optional[str]
    """Map PATCH requests"""
    patch: Optional[str]
    """Map POST requests"""
    post: Optional[str]
    """Map PUT requests"""
    put: Optional[str]

    @staticmethod
    def from_dict(obj: Any) -> "MethodMap":
        assert isinstance(obj, dict)
        delete = from_union([from_none, from_str], obj.get("DELETE"))
        get = from_union([from_none, from_str], obj.get("GET"))
        patch = from_union([from_none, from_str], obj.get("PATCH"))
        post = from_union([from_none, from_str], obj.get("POST"))
        put = from_union([from_none, from_str], obj.get("PUT"))
        return MethodMap(delete, get, patch, post, put)

    def to_dict(self) -> dict:
        result: dict = {}
        result["DELETE"] = from_union([from_none, from_str], self.delete)
        result["GET"] = from_union([from_none, from_str], self.get)
        result["PATCH"] = from_union([from_none, from_str], self.patch)
        result["POST"] = from_union([from_none, from_str], self.post)
        result["PUT"] = from_union([from_none, from_str], self.put)
        return result


@dataclass
class ParamMap:
    """Maps standard parameters to API specific parameters"""

    """The end date"""
    end: Optional[str]
    fields: Optional[str]
    id: Optional[str]
    """The start date"""
    start: Optional[str]

    @staticmethod
    def from_dict(obj: Any) -> "ParamMap":
        assert isinstance(obj, dict)
        end = from_union([from_none, from_str], obj.get("end"))
        fields = from_union([from_none, from_str], obj.get("fields"))
        id = from_union([from_none, from_str], obj.get("id"))
        start = from_union([from_none, from_str], obj.get("start"))
        return ParamMap(end, fields, id, start)

    def to_dict(self) -> dict:
        result: dict = {}
        result["end"] = from_union([from_none, from_str], self.end)
        result["fields"] = from_union([from_none, from_str], self.fields)
        result["id"] = from_union([from_none, from_str], self.id)
        result["start"] = from_union([from_none, from_str], self.start)
        return result


@dataclass
class Authentication:
    """API authentication"""

    """Unique identifier for the API resource"""
    auth_id: str
    """Base API URL"""
    api_base_url: Optional[str]
    """Extension to place  at the end of API urls"""
    api_ext: Optional[str]
    attrs: Optional[Dict[str, Union[bool, AttrClass, int, str]]]
    """The API authentication type"""
    auth_type: Optional[str]
    """API OAuth authorization URL"""
    authorization_base_url: Optional[str]
    """The API client ID"""
    client_id: Optional[str]
    """The API client secret"""
    client_secret: Optional[str]
    """Enable debug mode"""
    debug: Optional[bool]
    """URL to API reference documentation"""
    documentation_url: Optional[str]
    """HTTP headers to include with requests (case sensitive)"""
    headers: Optional[Headers]
    """Allow headless authentication"""
    headless: Optional[bool]
    """Web element used to navigate a provider's application login page"""
    headless_elements: Optional[List[HeadlessElement]]
    """Use this authentication object if one isn't provided"""
    is_default: Optional[bool]
    """Maps standard HTTP methods to API specific methods (case sensitive)"""
    method_map: Optional[MethodMap]
    """Maps standard parameters to API specific parameters"""
    param_map: Optional[ParamMap]
    params: Optional[Dict[str, Union[bool, AttrClass, int, str]]]
    """The base authentication object"""
    parent: Optional[str]
    """The application password"""
    password: Optional[str]
    """API OAuth flow callback entry point"""
    redirect_uri: Optional[str]
    """API OAuth token refresh URL (defaults to the `tokenURL`)"""
    refresh_url: Optional[str]
    """Place the resource ID *after* the subresource instead of before"""
    rid_last: Optional[bool]
    """The API permissions scope"""
    scope: Optional[List[str]]
    """Path to the tenant ID"""
    tenant_path: Optional[str]
    """API OAuth token URL"""
    token_url: Optional[str]
    """The application username"""
    username: Optional[str]

    @staticmethod
    def from_dict(obj: Any) -> "Authentication":
        assert isinstance(obj, dict)
        auth_id = from_str(obj.get("authId"))
        api_base_url = from_union([from_none, from_str], obj.get("apiBaseURL"))
        api_ext = from_union([from_none, from_str], obj.get("apiExt"))
        attrs = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [from_bool, AttrClass.from_dict, from_int, from_str], x
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("attrs"),
        )
        auth_type = from_union([from_none, from_str], obj.get("authType"))
        authorization_base_url = from_union(
            [from_none, from_str], obj.get("authorizationBaseURL")
        )
        client_id = from_union([from_none, from_str], obj.get("clientId"))
        client_secret = from_union([from_none, from_str], obj.get("clientSecret"))
        debug = from_union([from_bool, from_none], obj.get("debug"))
        documentation_url = from_union(
            [from_none, from_str], obj.get("documentationURL")
        )
        headers = from_union([Headers.from_dict, from_none], obj.get("headers"))
        headless = from_union([from_bool, from_none], obj.get("headless"))
        headless_elements = from_union(
            [lambda x: from_list(HeadlessElement.from_dict, x), from_none],
            obj.get("headlessElements"),
        )
        is_default = from_union([from_bool, from_none], obj.get("isDefault"))
        method_map = from_union([MethodMap.from_dict, from_none], obj.get("methodMap"))
        param_map = from_union([ParamMap.from_dict, from_none], obj.get("paramMap"))
        params = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [from_bool, AttrClass.from_dict, from_int, from_str], x
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("params"),
        )
        parent = from_union([from_none, from_str], obj.get("parent"))
        password = from_union([from_none, from_str], obj.get("password"))
        redirect_uri = from_union([from_none, from_str], obj.get("redirectURI"))
        refresh_url = from_union([from_none, from_str], obj.get("refreshURL"))
        rid_last = from_union([from_bool, from_none], obj.get("ridLast"))
        scope = from_union(
            [lambda x: from_list(from_str, x), from_none], obj.get("scope")
        )
        tenant_path = from_union([from_none, from_str], obj.get("tenantPath"))
        token_url = from_union([from_none, from_str], obj.get("tokenURL"))
        username = from_union([from_none, from_str], obj.get("username"))
        return Authentication(
            auth_id,
            api_base_url,
            api_ext,
            attrs,
            auth_type,
            authorization_base_url,
            client_id,
            client_secret,
            debug,
            documentation_url,
            headers,
            headless,
            headless_elements,
            is_default,
            method_map,
            param_map,
            params,
            parent,
            password,
            redirect_uri,
            refresh_url,
            rid_last,
            scope,
            tenant_path,
            token_url,
            username,
        )

    def to_dict(self) -> dict:
        result: dict = {}
        result["authId"] = from_str(self.auth_id)
        result["apiBaseURL"] = from_union([from_none, from_str], self.api_base_url)
        result["apiExt"] = from_union([from_none, from_str], self.api_ext)
        result["attrs"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            self.attrs,
        )
        result["authType"] = from_union([from_none, from_str], self.auth_type)
        result["authorizationBaseURL"] = from_union(
            [from_none, from_str], self.authorization_base_url
        )
        result["clientId"] = from_union([from_none, from_str], self.client_id)
        result["clientSecret"] = from_union([from_none, from_str], self.client_secret)
        result["debug"] = from_union([from_bool, from_none], self.debug)
        result["documentationURL"] = from_union(
            [from_none, from_str], self.documentation_url
        )
        result["headers"] = from_union(
            [lambda x: to_class(Headers, x), from_none], self.headers
        )
        result["headless"] = from_union([from_bool, from_none], self.headless)
        result["headlessElements"] = from_union(
            [lambda x: from_list(lambda x: to_class(HeadlessElement, x), x), from_none],
            self.headless_elements,
        )
        result["isDefault"] = from_union([from_bool, from_none], self.is_default)
        result["methodMap"] = from_union(
            [lambda x: to_class(MethodMap, x), from_none], self.method_map
        )
        result["paramMap"] = from_union(
            [lambda x: to_class(ParamMap, x), from_none], self.param_map
        )
        result["params"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            self.params,
        )
        result["parent"] = from_union([from_none, from_str], self.parent)
        result["password"] = from_union([from_none, from_str], self.password)
        result["redirectURI"] = from_union([from_none, from_str], self.redirect_uri)
        result["refreshURL"] = from_union([from_none, from_str], self.refresh_url)
        result["ridLast"] = from_union([from_bool, from_none], self.rid_last)
        result["scope"] = from_union(
            [lambda x: from_list(from_str, x), from_none], self.scope
        )
        result["tenantPath"] = from_union([from_none, from_str], self.tenant_path)
        result["tokenURL"] = from_union([from_none, from_str], self.token_url)
        result["username"] = from_union([from_none, from_str], self.username)
        return result


@dataclass
class Resource:
    """An API resource"""

    """Unique identifier for the API resource"""
    resource_id: str
    attrs: Optional[Dict[str, Union[bool, AttrClass, int, str]]]
    """The authorization object used to authenticate"""
    auth_id: Optional[str]
    """URL to API resource documentation"""
    documentation_url: Optional[str]
    """Resource fields to save from the parsed API response"""
    fields: Optional[List[str]]
    """Hide the resource from"""
    hidden: Optional[bool]
    """Field representing the resource ID"""
    id_field: Optional[str]
    """HTTP methods this resource allows"""
    methods: Optional[List[str]]
    """Field representing the resource name"""
    name_field: Optional[str]
    """resourceId of the base resource object"""
    parent: Optional[str]
    """What the resource is named in the API URL"""
    resource: Optional[str]
    """Currently active resource"""
    rid: Optional[str]
    """Currently active sub resource"""
    srid: Optional[str]
    """The path to extract from the parsed API response (should return a list of items)"""
    subkey: Optional[str]
    """What the sub resource is named in the API URL"""
    subresource: Optional[str]

    @staticmethod
    def from_dict(obj: Any) -> "Resource":
        assert isinstance(obj, dict)
        resource_id = from_str(obj.get("resourceId"))
        attrs = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [from_bool, AttrClass.from_dict, from_int, from_str], x
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("attrs"),
        )
        auth_id = from_union([from_none, from_str], obj.get("authId"))
        documentation_url = from_union(
            [from_none, from_str], obj.get("documentationURL")
        )
        fields = from_union(
            [lambda x: from_list(from_str, x), from_none], obj.get("fields")
        )
        hidden = from_union([from_bool, from_none], obj.get("hidden"))
        id_field = from_union([from_none, from_str], obj.get("idField"))
        methods = from_union(
            [lambda x: from_list(from_str, x), from_none], obj.get("methods")
        )
        name_field = from_union([from_none, from_str], obj.get("nameField"))
        parent = from_union([from_none, from_str], obj.get("parent"))
        resource = from_union([from_none, from_str], obj.get("resource"))
        rid = from_union([from_none, from_str], obj.get("rid"))
        srid = from_union([from_none, from_str], obj.get("srid"))
        subkey = from_union([from_none, from_str], obj.get("subkey"))
        subresource = from_union([from_none, from_str], obj.get("subresource"))
        return Resource(
            resource_id,
            attrs,
            auth_id,
            documentation_url,
            fields,
            hidden,
            id_field,
            methods,
            name_field,
            parent,
            resource,
            rid,
            srid,
            subkey,
            subresource,
        )

    def to_dict(self) -> dict:
        result: dict = {}
        result["resourceId"] = from_str(self.resource_id)
        result["attrs"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            self.attrs,
        )
        result["authId"] = from_union([from_none, from_str], self.auth_id)
        result["documentationURL"] = from_union(
            [from_none, from_str], self.documentation_url
        )
        result["fields"] = from_union(
            [lambda x: from_list(from_str, x), from_none], self.fields
        )
        result["hidden"] = from_union([from_bool, from_none], self.hidden)
        result["idField"] = from_union([from_none, from_str], self.id_field)
        result["methods"] = from_union(
            [lambda x: from_list(from_str, x), from_none], self.methods
        )
        result["nameField"] = from_union([from_none, from_str], self.name_field)
        result["parent"] = from_union([from_none, from_str], self.parent)
        result["resource"] = from_union([from_none, from_str], self.resource)
        result["rid"] = from_union([from_none, from_str], self.rid)
        result["srid"] = from_union([from_none, from_str], self.srid)
        result["subkey"] = from_union([from_none, from_str], self.subkey)
        result["subresource"] = from_union([from_none, from_str], self.subresource)
        return result


@dataclass
class Webhook:
    """A product from Acme's catalog"""

    """The HTTP header to extract the webhook signature from"""
    signature_header: str
    """The password to decrypt the webhook payload"""
    webhook_secret: str
    """Use Base64 encoding instead of Hexadecimal"""
    b64_encode: Optional[bool]
    """The webhook digest algorithm"""
    digest: Optional[str]
    """URL to API resource documentation"""
    documentation_url: Optional[str]
    """Disable verification by ignoring the signature (insecure!)"""
    ignore_signature: Optional[bool]
    """Key to extract from the payload request"""
    payload_key: Optional[str]
    """Split signature at the `=` character"""
    split_signature: Optional[bool]

    @staticmethod
    def from_dict(obj: Any) -> "Webhook":
        assert isinstance(obj, dict)
        signature_header = from_str(obj.get("signatureHeader"))
        webhook_secret = from_str(obj.get("webhookSecret"))
        b64_encode = from_union([from_bool, from_none], obj.get("b64Encode"))
        digest = from_union([from_none, from_str], obj.get("digest"))
        documentation_url = from_union(
            [from_none, from_str], obj.get("documentationURL")
        )
        ignore_signature = from_union(
            [from_bool, from_none], obj.get("ignoreSignature")
        )
        payload_key = from_union([from_none, from_str], obj.get("payloadKey"))
        split_signature = from_union([from_bool, from_none], obj.get("splitSignature"))
        return Webhook(
            signature_header,
            webhook_secret,
            b64_encode,
            digest,
            documentation_url,
            ignore_signature,
            payload_key,
            split_signature,
        )

    def to_dict(self) -> dict:
        result: dict = {}
        result["signatureHeader"] = from_str(self.signature_header)
        result["webhookSecret"] = from_str(self.webhook_secret)
        result["b64Encode"] = from_union([from_bool, from_none], self.b64_encode)
        result["digest"] = from_union([from_none, from_str], self.digest)
        result["documentationURL"] = from_union(
            [from_none, from_str], self.documentation_url
        )
        result["ignoreSignature"] = from_union(
            [from_bool, from_none], self.ignore_signature
        )
        result["payloadKey"] = from_union([from_none, from_str], self.payload_key)
        result["splitSignature"] = from_union(
            [from_bool, from_none], self.split_signature
        )
        return result


@dataclass
class Provider:
    """A 3rd party API provider"""

    """Authentication methods accepted by 3rd party API"""
    auths: List[Authentication]
    """Unique 3rd party identifier"""
    prefix: str
    """Resources exposed by 3rd party API"""
    resources: List[Resource]
    """The id of a resource to redirect to after authenticating the user"""
    status_resource: Optional[str]
    webhook: Optional[Webhook]

    @staticmethod
    def from_dict(obj: Any) -> "Provider":
        assert isinstance(obj, dict)
        auths = from_list(Authentication.from_dict, obj.get("auths"))
        prefix = from_str(obj.get("prefix"))
        resources = from_list(Resource.from_dict, obj.get("resources"))
        status_resource = from_union([from_none, from_str], obj.get("statusResource"))
        webhook = from_union([Webhook.from_dict, from_none], obj.get("webhook"))
        return Provider(auths, prefix, resources, status_resource, webhook)

    def to_dict(self) -> dict:
        result: dict = {}
        result["auths"] = from_list(lambda x: to_class(Authentication, x), self.auths)
        result["prefix"] = from_str(self.prefix)
        result["resources"] = from_list(lambda x: to_class(Resource, x), self.resources)
        result["statusResource"] = from_union(
            [from_none, from_str], self.status_resource
        )
        result["webhook"] = from_union(
            [lambda x: to_class(Webhook, x), from_none], self.webhook
        )
        return result


def provider_from_dict(s: Any) -> Provider:
    return Provider.from_dict(s)


def provider_to_dict(x: Provider) -> Any:
    return to_class(Provider, x)

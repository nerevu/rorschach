# To use this code, make sure you
#
#     import json
#
# and then, to convert JSON from a string, do
#
#     result = api_config_from_dict(json.loads(json_string))

from dataclasses import dataclass
from typing import Any, Callable, List, Optional, Type, TypeVar, cast

T = TypeVar("T")


def from_str(x: Any) -> str:
    assert isinstance(x, str)
    return x


def from_list(f: Callable[[Any], T], x: Any) -> List[T]:
    assert isinstance(x, list)
    return [f(y) for y in x]


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


@dataclass
class BlueprintRouteParams:
    """Blueprint route parameters

    Flask route parameters
    """

    """The function name"""
    func_name: str
    """The class or function module"""
    module: str
    """Unique identifier for the route"""
    name: str

    @staticmethod
    def from_dict(obj: Any) -> "BlueprintRouteParams":
        assert isinstance(obj, dict)
        func_name = from_str(obj.get("funcName"))
        module = from_str(obj.get("module"))
        name = from_str(obj.get("name"))
        return BlueprintRouteParams(func_name, module, name)

    def to_dict(self) -> dict:
        result: dict = {}
        result["funcName"] = from_str(self.func_name)
        result["module"] = from_str(self.module)
        result["name"] = from_str(self.name)
        return result


@dataclass
class MethodViewRouteParams:
    """MethodView route parameters

    Flask route parameters
    """

    """The MethodView class name"""
    class_name: str
    """The class or function module"""
    module: str
    """Unique identifier for the route"""
    name: str
    """HTTP methods this route allows"""
    methods: Optional[List[str]]
    """Query parameters this route accepts (in the form of `<type>:<name>`"""
    params: Optional[List[str]]

    @staticmethod
    def from_dict(obj: Any) -> "MethodViewRouteParams":
        assert isinstance(obj, dict)
        class_name = from_str(obj.get("className"))
        module = from_str(obj.get("module"))
        name = from_str(obj.get("name"))
        methods = from_union(
            [lambda x: from_list(from_str, x), from_none], obj.get("methods")
        )
        params = from_union(
            [lambda x: from_list(from_str, x), from_none], obj.get("params")
        )
        return MethodViewRouteParams(class_name, module, name, methods, params)

    def to_dict(self) -> dict:
        result: dict = {}
        result["className"] = from_str(self.class_name)
        result["module"] = from_str(self.module)
        result["name"] = from_str(self.name)
        result["methods"] = from_union(
            [lambda x: from_list(from_str, x), from_none], self.methods
        )
        result["params"] = from_union(
            [lambda x: from_list(from_str, x), from_none], self.params
        )
        return result


@dataclass
class APIConfig:
    """An exposed API Configuration"""

    """Exposed Blueprint route params"""
    blueprint_route_params: List[BlueprintRouteParams]
    """The API description"""
    description: str
    """Text to display on the API root route"""
    message: str
    """Exposed MethodView route params"""
    method_view_route_params: List[MethodViewRouteParams]
    """Unique identifier for the API"""
    name: str
    """Exposed resource provider prefixes"""
    provider_names: Optional[List[str]]

    @staticmethod
    def from_dict(obj: Any) -> "APIConfig":
        assert isinstance(obj, dict)
        blueprint_route_params = from_list(
            BlueprintRouteParams.from_dict, obj.get("blueprintRouteParams")
        )
        description = from_str(obj.get("description"))
        message = from_str(obj.get("message"))
        method_view_route_params = from_list(
            MethodViewRouteParams.from_dict, obj.get("methodViewRouteParams")
        )
        name = from_str(obj.get("name"))
        provider_names = from_union(
            [lambda x: from_list(from_str, x), from_none], obj.get("providerNames")
        )
        return APIConfig(
            blueprint_route_params,
            description,
            message,
            method_view_route_params,
            name,
            provider_names,
        )

    def to_dict(self) -> dict:
        result: dict = {}
        result["blueprintRouteParams"] = from_list(
            lambda x: to_class(BlueprintRouteParams, x), self.blueprint_route_params
        )
        result["description"] = from_str(self.description)
        result["message"] = from_str(self.message)
        result["methodViewRouteParams"] = from_list(
            lambda x: to_class(MethodViewRouteParams, x), self.method_view_route_params
        )
        result["name"] = from_str(self.name)
        result["providerNames"] = from_union(
            [lambda x: from_list(from_str, x), from_none], self.provider_names
        )
        return result


def api_config_from_dict(s: Any) -> APIConfig:
    return APIConfig.from_dict(s)


def api_config_to_dict(x: APIConfig) -> Any:
    return to_class(APIConfig, x)

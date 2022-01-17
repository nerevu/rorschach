# To use this code, make sure you
#
#     import json
#
# and then, to convert JSON from a string, do
#
#     result = interface_from_dict(json.loads(json_string))

from dataclasses import dataclass
from typing import Any, Callable, Dict, Type, TypeVar, Union, cast

T = TypeVar("T")


def from_str(x: Any) -> str:
    assert isinstance(x, str)
    return x


def from_dict(f: Callable[[Any], T], x: Any) -> Dict[str, T]:
    assert isinstance(x, dict)
    return {k: f(v) for (k, v) in x.items()}


def from_bool(x: Any) -> bool:
    assert isinstance(x, bool)
    return x


def from_int(x: Any) -> int:
    assert isinstance(x, int) and not isinstance(x, bool)
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
class Interface:
    """Translates a provider instance resource to an abstract resource"""

    """Path to the abstract resource"""
    abstraction: str
    """Maps reference abstract resource properties to API resource properties"""
    implementation: Dict[str, Union[bool, int, str]]
    """Path to the provider instance"""
    provider: str
    """Unique identifier for the provider instance resource"""
    provider_resource_id: str

    @staticmethod
    def from_dict(obj: Any) -> "Interface":
        assert isinstance(obj, dict)
        abstraction = from_str(obj.get("abstraction"))
        implementation = from_dict(
            lambda x: from_union([from_bool, from_int, from_str], x),
            obj.get("implementation"),
        )
        provider = from_str(obj.get("provider"))
        provider_resource_id = from_str(obj.get("providerResourceId"))
        return Interface(abstraction, implementation, provider, provider_resource_id)

    def to_dict(self) -> dict:
        result: dict = {}
        result["abstraction"] = from_str(self.abstraction)
        result["implementation"] = from_dict(
            lambda x: from_union([from_bool, from_int, from_str], x),
            self.implementation,
        )
        result["provider"] = from_str(self.provider)
        result["providerResourceId"] = from_str(self.provider_resource_id)
        return result


def interface_from_dict(s: Any) -> Interface:
    return Interface.from_dict(s)


def interface_to_dict(x: Interface) -> Any:
    return to_class(Interface, x)

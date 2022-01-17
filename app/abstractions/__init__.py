# To use this code, make sure you
#
#     import json
#
# and then, to convert JSON from a string, do
#
#     result = abstract_resource_from_dict(json.loads(json_string))

from dataclasses import dataclass
from typing import Any, Callable, List, Optional, Type, TypeVar, cast

T = TypeVar("T")


def from_str(x: Any) -> str:
    assert isinstance(x, str)
    return x


def from_bool(x: Any) -> bool:
    assert isinstance(x, bool)
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


def from_list(f: Callable[[Any], T], x: Any) -> List[T]:
    assert isinstance(x, list)
    return [f(y) for y in x]


def to_class(c: Type[T], x: Any) -> dict:
    assert isinstance(x, c)
    return cast(Any, x).to_dict()


@dataclass
class Field:
    """The field description"""

    description: str
    """Unique identifier for the field"""
    id: str
    """Whether or not an implementer is required to have this field"""
    required: Optional[bool]
    """The field type"""
    type: Optional[str]

    @staticmethod
    def from_dict(obj: Any) -> "Field":
        assert isinstance(obj, dict)
        description = from_str(obj.get("description"))
        id = from_str(obj.get("id"))
        required = from_union([from_bool, from_none], obj.get("required"))
        type = from_union([from_none, from_str], obj.get("type"))
        return Field(description, id, required, type)

    def to_dict(self) -> dict:
        result: dict = {}
        result["description"] = from_str(self.description)
        result["id"] = from_str(self.id)
        result["required"] = from_union([from_bool, from_none], self.required)
        result["type"] = from_union([from_none, from_str], self.type)
        return result


@dataclass
class AbstractResource:
    """An abstract resource"""

    """The resource description"""
    description: str
    """Example 3rd party applications applicable to this resource"""
    domains: List[str]
    """The resources properties to include"""
    fields: List[Field]
    """An abstract resource"""
    title: str
    """The subject areas applicable to this resource"""
    tags: Optional[List[str]]

    @staticmethod
    def from_dict(obj: Any) -> "AbstractResource":
        assert isinstance(obj, dict)
        description = from_str(obj.get("description"))
        domains = from_list(from_str, obj.get("domains"))
        fields = from_list(Field.from_dict, obj.get("fields"))
        title = from_str(obj.get("title"))
        tags = from_union(
            [lambda x: from_list(from_str, x), from_none], obj.get("tags")
        )
        return AbstractResource(description, domains, fields, title, tags)

    def to_dict(self) -> dict:
        result: dict = {}
        result["description"] = from_str(self.description)
        result["domains"] = from_list(from_str, self.domains)
        result["fields"] = from_list(lambda x: to_class(Field, x), self.fields)
        result["title"] = from_str(self.title)
        result["tags"] = from_union(
            [lambda x: from_list(from_str, x), from_none], self.tags
        )
        return result


def abstract_resource_from_dict(s: Any) -> AbstractResource:
    return AbstractResource.from_dict(s)


def abstract_resource_to_dict(x: AbstractResource) -> Any:
    return to_class(AbstractResource, x)

"""A tiny, dependency-free JSON-Schema validator.

Only the subset the tool catalogue uses is implemented — enough to reject a
malformed or hostile ``tools/call`` argument object before any handler runs,
without pulling in a third-party schema library. It fails closed: an unknown
keyword is ignored, but a violated known constraint always raises.
"""

from __future__ import annotations

import re

_TYPES = {
    "object": dict, "array": (list, tuple), "string": str,
    "integer": int, "number": (int, float), "boolean": bool,
}


class SchemaError(ValueError):
    pass


def validate(schema: dict, value, path: str = "$") -> None:
    if not schema:
        return
    t = schema.get("type")
    if t:
        expected = _TYPES.get(t)
        # bool is a subclass of int — keep them distinct.
        if t in ("integer", "number") and isinstance(value, bool):
            raise SchemaError(f"{path}: expected {t}, got boolean")
        if expected and not isinstance(value, expected):
            raise SchemaError(f"{path}: expected {t}")

    if "enum" in schema and value not in schema["enum"]:
        raise SchemaError(f"{path}: not one of {schema['enum']}")

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise SchemaError(f"{path}: shorter than {schema['minLength']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise SchemaError(f"{path}: longer than {schema['maxLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            raise SchemaError(f"{path}: does not match required pattern")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise SchemaError(f"{path}: below minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            raise SchemaError(f"{path}: above maximum {schema['maximum']}")

    if isinstance(value, (list, tuple)):
        if "minItems" in schema and len(value) < schema["minItems"]:
            raise SchemaError(f"{path}: fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise SchemaError(f"{path}: more than {schema['maxItems']} items")
        item_schema = schema.get("items")
        if item_schema:
            for i, item in enumerate(value):
                validate(item_schema, item, f"{path}[{i}]")

    if isinstance(value, dict):
        props = schema.get("properties", {})
        for req in schema.get("required", []):
            if req not in value:
                raise SchemaError(f"{path}: missing required property '{req}'")
        if schema.get("additionalProperties") is False:
            extra = set(value) - set(props)
            if extra:
                raise SchemaError(f"{path}: unexpected properties {sorted(extra)}")
        for k, v in value.items():
            if k in props:
                validate(props[k], v, f"{path}.{k}")

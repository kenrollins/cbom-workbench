"""JSON Schemas for the interfaces in spec/interfaces.md, and a validator for each.

A reader rejects a major version it does not know and ignores fields it does
not know, so every schema allows additional properties.
"""

from __future__ import annotations

import json
from functools import cache
from importlib import resources

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

KNOWN = {
    "pqch.scope/1": "scope.json",
    "pqch.finding/1": "finding.json",
    "pqch.event/1": "event.json",
    "pqch.checkpoint/1": "checkpoint.json",
}


@cache
def _registry() -> Registry:
    resources_ = []
    for name in KNOWN.values():
        doc = json.loads(resources.files(__package__).joinpath(name).read_text())
        resources_.append((doc["$id"], Resource.from_contents(doc)))
    return Registry().with_resources(resources_)


@cache
def validator(schema_id: str) -> Draft202012Validator:
    if schema_id not in KNOWN:
        raise ValueError(f"unknown schema {schema_id!r}")
    doc = json.loads(resources.files(__package__).joinpath(KNOWN[schema_id]).read_text())
    return Draft202012Validator(doc, registry=_registry())


def validate(obj: dict) -> None:
    """Validate an object against the schema its `schema` field names. Raises on failure."""
    schema_id = obj.get("schema")
    if schema_id not in KNOWN:
        raise ValueError(f"unknown or missing schema {schema_id!r}")
    validator(schema_id).validate(obj)

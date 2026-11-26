"""Account for response bodies recursively, including deliberately open fields.

Coverage is a description measure, never evidence of execution or compatibility.
Unknown properties cannot turn an opaque response envelope into a typed one.
"""

METHODS = {"get", "put", "post", "patch", "delete", "head", "options", "trace"}


def resolve_pointer(document, pointer):
    if not pointer.startswith("#/"):
        raise ValueError("Only local schema references are supported")
    value = document
    for part in pointer[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def inspect_schema(document, schema, location, *, envelope=True, seen=frozenset()):
    problems, open_fields = [], []

    def problem(reason):
        problems.append({"location": location, "reason": reason})

    if schema is False:
        return problems, open_fields
    if not isinstance(schema, dict):
        problem("unconstrained schema" if schema is True else "missing schema")
        return problems, open_fields
    reason = schema.get("x-open-schema-reason")
    structured = any(
        key in schema
        for key in (
            "properties",
            "$ref",
            "items",
            "prefixItems",
            "anyOf",
            "oneOf",
            "allOf",
        )
    )
    if reason and not envelope and not structured:
        # Explicitly surfaced in a separate inventory, not silently counted as
        # a closed structure. The reason is reviewed with the source serializer.
        open_fields.append({"location": location, "reason": reason})
        return problems, open_fields

    def descend(child, suffix, *, child_envelope=False, child_seen=seen):
        opaque, intentional = inspect_schema(
            document,
            child,
            location + suffix,
            envelope=child_envelope,
            seen=child_seen,
        )
        problems.extend(opaque)
        open_fields.extend(intentional)

    if "$ref" in schema:
        reference = schema["$ref"]
        try:
            target = resolve_pointer(document, reference)
        except (KeyError, IndexError, TypeError, ValueError):
            problem("unresolved reference: " + str(reference))
            return problems, open_fields
        if reference not in seen:
            descend(
                target,
                " -> " + reference,
                child_envelope=envelope,
                child_seen=seen | {reference},
            )
    elif "const" in schema or "enum" in schema:
        pass
    elif any(key in schema for key in ("anyOf", "oneOf", "allOf")):
        for key in ("anyOf", "oneOf", "allOf"):
            for index, member in enumerate(schema.get(key, [])):
                descend(member, f"/{key}/{index}", child_envelope=envelope)
    elif schema.get("type") == "array":
        if "items" in schema:
            descend(schema["items"], "/items", child_envelope=envelope)
        elif "prefixItems" not in schema:
            problem("array items are unspecified")
        for index, member in enumerate(schema.get("prefixItems", [])):
            descend(member, f"/prefixItems/{index}", child_envelope=envelope)
    elif schema.get("type") == "object" or "properties" in schema:
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        patterns = schema.get("patternProperties", {})
        if not properties and not patterns and not isinstance(additional, dict):
            if additional is not False:
                problem("object values are unspecified")
        for name, child in properties.items():
            descend(child, "/properties/" + name)
        if properties and additional is True:
            if reason:
                open_fields.append(
                    {"location": location + "/additionalProperties", "reason": reason}
                )
            else:
                problems.append(
                    {
                        "location": location + "/additionalProperties",
                        "reason": (
                            "additional object fields are unconstrained without an"
                            " explanation"
                        ),
                    }
                )
        if isinstance(additional, dict):
            descend(additional, "/additionalProperties")
        for pattern, child in patterns.items():
            descend(child, "/patternProperties/" + pattern)
    elif schema.get("type") not in ("string", "number", "integer", "boolean", "null"):
        problem("schema has no described value shape")
    return problems, open_fields


def response_inventory(document):
    untyped, described, intentional = [], [], []
    for path, methods in sorted(document.get("paths", {}).items()):
        for method, operation in sorted(methods.items()):
            if method not in METHODS:
                continue
            entry = {"method": method.upper(), "path": path}
            opaque, successful = [], []
            for status, response in operation.get("responses", {}).items():
                # Redirects are successful protocol outcomes, not JSON bodies.
                if not str(status).startswith(("2", "3")):
                    continue
                successful.append(status)
                if "$ref" in response:
                    try:
                        response = resolve_pointer(document, response["$ref"])
                    except (KeyError, TypeError, ValueError, IndexError):
                        opaque.append(
                            {
                                "location": str(status),
                                "reason": "unresolved response reference",
                            }
                        )
                        continue
                content = response.get("content", {})
                if not content and str(status) not in {"204", "205", "304"}:
                    if not response.get("x-no-response-body"):
                        opaque.append(
                            {
                                "location": str(status),
                                "reason": "body absence is not described",
                            }
                        )
                for media, definition in content.items():
                    problems, open_fields = inspect_schema(
                        document, definition.get("schema"), f"{status}:{media}"
                    )
                    opaque.extend(problems)
                    intentional.extend({**entry, **item} for item in open_fields)
            if not successful and not operation.get("x-no-success-response"):
                opaque.append(
                    {
                        "location": "responses",
                        "reason": "no successful response described",
                    }
                )
            if opaque:
                untyped.append(
                    {
                        **entry,
                        "opaque_responses": sorted({row["location"] for row in opaque}),
                        "findings": sorted(
                            opaque, key=lambda row: (row["location"], row["reason"])
                        ),
                    }
                )
            else:
                described.append(entry)
    return {
        "operation_count": len(untyped) + len(described),
        "untyped_count": len(untyped),
        "untyped": untyped,
        "described_count": len(described),
        "intentional_open_field_count": len(intentional),
        "intentional_open_fields": sorted(
            intentional,
            key=lambda row: (
                row["path"],
                row["method"],
                row["location"],
                row["reason"],
            ),
        ),
        "qualification": (
            "Recursive response-description inventory, including references, arrays, "
            "unions and bodyless/redirect outcomes. Intentional open fields remain "
            "listed separately. Coverage is not runtime validation, execution "
            "evidence or consumer compatibility."
        ),
    }

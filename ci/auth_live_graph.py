"""Read effective FastAPI dispatch routes, including startup-mounted routers.

This is topology evidence, not authorization inferred from dependency names.
Unknown dispatch node types fail rather than disappearing from the denominator.
"""

from fastapi.routing import APIRoute, APIWebSocketRoute, _IncludedRouter
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.staticfiles import StaticFiles


def dependency_closure(dependant):
    found = set()

    def visit(node):
        if node is None:
            return
        call = node.call
        if call is not None:
            found.add(
                f"{getattr(call, '__module__', type(call).__module__)}:"
                f"{getattr(call, '__qualname__', type(call).__qualname__)}"
            )
        for child in node.dependencies:
            visit(child)

    if dependant is not None:
        for child in dependant.dependencies:
            visit(child)
    return sorted(found)


def live_graph(app):
    rows = []
    for node in app.routes:
        contexts = (
            node.effective_route_contexts()
            if isinstance(node, _IncludedRouter)
            else [node]
        )
        for context in contexts:
            original = getattr(context, "original_route", context)
            effective = getattr(context, "starlette_route", None) or context
            if (
                isinstance(original, Mount)
                and original.path == "/docs-assets"
                and isinstance(original.app, StaticFiles)
            ):
                rows.append(
                    {
                        "path": effective.path + "/{path:path}",
                        "methods": ["GET", "HEAD"],
                        "handler": type(original.app).__name__,
                        "module": type(original.app).__module__,
                        "framework": True,
                        "dependencies": [],
                        "regex": effective.path_regex,
                        "mount": True,
                    }
                )
                continue
            if not isinstance(original, (Route, WebSocketRoute)):
                raise AssertionError(f"Unclassified dispatch node: {type(original)}")
            endpoint = original.endpoint
            websocket = isinstance(original, WebSocketRoute)
            rows.append(
                {
                    "path": effective.path,
                    "methods": (
                        ["WEBSOCKET"] if websocket else sorted(effective.methods)
                    ),
                    "handler": endpoint.__name__,
                    "module": endpoint.__module__,
                    "framework": not isinstance(
                        original, (APIRoute, APIWebSocketRoute)
                    ),
                    "dependencies": dependency_closure(
                        getattr(effective, "dependant", None)
                    ),
                    "regex": effective.path_regex,
                }
            )
    return rows


def operations(rows):
    return [(method, row["path"]) for row in rows for method in row["methods"]]


def require_unique(rows):
    keys = operations(rows)
    if len(keys) != len(set(keys)):
        raise AssertionError("Duplicate live method/path")


def literal_shadows(rows):
    """Identify earlier dynamic routes swallowing a later literal route.

    Dynamic/dynamic overlap needs a separate reviewed converter analysis; this
    function deliberately makes no claim to prove those disjoint.
    """
    result = []
    for index, row in enumerate(rows):
        if "{" in row["path"]:
            continue
        for previous in rows[:index]:
            overlap = set(row["methods"]) & set(previous["methods"])
            if overlap and previous["regex"].fullmatch(row["path"]):
                result.append((previous["path"], row["path"], sorted(overlap)))
    return result

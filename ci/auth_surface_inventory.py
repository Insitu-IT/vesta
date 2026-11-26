"""Conservative source inventory for D11 review, without starting the app.

Includes optional commercial and disabled/demo routes: absence from one runtime
profile is not permission to omit a surface from review. No authority is inferred
from a method name or a dependency's spelling.
"""

import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "websocket",
    "api_route",
    "route",
    "websocket_route",
}
BOUNDARIES = {
    "add_job",
    "scheduled_job",
    "add_task",
    "create_task",
    "Thread",
    "on_event",
    "run_in_executor",
    "ensure_future",
    "call_soon",
    "call_soon_threadsafe",
    "call_later",
    "call_at",
    "submit",
    "start_soon",
    "to_thread",
}
ROUTE_REGISTRATIONS = {
    "add_api_route",
    "add_route",
    "add_websocket_route",
    "add_api_websocket_route",
}
TOPOLOGY_REGISTRATIONS = ROUTE_REGISTRATIONS | {"include_router", "mount"}
# Still scanned and recorded. Both shipped Dockerfiles select app:app, not this
# historical entrypoint. Runtime conformance separately verifies the live set.
UNMOUNTED_SOURCES = {"backend/app_monolith.py"}

# Explicit privilege entry points and trusted readers. This is a reviewed
# vocabulary, not an inference that any other call is safe.
TRUSTED_CALLS = {
    "PlatformContext",
    "AdminContext",
    "DemoContext",
    "read_configuration",
}
MIDDLEWARE_CALLS = {"add_middleware", "middleware", "Middleware"}


def authority_inventory(root=ROOT):
    """Record middleware, direct privilege entry and trusted-reader call sites.

    Import aliases and simple assignment aliases retain their canonical terminal
    name. Callable factories/reflection and arbitrary object dispatch still need
    manual review; this does not purport to be whole-program reachability.
    """
    rows = []
    for path in source_paths(root):
        tree = ast.parse(path.read_text())
        parents = {c: p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
        aliases = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for item in node.names:
                    aliases[item.asname or item.name] = item.name
        # Resolve chains without depending on AST traversal order.
        assignments = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)]
        for _ in range(len(assignments) + 1):
            changed = False
            for node in assignments:
                if not isinstance(node.value, (ast.Name, ast.Attribute)):
                    continue
                name = ast.unparse(node.value).split(".")[-1]
                name = aliases.get(name, name)
                if name not in TRUSTED_CALLS | MIDDLEWARE_CALLS:
                    continue
                for target in node.targets:
                    if isinstance(target, ast.Name) and aliases.get(target.id) != name:
                        aliases[target.id] = name
                        changed = True
            if not changed:
                break
        occurrences = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = ast.unparse(node.func).split(".")[-1]
            name = aliases.get(name, name)
            if name not in TRUSTED_CALLS | MIDDLEWARE_CALLS:
                continue
            kind = "middleware" if name in MIDDLEWARE_CALLS else "trusted_call"
            scope = []
            parent = parents.get(node)
            while parent is not None:
                if isinstance(
                    parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    scope.append(parent.name)
                parent = parents.get(parent)
            scope = ".".join(reversed(scope)) or "<module>"
            expression = ast.unparse(node)
            immediate_parent = parents.get(node)
            if name == "middleware":
                if (
                    isinstance(immediate_parent, ast.Call)
                    and immediate_parent.func is node
                ):
                    expression = ast.unparse(immediate_parent)
                elif isinstance(
                    immediate_parent, (ast.FunctionDef, ast.AsyncFunctionDef)
                ):
                    expression += " -> " + immediate_parent.name
            relative = str(path.relative_to(root))
            key = (scope, expression)
            occurrences[key] = occurrences.get(key, 0) + 1
            rows.append(
                {
                    "id": f"{kind}:{relative}:{scope}:{occurrences[key]}:{expression}",
                    "kind": kind,
                    "source": relative,
                    "scope": scope,
                    "entry": name,
                    "expression": expression,
                }
            )
    return sorted(rows, key=lambda row: row["id"])


def source_paths(root=ROOT):
    """All Python beneath both shipped source trees, at any directory depth."""
    return sorted(
        {
            path
            for base in (root / "backend", root / "commercial/backend")
            for path in base.rglob("*.py")
            if "tests" not in path.relative_to(base).parts
        }
    )


def topology_registrations(root=ROOT):
    """Explicit registration syntax complements the post-lifespan graph.

    Scan all production Python, including code outside the decorator inventory.
    New registration mechanisms require review even when inactive in profiles.
    """
    rows = []
    for path in source_paths(root):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in TOPOLOGY_REGISTRATIONS:
                    rows.append(
                        {
                            "source": str(path.relative_to(root)),
                            "expression": ast.unparse(node),
                        }
                    )
    return sorted(rows, key=lambda row: (row["source"], row["expression"]))


def inventory(root=ROOT):
    paths = source_paths(root)
    rows = []
    for path in paths:
        tree = ast.parse(path.read_text())
        relative = str(path.relative_to(root))
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        occurrences = {}
        prefixes = {}
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Call)
                and ast.unparse(node.value.func).endswith("APIRouter")
            ):
                prefix = next(
                    (
                        ast.literal_eval(k.value)
                        for k in node.value.keywords
                        if k.arg == "prefix"
                    ),
                    "",
                )
                for target in node.targets:
                    owner = ast.unparse(target)
                    if owner in prefixes and prefixes[owner] != prefix:
                        raise ValueError(f"Ambiguous router binding {relative}:{owner}")
                    prefixes[owner] = prefix
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call) or not isinstance(
                    decorator.func, ast.Attribute
                ):
                    continue
                method = decorator.func.attr
                if method not in METHODS:
                    continue
                owner = ast.unparse(decorator.func.value)
                if owner not in prefixes and owner != "app":
                    raise ValueError(f"Unresolved router {relative}:{owner}")
                route = prefixes.get(owner, "") + ast.literal_eval(decorator.args[0])
                methods = [
                    (
                        "WEBSOCKET"
                        if method in {"websocket", "websocket_route"}
                        else method.upper()
                    )
                ]
                if method in {"api_route", "route"}:
                    methods = next(
                        (
                            ast.literal_eval(k.value)
                            for k in decorator.keywords
                            if k.arg == "methods"
                        ),
                        ["GET"],
                    )
                dependencies = sorted(
                    {
                        ast.unparse(call)
                        for call in ast.walk(node)
                        if isinstance(call, ast.Call)
                        and ast.unparse(call.func) in {"Depends", "check_role"}
                    }
                )
                for verb in methods:
                    rows.append(
                        {
                            "id": f"route:{relative}:{node.name}:{verb}:{route}",
                            "kind": "route",
                            "source": relative,
                            "handler": node.name,
                            "method": verb,
                            "path": route,
                            "observed_dependencies": dependencies,
                        }
                    )
        # Dynamic route registrations are recorded even when their path/handler
        # is computed. They cannot count as classified routes: runtime/matrix
        # conformance must resolve them before accepting the new surface.
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in ROUTE_REGISTRATIONS
            ):
                expression = ast.unparse(node)
                rows.append(
                    {
                        "id": f"route_registration:{relative}:{expression}",
                        "kind": "route_registration",
                        "source": relative,
                        "registration": expression,
                    }
                )
        # Registration expressions are inventoried independently of route nodes.
        # Source-expression identity avoids line-number churn and fails on a new
        # task target even when the enclosing route is unchanged.
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = ast.unparse(node.func).split(".")[-1]
            if name not in BOUNDARIES:
                continue
            expression = ast.unparse(node)
            scope = []
            parent = parents.get(node)
            while parent is not None:
                if isinstance(
                    parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    scope.append(parent.name)
                parent = parents.get(parent)
            scope = ".".join(reversed(scope)) or "<module>"
            key = (scope, expression)
            occurrences[key] = occurrences.get(key, 0) + 1
            rows.append(
                {
                    "id": f"action:{relative}:{scope}:{occurrences[key]}:{expression}",
                    "kind": "action",
                    "source": relative,
                    "scope": scope,
                    "registration": expression,
                }
            )
    return sorted(rows, key=lambda row: row["id"])


def write_inventories(root=ROOT):
    """Regenerate all three linked artifacts without changing policy rows."""
    from authority_calls import discover

    artifacts = {
        "auth-surface-inventory.json": inventory(root),
        "auth-authority-inventory.json": authority_inventory(root),
        "auth-authority-uses.json": discover(source_paths(root), root),
    }
    for filename, rows in artifacts.items():
        (root / "docs/security" / filename).write_text(
            json.dumps(rows, indent=2) + "\n"
        )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Regenerate the source inventory")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if args.write:
        write_inventories()
    else:
        print(json.dumps(inventory(), indent=2) + "\n", end="")

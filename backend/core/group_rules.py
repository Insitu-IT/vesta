"""
Dynamic group rule evaluation engine.

Converts rule definitions (JSON) into SQLAlchemy queries to resolve
group membership dynamically.

Rule schema:
    {"field": "name", "op": "regex", "value": "^prod-"}

Supported fields: name, state, agent_id
Supported operators: eq, neq, regex, glob, in
"""

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from models import VM

VALID_FIELDS = {"name", "state", "agent_id"}
VALID_OPS = {"eq", "neq", "regex", "glob", "in"}


def validate_rules(rules: list[dict]) -> list[str]:
    """Validate rule definitions. Returns list of error messages (empty = valid)."""
    errors = []
    if not isinstance(rules, list):
        return ["rules must be a list"]

    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            errors.append(f"Rule {i}: must be an object")
            continue
        field = rule.get("field")
        op = rule.get("op")
        value = rule.get("value")

        if field not in VALID_FIELDS:
            errors.append(
                f"Rule {i}: invalid field '{field}'. Must be one of: {', '.join(sorted(VALID_FIELDS))}"
            )
        if op not in VALID_OPS:
            errors.append(
                f"Rule {i}: invalid op '{op}'. Must be one of: {', '.join(sorted(VALID_OPS))}"
            )
        if value is None:
            errors.append(f"Rule {i}: value is required")
        if op == "in" and not isinstance(value, list):
            errors.append(f"Rule {i}: 'in' operator requires a list value")

    return errors


def _rule_to_filter(rule: dict):
    """Convert a single rule to a SQLAlchemy filter expression."""
    field = rule["field"]
    op = rule["op"]
    value = rule["value"]

    col = getattr(VM, field)

    if op == "eq":
        return col == value
    elif op == "neq":
        return col != value
    elif op == "regex":
        # PostgreSQL regex match (~)
        return col.op("~")(value)
    elif op == "glob":
        # Case-insensitive LIKE pattern (* → %, ? → _)
        like_pattern = value.replace("*", "%").replace("?", "_")
        return col.ilike(like_pattern)
    elif op == "in":
        return col.in_(value)


def build_rule_query(db: Session, rules: list[dict], match: str = "all"):
    """Convert rules JSON to a filtered SQLAlchemy query."""
    query = db.query(VM)

    if not rules:
        return query

    filters = [_rule_to_filter(r) for r in rules]

    if match == "any":
        query = query.filter(or_(*filters))
    else:
        query = query.filter(and_(*filters))

    return query


def resolve_group_members(db: Session, group) -> list:
    """Return VMs matching group rules (+ static members for hybrid)."""
    if group.group_type == "static":
        return list(group.vms)

    dynamic_vms = []
    if group.rules:
        query = build_rule_query(db, group.rules, group.rules_match or "all")
        dynamic_vms = query.all()

    if group.group_type == "hybrid":
        # Merge static + dynamic, deduplicate by ID
        static_ids = {vm.id for vm in group.vms}
        merged = list(group.vms)
        for vm in dynamic_vms:
            if vm.id not in static_ids:
                merged.append(vm)
        return merged

    return dynamic_vms

"""Every Settings field must have a reader.

Origin (#52, then #54): `backend/config.py` declares pydantic-settings fields
that nothing consumes. That is not untidiness — it is how #52 happened. Two
modules imported `JWT_SECRET` from `config`, which never defined it, and the
wrong import survived *because* nothing read `config`'s JWT fields. There was no
working consumer to contradict it. Dead configuration absorbs a wrong reference
and holds it plausible.

There is no generator to fix: `config.py` is hand-written, so the pattern is a
practice — a field added beside a feature, the feature wired up elsewhere, the
field left behind. Deleting the existing ones closes nothing. This check is what
closes it, by failing the next time it happens.

THREE WAYS A FIELD CAN BE READ WITHOUT LOOKING READ, and each has already
produced a false "dead" verdict somewhere in the cohort:

1. A DERIVED PROPERTY. `allowed_origins` is read through `allowed_origins_list`,
   which `middleware.py` uses for CORS. A hand-run of this analysis nearly filed
   a live CORS setting as dead, in an issue whose remedy is "wire it or delete
   it" — one action from removing working CORS configuration.
2. DYNAMIC ACCESS. `getattr(settings, "name")` is not an `ast.Attribute` either.
   dev-iris-core's first pass reported six candidates of which four were wrong;
   this resolution rescued their Vault CA encryption settings from a proposed
   deletion. vnbui uses no `getattr` on settings today — the resolution is here
   so the answer stays right when it does.
3. A READER IN ANOTHER REPOSITORY. Not an instrument bug and not fixable here:
   the AST is complete and the answer is elsewhere. vnbui's `commercial/` is
   in-tree and is scanned below, and a project search returns no separate
   counterpart — verified, not assumed. IF ONE IS EVER ADDED, THIS CHECK STOPS
   BEING SUFFICIENT and the unread set it reports becomes an over-count.

   That is not defensive boilerplate for a case which will never arrive. The
   cohort already has both instances: vnbui without a counterpart, and iris-core
   WITH one — where `uplink_require_mtls` has no reader in the main repo and is
   read from iris-core-commercial via `getattr(settings, ..., False)`. Deleting
   it there would have made strict mTLS unreachable, silently. And the group is
   moving toward that shape rather than away from it: an OSS/MSP/ENT commercial
   split is in flight. Whoever adds a counterpart to this repo has to widen
   CONSUMER_ROOTS or retire this check; a green run will not tell them.

⚠ AND "SAFE TO DELETE" IS NARROWER THAN IT SOUNDS. `Settings` declares no
`extra`, so pydantic ignores unknown environment variables and removing a field
cannot crash startup. That is not the same as harmless: where a field is read
elsewhere via `getattr(settings, name, default)`, deleting it makes the default
win silently — the operator sets the variable, pydantic discards it, and nothing
reports anything. The property that makes deletion safe from crashing is the
same one that makes such a deletion invisible.
"""

import ast
import os
import re

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(BACKEND_DIR, "config.py")

# The baseline is intentionally empty: every declared Settings field must have
# a reader. This may never grow; a newly unread field is the defect this file
# exists to catch.
KNOWN_UNREAD = set()


def _settings_members():
    """(annotated field names, {property/method name: its source})."""
    src = open(CONFIG, encoding="utf-8").read()
    tree = ast.parse(src)
    fields, members = [], {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "Settings":
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(
                    stmt.target, ast.Name
                ):
                    fields.append(stmt.target.id)
                elif isinstance(stmt, ast.FunctionDef):
                    members[stmt.name] = ast.get_source_segment(src, stmt) or ""
    return fields, members


# commercial/ is in-tree here and is scanned. A settings reader in a SEPARATE
# repository would be invisible to this check entirely — see the module docstring.
CONSUMER_ROOTS = (BACKEND_DIR, os.path.join(os.path.dirname(BACKEND_DIR), "commercial"))


def _consumer_source():
    """Every module that could read settings, except config.py itself."""
    out = []
    for base in CONSUMER_ROOTS:
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if d not in ("__pycache__", "tests", "alembic")]
            for name in sorted(files):
                path = os.path.join(root, name)
                if name.endswith(".py") and path != CONFIG:
                    out.append(open(path, encoding="utf-8").read())
    return "\n".join(out)


def unread_fields():
    fields, members = _settings_members()
    consumers = _consumer_source()

    def read_directly(f):
        return bool(re.search(r"\." + f + r"\b", consumers))

    def read_via_getattr(f):
        # getattr(settings, "field") — invisible to an attribute search.
        return bool(
            re.search(r'getattr\s*\(\s*\w+\s*,\s*["\']' + f + r'["\']', consumers)
        )

    def read_via_member(f):
        # A field referenced inside a property/method whose name is itself used
        # by a consumer counts as read. This is the allowed_origins case.
        for name, body in members.items():
            if re.search(r"\b" + f + r"\b", body) and re.search(
                r"\." + name + r"\b", consumers
            ):
                return True
        return False

    return {
        f
        for f in fields
        if not read_directly(f) and not read_via_member(f) and not read_via_getattr(f)
    }


def test_no_new_unread_settings_field():
    """The check. A field nobody reads is a name waiting to be wrongly imported."""
    unread = unread_fields()
    new = unread - KNOWN_UNREAD
    assert not new, (
        "Settings fields declared but read nowhere:\n"
        + "\n".join(f"  {f}" for f in sorted(new))
        + "\n\nWire it or delete it. See #54 — this is the condition that "
        "produced #52, where a field nothing read let a wrong import survive.\n"
        "Before deleting, confirm Settings still declares no `extra`: with "
        "extra=forbid, removing a field makes its env var a startup error."
    )


def test_the_baseline_only_shrinks():
    """KNOWN_UNREAD must not list a field that is now read, or it hides progress.

    Without this, wiring a field up leaves a stale entry that would mask the
    next genuinely-unread field with the same name.
    """
    stale = KNOWN_UNREAD - unread_fields()
    assert (
        not stale
    ), "these are read now and should be removed from KNOWN_UNREAD:\n" + "\n".join(
        f"  {f}" for f in sorted(stale)
    )


def test_derived_properties_count_as_reading_a_field():
    """The near-miss, pinned.

    allowed_origins is consumed only through allowed_origins_list. A check
    without property resolution reports it dead, and this issue's remedy is
    "wire it or delete it" — so the next reader deletes CORS configuration.
    """
    assert "allowed_origins" not in unread_fields(), (
        "allowed_origins is read via the allowed_origins_list property; a check "
        "that misses derived properties would license deleting live CORS config"
    )


def test_dynamic_access_counts_as_reading_a_field():
    """getattr resolution, pinned.

    dev-iris-core's first pass without this reported six dead fields of which
    four were read via getattr, including their Vault CA encryption settings.
    vnbui has no such usage today, so this asserts the resolver rather than a
    live field — otherwise the guard silently regresses the day someone adds one.
    """
    consumers = 'x = getattr(settings, "some_field", None)\n'
    assert re.search(r'getattr\s*\(\s*\w+\s*,\s*["\']some_field["\']', consumers)
    assert not re.search(r"\.some_field\b", consumers), (
        "the point of this resolution: getattr access does not appear as an "
        "attribute, so an attribute-only search calls the field dead"
    )


def test_the_detector_can_actually_fire():
    """Positive control.

    Without it, every assertion above passes against an analysis that finds
    nothing — and a scanner that silently stops matching is indistinguishable
    from a clean codebase.
    """
    fields, members = _settings_members()
    assert fields, "no Settings fields parsed — the analysis lost its target"

    # A field name that appears nowhere must be reported unread.
    consumers = "x = settings.database_url\n"
    invented = "a_field_no_module_reads"
    assert not re.search(r"\." + invented + r"\b", consumers)

    # ...and one that is referenced must not be.
    assert re.search(r"\.database_url\b", consumers)

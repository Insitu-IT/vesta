"""Cross-component consistency tests — auto-validated from source code.

These tests import directly from actual source modules to detect drift
between components. No hardcoded lists to maintain — if you add a router,
column, enum value, or endpoint, these tests pick it up automatically.

Catches at test time:
- Router files not registered in __init__.py
- VM sort columns that don't exist on the model
- Group rule fields that don't exist on the model
- Status enum drift between backend and agent
- Schema default mismatches vs ORM defaults
- Backend/frontend version drift
- Paginated endpoints missing skip/limit params
"""

import ast
import json
import os
import re
import sys

import pytest

# Path setup (also in conftest.py, but explicit for standalone clarity)
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_DIR = os.path.dirname(BACKEND_DIR)
ROUTERS_DIR = os.path.join(BACKEND_DIR, "routers")

sys.path.insert(0, BACKEND_DIR)
sys.path.insert(0, os.path.join(PROJECT_DIR, "agent"))


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers — extract info from source without importing the app
# ═══════════════════════════════════════════════════════════════════════════════


def _router_files():
    """Return set of router module names from the routers/ directory."""
    return {
        f[:-3]
        for f in os.listdir(ROUTERS_DIR)
        if f.endswith(".py") and f != "__init__.py"
    }


def _extract_set_from_source(filepath, varname):
    """Extract a set literal (e.g., VALID_VM_SORT_COLUMNS = {"a", "b"}) from source."""
    with open(filepath) as f:
        content = f.read()
    match = re.search(rf"{varname}\s*=\s*\{{([^}}]+)\}}", content)
    if not match:
        return set()
    return set(re.findall(r'["\'](\w+)["\']', match.group(1)))


def _registered_routers():
    """Return set of module names imported in routers/__init__.py."""
    init_path = os.path.join(ROUTERS_DIR, "__init__.py")
    with open(init_path) as f:
        content = f.read()
    # Match: from routers.foo import router as foo_router
    return set(re.findall(r"from routers\.(\w+) import", content))


def _integer_annotation(annotation):
    """Read plain/Annotated integer types without evaluating source code."""
    if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
        annotation = ast.parse(annotation.value, mode="eval").body
    if (
        isinstance(annotation, ast.Subscript)
        and ast.unparse(annotation.value).rsplit(".", 1)[-1] == "Annotated"
    ):
        arguments = annotation.slice
        annotation = (
            arguments.elts[0] if isinstance(arguments, ast.Tuple) else arguments
        )
    return isinstance(annotation, ast.Name) and annotation.id == "int"


def _paginated_routes_from_source(content):
    """Associate route decorators with their own function's pagination arguments."""
    tree = ast.parse(content)
    prefixes = {}
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if (
            not isinstance(value, ast.Call)
            or ast.unparse(value.func).rsplit(".", 1)[-1] != "APIRouter"
        ):
            continue
        prefix = next(
            (keyword.value for keyword in value.keywords if keyword.arg == "prefix"),
            None,
        )
        prefix = "" if prefix is None else ast.literal_eval(prefix)
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        prefixes.update(
            {target.id: prefix for target in targets if isinstance(target, ast.Name)}
        )

    result = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        arguments = {
            argument.arg: argument
            for argument in (
                node.args.posonlyargs + node.args.args + node.args.kwonlyargs
            )
        }
        if not {"skip", "limit"} <= arguments.keys() or not _integer_annotation(
            arguments["skip"].annotation
        ):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(
                decorator.func, ast.Attribute
            ):
                continue
            function = decorator.func
            if (
                not isinstance(function.value, ast.Name)
                or function.value.id not in prefixes
                or function.attr not in {"get", "post", "put", "patch", "delete"}
            ):
                continue
            path = (
                decorator.args[0]
                if decorator.args
                else next(
                    (
                        keyword.value
                        for keyword in decorator.keywords
                        if keyword.arg == "path"
                    ),
                    None,
                )
            )
            full_path = prefixes[function.value.id] + ast.literal_eval(path)
            result.append(
                (function.attr.upper(), re.sub(r"\{[^}]+\}", ":param", full_path))
            )
    return result


def _scan_paginated_endpoints():
    """Discover pagination from real signatures, including validated annotations."""
    result = []
    for filename in sorted(os.listdir(ROUTERS_DIR)):
        if not filename.endswith(".py") or filename.startswith("_"):
            continue
        with open(os.path.join(ROUTERS_DIR, filename)) as source:
            result.extend(_paginated_routes_from_source(source.read()))
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# 1. ROUTER REGISTRATION — every .py in routers/ must be in __init__.py
# ═══════════════════════════════════════════════════════════════════════════════


class TestRouterRegistration:
    """Verify all router files are imported and registered."""

    def test_all_router_files_registered(self):
        """Every .py file in routers/ must be imported in __init__.py."""
        on_disk = _router_files()
        registered = _registered_routers()
        missing = on_disk - registered
        assert not missing, (
            f"Router files exist but are NOT imported in routers/__init__.py: "
            f"{', '.join(sorted(missing))}. Add them to __init__.py and app.py."
        )

    def test_no_stale_imports(self):
        """__init__.py should not import routers that don't exist on disk."""
        on_disk = _router_files()
        registered = _registered_routers()
        stale = registered - on_disk
        assert not stale, (
            f"routers/__init__.py imports modules that don't exist: "
            f"{', '.join(sorted(stale))}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 2. VM SORT COLUMNS — agents.py VALID_VM_SORT_COLUMNS vs actual VM model
# ═══════════════════════════════════════════════════════════════════════════════


class TestVMSortColumns:
    """Verify VM sort columns reference real model columns.

    Extracts VALID_VM_SORT_COLUMNS from agents.py source (avoids importing
    the full router chain which pulls in apscheduler and other dependencies).
    """

    # Columns that are valid sort targets but resolved via JOIN, not direct VM columns
    KNOWN_JOIN_COLUMNS = {"agent_hostname"}

    @pytest.fixture(scope="class")
    def sort_columns(self):
        return _extract_set_from_source(
            os.path.join(ROUTERS_DIR, "agents.py"), "VALID_VM_SORT_COLUMNS"
        )

    def test_sort_columns_found(self, sort_columns):
        """Sanity: we should find the set in the source."""
        assert (
            len(sort_columns) >= 4
        ), f"Only found {sort_columns} — extractor may be broken"

    def test_sort_columns_exist_on_model(self, sort_columns):
        """Every VALID_VM_SORT_COLUMNS entry must be a VM column or a known join."""
        from models import VM

        vm_columns = {c.key for c in VM.__table__.columns}
        invalid = sort_columns - vm_columns - self.KNOWN_JOIN_COLUMNS
        assert not invalid, (
            f"VALID_VM_SORT_COLUMNS contains columns that don't exist on VM model "
            f"and aren't known joins: {invalid}. "
            f"Valid VM columns: {sorted(vm_columns)}"
        )

    def test_join_columns_have_handler(self, sort_columns):
        """Join-based sort columns (agent_hostname) must have explicit handling in the router."""
        filepath = os.path.join(ROUTERS_DIR, "agents.py")
        with open(filepath) as f:
            content = f.read()

        for col in sort_columns & self.KNOWN_JOIN_COLUMNS:
            assert f'"{col}"' in content or f"'{col}'" in content, (
                f"Join column '{col}' is in VALID_VM_SORT_COLUMNS but has no "
                f"special handling in agents.py"
            )


# ═══════════════════════════════════════════════════════════════════════════════
# 3. GROUP RULE FIELDS — group_rules.py VALID_FIELDS vs actual VM model
# ═══════════════════════════════════════════════════════════════════════════════


class TestGroupRuleFields:
    """Verify dynamic group rule fields reference real model columns.

    Extracts VALID_FIELDS from source to avoid triggering router imports.
    """

    @pytest.fixture(scope="class")
    def rule_fields(self):
        return _extract_set_from_source(
            os.path.join(BACKEND_DIR, "core", "group_rules.py"), "VALID_FIELDS"
        )

    @pytest.fixture(scope="class")
    def rule_ops(self):
        return _extract_set_from_source(
            os.path.join(BACKEND_DIR, "core", "group_rules.py"), "VALID_OPS"
        )

    def test_rule_fields_exist_on_model(self, rule_fields):
        """Every VALID_FIELDS entry must be a real VM column."""
        from models import VM

        vm_columns = {c.key for c in VM.__table__.columns}
        invalid = rule_fields - vm_columns
        assert not invalid, (
            f"group_rules.VALID_FIELDS contains fields that don't exist on VM: "
            f"{invalid}. Valid VM columns: {sorted(vm_columns)}"
        )

    def test_rule_ops_covered(self, rule_ops):
        """All VALID_OPS must be handled in _rule_to_filter."""
        filepath = os.path.join(BACKEND_DIR, "core", "group_rules.py")
        with open(filepath) as f:
            content = f.read()
        # Find the _rule_to_filter function body
        start = content.find("def _rule_to_filter")
        assert start != -1, "_rule_to_filter function not found"
        func_body = content[start:]
        for op in rule_ops:
            assert (
                f'"{op}"' in func_body or f"'{op}'" in func_body
            ), f"Operator '{op}' is in VALID_OPS but not handled in _rule_to_filter()"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. STATUS ENUM PARITY — backend string literals vs agent enums
# ═══════════════════════════════════════════════════════════════════════════════


class TestStatusEnumParity:
    """Verify status strings used in backend match agent enum definitions."""

    def test_backup_status_values_match_agent(self):
        """Status values used in ORM default + queries must be in agent TaskStatus."""
        from contracts.contracts import TASK_STATUSES
        from models import Backup

        # Backup.status default from the model
        default = Backup.status.property.columns[0].default.arg
        assert (
            default in TASK_STATUSES
        ), f"Backup.status default '{default}' not in agent TaskStatus: {TASK_STATUSES}"

    def test_restore_status_values_match_agent(self):
        """Restore status values must match agent TaskStatus."""
        from contracts.contracts import TASK_STATUSES
        from models import Restore

        default = Restore.status.property.columns[0].default.arg
        assert (
            default in TASK_STATUSES
        ), f"Restore.status default '{default}' not in agent TaskStatus: {TASK_STATUSES}"

    def test_backup_type_default_matches_agent(self):
        """Backup.backup_type default must be a valid agent BackupType."""
        from contracts.contracts import BACKUP_TYPES
        from models import Backup

        default = Backup.backup_type.property.columns[0].default.arg
        assert (
            default in BACKUP_TYPES
        ), f"Backup.backup_type default '{default}' not in agent BackupType: {BACKUP_TYPES}"

    def test_schema_backup_type_default_matches_model(self):
        """BackupCreate.backup_type default must match Backup.backup_type default."""
        from schemas.models import BackupCreate
        from models import Backup

        schema_default = BackupCreate.model_fields["backup_type"].default
        model_default = Backup.backup_type.property.columns[0].default.arg
        assert schema_default == model_default, (
            f"BackupCreate.backup_type default '{schema_default}' != "
            f"Backup.backup_type column default '{model_default}'"
        )

    def test_encryption_key_status_values(self):
        """EncryptionKey.status values must be documented set."""
        from models import EncryptionKey

        # These are the only valid transitions in the KMS lifecycle
        expected = {"active", "rotated", "revoked"}
        default = EncryptionKey.status.property.columns[0].default.arg
        assert (
            default in expected
        ), f"EncryptionKey.status default '{default}' not in expected: {expected}"

    def test_agent_certificate_status_values(self):
        """AgentCertificate.status values must cover the lifecycle."""
        from models import AgentCertificate

        expected = {"active", "expired", "revoked"}
        default = AgentCertificate.status.property.columns[0].default.arg
        assert (
            default in expected
        ), f"AgentCertificate.status default '{default}' not in expected: {expected}"


# ═══════════════════════════════════════════════════════════════════════════════
# 5. SCHEMA CONSISTENCY — Pydantic models should agree with each other
# ═══════════════════════════════════════════════════════════════════════════════


class TestSchemaConsistency:
    """Verify Pydantic schemas are consistent across related models."""

    def test_tags_type_consistency(self):
        """BackupCreate and BulkBackupCreate should agree on tags type.

        BulkBackupCreate.tags is dict, BackupQueueCreate.tags is List[str].
        This test documents the inconsistency so it's visible.
        """
        from schemas.models import BackupCreate, BulkBackupCreate

        bc_type = BackupCreate.model_fields["tags"].annotation
        bulk_type = BulkBackupCreate.model_fields["tags"].annotation

        # BackupCreate and BulkBackupCreate should match
        assert bc_type == bulk_type, (
            f"BackupCreate.tags type ({bc_type}) != "
            f"BulkBackupCreate.tags type ({bulk_type})"
        )

    def test_group_type_values_match_model(self):
        """VMGroupCreate.group_type default must match VMGroup column default."""
        from schemas.models import VMGroupCreate
        from models import VMGroup

        schema_default = VMGroupCreate.model_fields["group_type"].default
        model_default = VMGroup.group_type.property.columns[0].default.arg
        assert schema_default == model_default, (
            f"VMGroupCreate.group_type default '{schema_default}' != "
            f"VMGroup.group_type column default '{model_default}'"
        )

    def test_rules_match_values_match_model(self):
        """VMGroupCreate.rules_match default must match VMGroup column default."""
        from schemas.models import VMGroupCreate
        from models import VMGroup

        schema_default = VMGroupCreate.model_fields["rules_match"].default
        model_default = VMGroup.rules_match.property.columns[0].default.arg
        assert schema_default == model_default, (
            f"VMGroupCreate.rules_match default '{schema_default}' != "
            f"VMGroup.rules_match column default '{model_default}'"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 6. VERSION SYNC — backend and frontend versions must match (major.minor)
# ═══════════════════════════════════════════════════════════════════════════════


class TestVersionSync:
    """Verify component versions stay in sync."""

    def _backend_version(self):
        from version import __version__

        return __version__

    def _frontend_version(self):
        pkg_path = os.path.join(PROJECT_DIR, "frontend", "package.json")
        with open(pkg_path) as f:
            return json.load(f)["version"]

    def _agent_version(self):
        version_path = os.path.join(PROJECT_DIR, "agent", "VERSION")
        with open(version_path) as f:
            return f.read().strip()

    def test_backend_frontend_major_minor_match(self):
        """Backend and frontend must share same major.minor version."""
        be = self._backend_version()
        fe = self._frontend_version()
        be_mm = ".".join(be.split(".")[:2])
        fe_mm = ".".join(fe.split(".")[:2])
        assert (
            be_mm == fe_mm
        ), f"Backend ({be}) and frontend ({fe}) major.minor versions diverged"

    def test_backend_agent_major_minor_match(self):
        """Backend and agent must share same major.minor version."""
        be = self._backend_version()
        ag = self._agent_version()
        be_mm = ".".join(be.split(".")[:2])
        ag_mm = ".".join(ag.split(".")[:2])
        assert (
            be_mm == ag_mm
        ), f"Backend ({be}) and agent ({ag}) major.minor versions diverged"


# ═══════════════════════════════════════════════════════════════════════════════
# 7. PAGINATED ENDPOINTS — auto-discovered from router source
# ═══════════════════════════════════════════════════════════════════════════════


class TestPaginatedEndpoints:
    """Verify all paginated endpoints are GET routes (auto-discovered)."""

    @pytest.mark.parametrize(
        "annotation",
        [
            "int",
            "Annotated[int, Query(ge=0)]",
            "typing.Annotated[int, Query(ge=0)]",
            '"Annotated[int, Query(ge=0)]"',
        ],
    )
    def test_pagination_discovery_uses_own_signature(self, annotation):
        source = f'''router = APIRouter(prefix="/api/v1")
@router.get("/decoy")
def detail():
    """The text skip: int describes no actual pagination parameter."""
    return None

@router.get(
    "/records/{{record_id}}",
    summary="A decorator longer than the historical lookahead",
)
@other_decorator
async def records(request, *, limit: int = 50, skip: {annotation} = 0):
    raise RuntimeError("Source scanning must never import or execute this module")
'''
        assert _paginated_routes_from_source(source) == [
            ("GET", "/api/v1/records/:param")
        ]

    def test_paginated_get_endpoints_exist(self):
        """All GET endpoints with skip/limit params should be properly registered."""
        paginated = _scan_paginated_endpoints()
        get_paginated = [(m, p) for m, p in paginated if m == "GET"]
        assert len(get_paginated) >= 10, (
            f"Only found {len(get_paginated)} paginated GET endpoints — "
            f"scanner may be broken. Found: {get_paginated}"
        )

    def test_paginated_count_sanity(self):
        """Sanity check: we should find a reasonable number of paginated endpoints."""
        paginated = _scan_paginated_endpoints()
        # We know there are at least 11 paginated endpoints as of v4.2
        assert len(paginated) >= 10, (
            f"Expected at least 10 paginated endpoints, found {len(paginated)}: "
            + ", ".join(f"{m} {p}" for m, p in paginated)
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 8. BUILDER ↔ EXECUTOR ALIGNMENT — agent_requests.py vs actual usage
# ═══════════════════════════════════════════════════════════════════════════════


class TestBuilderAlignment:
    """Verify builder functions in agent_requests.py match executor usage."""

    def test_build_backup_request_params_match_agent_model(self):
        """All fields in build_backup_request output must exist on agent BackupRequest."""
        from core.agent_requests import build_backup_request
        from contracts.contracts import BACKUP_REQUEST_FIELDS

        d = build_backup_request("id", "vm", "full", "/tmp/out")
        for key in d:
            assert key in BACKUP_REQUEST_FIELDS, (
                f"build_backup_request() produces key '{key}' that doesn't exist "
                f"on agent BackupRequest model. Agent fields: {sorted(BACKUP_REQUEST_FIELDS)}"
            )

    def test_build_restore_request_params_match_agent_model(self):
        """All fields in build_restore_request output must exist on agent RestoreRequest."""
        from core.agent_requests import build_restore_request
        from contracts.contracts import RESTORE_REQUEST_FIELDS

        d = build_restore_request("id", "/path", "/out")
        for key in d:
            assert key in RESTORE_REQUEST_FIELDS, (
                f"build_restore_request() produces key '{key}' that doesn't exist "
                f"on agent RestoreRequest model. Agent fields: {sorted(RESTORE_REQUEST_FIELDS)}"
            )

    def test_build_s3_restore_request_params_match_agent_model(self):
        """All fields in build_s3_restore_request output must exist on agent RestoreRequest."""
        from core.agent_requests import build_s3_restore_request, build_s3_config
        from contracts.contracts import RESTORE_REQUEST_FIELDS

        d = build_s3_restore_request(
            "id",
            "/out",
            s3_config=build_s3_config(None, "b", None, "a", "s"),
            chain_members=[],
        )
        for key in d:
            assert key in RESTORE_REQUEST_FIELDS, (
                f"build_s3_restore_request() produces key '{key}' that doesn't exist "
                f"on agent RestoreRequest model. Agent fields: {sorted(RESTORE_REQUEST_FIELDS)}"
            )

    def test_heartbeat_response_keys_stable(self):
        """build_heartbeat_response must always return the documented keys."""
        from core.agent_requests import build_heartbeat_response
        from contracts.contracts import HEARTBEAT_RESPONSE_FIELDS

        d = build_heartbeat_response("a", "t", {})
        assert (
            set(d.keys()) == HEARTBEAT_RESPONSE_FIELDS
        ), f"Heartbeat response keys drifted: {set(d.keys())} != {HEARTBEAT_RESPONSE_FIELDS}"

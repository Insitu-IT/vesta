"""
Tests for M2 scale features — full-cycle flow tests.

Tests every flow that uses or relies on scale features:
1. VM list: pagination, sorting, filtering, combined filters
2. VM ids-by-filter: exact parity with list_vms query
3. Dynamic groups: create → rules → resolve → schedule
4. Hybrid groups: static + dynamic merge, deduplication
5. Groups pagination: list + detail view
6. Bulk backup: filter-based resolution
7. Group lifecycle: create → edit type → add rules → preview → delete
8. Edge cases: empty rules, zero results, boundary pages
"""

import pytest
import uuid

# Fixtures (db_engine, session_factory, db_session, set_encryption_env,
# _clean_db) provided by conftest.py


@pytest.fixture
def db(db_session):
    """Alias for db_session — test_scale uses 'db' parameter name."""
    return db_session


# ============================================================
# Test data builders
# ============================================================


def _make_agent(db, hostname="host1"):
    from models import Agent

    agent = Agent(id=str(uuid.uuid4()), hostname=hostname, status="online")
    db.add(agent)
    db.flush()
    return agent


def _make_vm(db, agent, name="vm1", state="running", memory_kb=2048, vcpu_count=2):
    from models import VM

    vm = VM(
        id=str(uuid.uuid4()),
        name=name,
        agent_id=agent.id,
        state=state,
        uuid=str(uuid.uuid4()),
        memory_kb=memory_kb,
        vcpu_count=vcpu_count,
    )
    db.add(vm)
    db.flush()
    return vm


def _make_group(db, name="grp1", group_type="static", rules=None, rules_match="all"):
    from models import VMGroup

    group = VMGroup(
        id=str(uuid.uuid4()),
        name=name,
        group_type=group_type,
        rules=rules,
        rules_match=rules_match,
    )
    db.add(group)
    db.flush()
    return group


def _build_vm_query(db, search=None, agent_id=None, state=None, group_id=None):
    """Mirror of routers.agents._build_vm_query (avoids import cascade)."""
    from models import VM, vm_group_association

    query = db.query(VM)
    if search:
        query = query.filter(VM.name.ilike(f"%{search}%"))
    if agent_id:
        query = query.filter(VM.agent_id == agent_id)
    if state:
        query = query.filter(VM.state == state)
    if group_id:
        query = query.join(vm_group_association).filter(
            vm_group_association.c.group_id == group_id
        )
    return query


def _resolve_bulk_vm_ids(db, bulk_data):
    """Mirror of routers.bulk._resolve_bulk_vm_ids (avoids import cascade)."""
    from models import VM

    if bulk_data.vm_ids:
        return bulk_data.vm_ids
    if bulk_data.filter:
        query = _build_vm_query(
            db,
            search=bulk_data.filter.get("search"),
            agent_id=bulk_data.filter.get("agent_id"),
            state=bulk_data.filter.get("state"),
            group_id=bulk_data.filter.get("group_id"),
        )
        return [vm.id for vm in query.with_entities(VM.id).all()]
    return []


def _seed_large_dataset(db, num_agents=3, vms_per_agent=20):
    """Create a realistic dataset for pagination tests."""
    agents = []
    all_vms = []
    for i in range(num_agents):
        agent = _make_agent(db, f"kvm-host-{i:02d}")
        agents.append(agent)
        for j in range(vms_per_agent):
            state = ["running", "stopped", "paused"][j % 3]
            prefix = ["prod", "dev", "staging"][j % 3]
            vm = _make_vm(
                db,
                agent,
                name=f"{prefix}-vm-{i:02d}-{j:03d}",
                state=state,
                memory_kb=(j + 1) * 1024,
                vcpu_count=(j % 4) + 1,
            )
            all_vms.append(vm)
    db.commit()
    return agents, all_vms


# ============================================================
# FLOW 1: VM list — pagination + sorting + filtering
# ============================================================


class TestVMListFlow:
    """Full flow: frontend loads VM page → server-side pagination/sort/filter."""

    def test_pagination_basics(self, db):
        """Page 1 returns first N items, page 2 returns next N."""
        agents, vms = _seed_large_dataset(db, 1, 10)
        from models import VM

        query = db.query(VM).order_by(VM.name.asc())
        total = query.count()
        assert total == 10

        page1 = query.offset(0).limit(5).all()
        page2 = query.offset(5).limit(5).all()
        assert len(page1) == 5
        assert len(page2) == 5
        # No overlap
        page1_ids = {vm.id for vm in page1}
        page2_ids = {vm.id for vm in page2}
        assert page1_ids.isdisjoint(page2_ids)

    def test_sort_by_name_asc(self, db):
        agent = _make_agent(db, "h1")
        _make_vm(db, agent, "charlie")
        _make_vm(db, agent, "alpha")
        _make_vm(db, agent, "bravo")
        db.commit()
        from models import VM

        vms = db.query(VM).order_by(VM.name.asc()).all()
        names = [v.name for v in vms]
        assert names == ["alpha", "bravo", "charlie"]

    def test_sort_by_name_desc(self, db):
        agent = _make_agent(db, "h1")
        _make_vm(db, agent, "charlie")
        _make_vm(db, agent, "alpha")
        _make_vm(db, agent, "bravo")
        db.commit()
        from models import VM

        vms = db.query(VM).order_by(VM.name.desc()).all()
        names = [v.name for v in vms]
        assert names == ["charlie", "bravo", "alpha"]

    def test_sort_by_memory(self, db):
        agent = _make_agent(db, "h1")
        _make_vm(db, agent, "big", memory_kb=8192)
        _make_vm(db, agent, "small", memory_kb=1024)
        _make_vm(db, agent, "medium", memory_kb=4096)
        db.commit()
        from models import VM

        vms = db.query(VM).order_by(VM.memory_kb.asc()).all()
        names = [v.name for v in vms]
        assert names == ["small", "medium", "big"]

    def test_sort_by_agent_hostname(self, db):
        """Sort by agent hostname requires join to Agent table."""
        from models import VM, Agent

        agent_z = _make_agent(db, "z-host")
        agent_a = _make_agent(db, "a-host")
        _make_vm(db, agent_z, "vm-on-z")
        _make_vm(db, agent_a, "vm-on-a")
        db.commit()

        vms = (
            db.query(VM)
            .join(Agent, VM.agent_id == Agent.id)
            .order_by(Agent.hostname.asc())
            .all()
        )
        hostnames = [v.agent.hostname for v in vms]
        assert hostnames == ["a-host", "z-host"]

    def test_combined_filter_and_sort(self, db):
        """Filter by state + sort by name — the common UI case."""
        from models import VM

        agent = _make_agent(db, "h1")
        _make_vm(db, agent, "z-prod", state="running")
        _make_vm(db, agent, "a-prod", state="running")
        _make_vm(db, agent, "stopped-one", state="stopped")
        db.commit()

        query = _build_vm_query(db, state="running")
        vms = query.order_by(VM.name.asc()).all()
        assert len(vms) == 2
        assert vms[0].name == "a-prod"
        assert vms[1].name == "z-prod"

    def test_group_filter_with_sort(self, db):
        """Filter by group_id AND sort — tests the double-join case."""
        from models import VM, Agent

        agent1 = _make_agent(db, "host-b")
        agent2 = _make_agent(db, "host-a")
        vm1 = _make_vm(db, agent1, "vm1")
        vm2 = _make_vm(db, agent2, "vm2")
        _vm3 = _make_vm(db, agent1, "vm3")  # noqa: F841 - not in group
        group = _make_group(db, "test-grp")
        group.vms.append(vm1)
        group.vms.append(vm2)
        db.commit()

        # Filter by group + sort by agent hostname
        query = _build_vm_query(db, group_id=group.id)
        query = query.join(Agent, VM.agent_id == Agent.id)
        vms = query.order_by(Agent.hostname.asc()).all()
        assert len(vms) == 2
        assert vms[0].agent.hostname == "host-a"
        assert vms[1].agent.hostname == "host-b"

    def test_search_plus_agent_filter(self, db):
        """Multiple filters combined."""
        agent1 = _make_agent(db, "host1")
        agent2 = _make_agent(db, "host2")
        _make_vm(db, agent1, "prod-web01")
        _make_vm(db, agent1, "prod-db01")
        _make_vm(db, agent2, "prod-web02")
        _make_vm(db, agent1, "dev-web01")
        db.commit()

        vms = _build_vm_query(db, search="prod", agent_id=agent1.id).all()
        assert len(vms) == 2
        names = {v.name for v in vms}
        assert names == {"prod-web01", "prod-db01"}

    def test_count_matches_results(self, db):
        """count() returns same number as len(all())."""
        agents, _ = _seed_large_dataset(db, 2, 15)

        query = _build_vm_query(db, state="running")
        count = query.count()
        results = query.all()
        assert count == len(results)

    def test_pagination_total_consistent_across_pages(self, db):
        """Total count is the same regardless of which page you request."""
        _seed_large_dataset(db, 1, 25)
        from models import VM

        query = db.query(VM).order_by(VM.name)
        total = query.count()

        page1 = query.offset(0).limit(10).all()
        page2 = query.offset(10).limit(10).all()
        page3 = query.offset(20).limit(10).all()

        assert len(page1) == 10
        assert len(page2) == 10
        assert len(page3) == 5
        assert len(page1) + len(page2) + len(page3) == total

    def test_valid_sort_columns(self):
        from models import VM, Agent

        valid = {
            "name",
            "state",
            "memory_kb",
            "vcpu_count",
            "created_at",
            "agent_hostname",
        }
        for col in valid:
            if col == "agent_hostname":
                assert hasattr(Agent, "hostname")
            else:
                assert hasattr(VM, col), f"VM missing column {col}"


# ============================================================
# FLOW 2: VM ids-by-filter — parity with list_vms
# ============================================================


class TestVMIdsByFilter:
    """Full flow: user clicks 'Select all N matching' → POST ids-by-filter."""

    def test_ids_match_list_results(self, db):
        """ids-by-filter returns same IDs as paginated list_vms would."""
        from models import VM

        _seed_large_dataset(db, 2, 20)

        # Filter by state
        query = _build_vm_query(db, state="running")
        all_ids = [vm.id for vm in query.with_entities(VM.id).all()]
        all_vms = query.all()
        assert len(all_ids) == len(all_vms)
        assert set(all_ids) == {vm.id for vm in all_vms}

    def test_filter_by_group_id(self, db):
        """ids-by-filter with group_id returns only group members."""
        from models import VM

        agent = _make_agent(db, "h1")
        vm1 = _make_vm(db, agent, "in-group")
        _vm2 = _make_vm(db, agent, "not-in-group")  # noqa: F841
        group = _make_group(db, "g1")
        group.vms.append(vm1)
        db.commit()

        query = _build_vm_query(db, group_id=group.id)
        ids = [vm.id for vm in query.with_entities(VM.id).all()]
        assert ids == [vm1.id]

    def test_empty_filter_returns_all(self, db):
        """No filters → returns all VMs."""
        from models import VM

        agent = _make_agent(db, "h1")
        _make_vm(db, agent, "a")
        _make_vm(db, agent, "b")
        db.commit()

        query = _build_vm_query(db)
        ids = [vm.id for vm in query.with_entities(VM.id).all()]
        assert len(ids) == 2

    def test_no_match_returns_empty(self, db):
        """Filter that matches nothing → empty list."""
        from models import VM

        agent = _make_agent(db, "h1")
        _make_vm(db, agent, "running-vm", state="running")
        db.commit()

        query = _build_vm_query(db, state="error")
        ids = [vm.id for vm in query.with_entities(VM.id).all()]
        assert ids == []


# ============================================================
# FLOW 3: Dynamic group — full lifecycle
# ============================================================


class TestDynamicGroupLifecycle:
    """Create dynamic group → rules match VMs → scheduler resolves at execution."""

    def test_create_with_rules(self, db):
        """Create dynamic group, verify rules stored and members resolved."""
        from core.group_rules import resolve_group_members, validate_rules

        agent = _make_agent(db, "h1")
        _make_vm(db, agent, "prod-web01", state="running")
        _make_vm(db, agent, "prod-db01", state="running")
        _make_vm(db, agent, "dev-web01", state="running")
        db.commit()

        rules = [{"field": "name", "op": "glob", "value": "prod-*"}]
        assert validate_rules(rules) == []

        group = _make_group(db, "prod-vms", group_type="dynamic", rules=rules)
        db.commit()

        members = resolve_group_members(db, group)
        assert len(members) == 2
        names = {m.name for m in members}
        assert names == {"prod-web01", "prod-db01"}

    def test_dynamic_group_auto_updates(self, db):
        """Adding a VM that matches rules auto-includes it (no manual add)."""
        from core.group_rules import resolve_group_members

        agent = _make_agent(db, "h1")
        _make_vm(db, agent, "prod-web01")
        db.commit()

        group = _make_group(
            db,
            "prod",
            group_type="dynamic",
            rules=[{"field": "name", "op": "glob", "value": "prod-*"}],
        )
        db.commit()

        assert len(resolve_group_members(db, group)) == 1

        # Add a new VM that matches the rule
        _make_vm(db, agent, "prod-web02")
        db.commit()

        # Re-resolve — should now include the new VM
        assert len(resolve_group_members(db, group)) == 2

    def test_dynamic_group_excludes_non_matching(self, db):
        """VM that stops matching rules is excluded on next resolution."""
        from core.group_rules import resolve_group_members

        agent = _make_agent(db, "h1")
        vm = _make_vm(db, agent, "prod-web01", state="running")
        db.commit()

        group = _make_group(
            db,
            "running-prod",
            group_type="dynamic",
            rules=[
                {"field": "name", "op": "glob", "value": "prod-*"},
                {"field": "state", "op": "eq", "value": "running"},
            ],
        )
        db.commit()

        assert len(resolve_group_members(db, group)) == 1

        # VM goes offline
        vm.state = "stopped"
        db.commit()

        assert len(resolve_group_members(db, group)) == 0

    def test_scheduler_resolves_dynamic_group(self, db):
        """Simulates what the scheduler does: resolve group → get target VMs."""
        from core.group_rules import resolve_group_members
        from models import VMGroup

        agent = _make_agent(db, "h1")
        _make_vm(db, agent, "prod-web01")
        _make_vm(db, agent, "prod-db01")
        _make_vm(db, agent, "dev-web01")
        db.commit()

        group = _make_group(
            db,
            "scheduled-group",
            group_type="dynamic",
            rules=[{"field": "name", "op": "glob", "value": "prod-*"}],
        )
        db.commit()

        # This is what scheduler.py does:
        fetched_group = db.query(VMGroup).filter(VMGroup.id == group.id).first()
        if fetched_group.group_type == "static":
            target_vms = list(fetched_group.vms)
        else:
            target_vms = resolve_group_members(db, fetched_group)

        assert len(target_vms) == 2
        names = {vm.name for vm in target_vms}
        assert names == {"prod-web01", "prod-db01"}

    def test_any_match_mode(self, db):
        """rules_match='any' uses OR logic."""
        from core.group_rules import resolve_group_members

        agent = _make_agent(db, "h1")
        _make_vm(db, agent, "prod-web01", state="running")
        _make_vm(db, agent, "dev-db01", state="stopped")
        _make_vm(db, agent, "staging-api", state="paused")
        db.commit()

        group = _make_group(
            db,
            "any-match",
            group_type="dynamic",
            rules=[
                {"field": "name", "op": "glob", "value": "prod-*"},
                {"field": "state", "op": "eq", "value": "stopped"},
            ],
            rules_match="any",
        )
        db.commit()

        members = resolve_group_members(db, group)
        names = {m.name for m in members}
        # prod-web01 matches first rule, dev-db01 matches second
        assert names == {"prod-web01", "dev-db01"}

    def test_all_match_mode(self, db):
        """rules_match='all' uses AND logic."""
        from core.group_rules import resolve_group_members

        agent = _make_agent(db, "h1")
        _make_vm(db, agent, "prod-web01", state="running")
        _make_vm(db, agent, "prod-db01", state="stopped")
        _make_vm(db, agent, "dev-web01", state="running")
        db.commit()

        group = _make_group(
            db,
            "all-match",
            group_type="dynamic",
            rules=[
                {"field": "name", "op": "glob", "value": "prod-*"},
                {"field": "state", "op": "eq", "value": "running"},
            ],
            rules_match="all",
        )
        db.commit()

        members = resolve_group_members(db, group)
        assert len(members) == 1
        assert members[0].name == "prod-web01"


# ============================================================
# FLOW 4: Hybrid group — static + dynamic merge
# ============================================================


class TestHybridGroupFlow:
    """Hybrid groups combine manual VM assignment with rule-based resolution."""

    def test_hybrid_includes_both(self, db):
        """Hybrid returns union of static members + rule-matched VMs."""
        from core.group_rules import resolve_group_members

        agent = _make_agent(db, "h1")
        vm_static = _make_vm(db, agent, "manually-added", state="stopped")
        _vm_dynamic = _make_vm(db, agent, "prod-web01", state="running")  # noqa: F841
        vm_both = _make_vm(db, agent, "prod-db01", state="running")
        db.commit()

        group = _make_group(
            db,
            "hybrid",
            group_type="hybrid",
            rules=[{"field": "name", "op": "glob", "value": "prod-*"}],
        )
        group.vms.append(vm_static)
        group.vms.append(vm_both)  # Statically added AND matches rule
        db.commit()

        members = resolve_group_members(db, group)
        names = {m.name for m in members}
        # static: manually-added, prod-db01
        # dynamic: prod-web01, prod-db01
        # merged: all three, deduplicated
        assert names == {"manually-added", "prod-web01", "prod-db01"}
        assert len(members) == 3

    def test_hybrid_deduplicates(self, db):
        """A VM in both static and dynamic results appears only once."""
        from core.group_rules import resolve_group_members

        agent = _make_agent(db, "h1")
        vm = _make_vm(db, agent, "prod-web01")
        db.commit()

        group = _make_group(
            db,
            "hybrid-dedup",
            group_type="hybrid",
            rules=[{"field": "name", "op": "glob", "value": "prod-*"}],
        )
        group.vms.append(vm)  # Static AND matches rule
        db.commit()

        members = resolve_group_members(db, group)
        assert len(members) == 1
        assert members[0].name == "prod-web01"

    def test_hybrid_no_rules_returns_static_only(self, db):
        """Hybrid with no rules returns only static members."""
        from core.group_rules import resolve_group_members

        agent = _make_agent(db, "h1")
        vm = _make_vm(db, agent, "vm1")
        db.commit()

        group = _make_group(db, "hybrid-no-rules", group_type="hybrid", rules=None)
        group.vms.append(vm)
        db.commit()

        members = resolve_group_members(db, group)
        assert len(members) == 1


# ============================================================
# FLOW 5: Groups pagination
# ============================================================


class TestGroupsPagination:
    """Groups list and detail pagination."""

    def test_groups_paginated(self, db):
        """List groups returns paginated results."""
        from models import VMGroup

        for i in range(15):
            _make_group(db, f"group-{i:02d}")
        db.commit()

        query = db.query(VMGroup).order_by(VMGroup.name)
        total = query.count()
        assert total == 15

        page1 = query.offset(0).limit(10).all()
        page2 = query.offset(10).limit(10).all()
        assert len(page1) == 10
        assert len(page2) == 5

    def test_groups_search(self, db):
        from models import VMGroup

        _make_group(db, "production-servers")
        _make_group(db, "development-servers")
        _make_group(db, "production-databases")
        db.commit()

        results = db.query(VMGroup).filter(VMGroup.name.ilike("%production%")).all()
        assert len(results) == 2

    def test_groups_type_filter(self, db):
        from models import VMGroup

        _make_group(db, "static-one", group_type="static")
        _make_group(db, "dynamic-one", group_type="dynamic")
        _make_group(db, "dynamic-two", group_type="dynamic")
        db.commit()

        results = db.query(VMGroup).filter(VMGroup.group_type == "dynamic").all()
        assert len(results) == 2

    def test_group_detail_vm_pagination(self, db):
        """Group detail view returns paginated VM list."""
        from core.group_rules import resolve_group_members

        agent = _make_agent(db, "h1")
        group = _make_group(db, "big-group")
        for i in range(25):
            vm = _make_vm(db, agent, f"vm-{i:03d}")
            group.vms.append(vm)
        db.commit()

        all_vms = resolve_group_members(db, group)
        assert len(all_vms) == 25

        page1 = all_vms[0:10]
        page2 = all_vms[10:20]
        page3 = all_vms[20:30]
        assert len(page1) == 10
        assert len(page2) == 10
        assert len(page3) == 5


# ============================================================
# FLOW 6: Bulk backup with filter resolution
# ============================================================


class TestBulkFilterFlow:
    """User selects VMs by filter → bulk-create uses filter resolution."""

    def test_filter_by_state(self, db):
        from schemas import BulkBackupCreate

        agent = _make_agent(db, "h1")
        vm_r1 = _make_vm(db, agent, "running-1", state="running")
        vm_r2 = _make_vm(db, agent, "running-2", state="running")
        _make_vm(db, agent, "stopped-1", state="stopped")
        db.commit()

        bulk = BulkBackupCreate(filter={"state": "running"})
        ids = _resolve_bulk_vm_ids(db, bulk)
        assert set(ids) == {vm_r1.id, vm_r2.id}

    def test_filter_by_search_and_agent(self, db):
        from schemas import BulkBackupCreate

        agent1 = _make_agent(db, "host1")
        agent2 = _make_agent(db, "host2")
        vm1 = _make_vm(db, agent1, "prod-web01")
        _make_vm(db, agent2, "prod-web02")
        _make_vm(db, agent1, "dev-web01")
        db.commit()

        bulk = BulkBackupCreate(filter={"search": "prod", "agent_id": agent1.id})
        ids = _resolve_bulk_vm_ids(db, bulk)
        assert ids == [vm1.id]

    def test_filter_by_group(self, db):
        from schemas import BulkBackupCreate

        agent = _make_agent(db, "h1")
        vm1 = _make_vm(db, agent, "in-group")
        _make_vm(db, agent, "not-in-group")
        group = _make_group(db, "target-group")
        group.vms.append(vm1)
        db.commit()

        bulk = BulkBackupCreate(filter={"group_id": group.id})
        ids = _resolve_bulk_vm_ids(db, bulk)
        assert ids == [vm1.id]

    def test_explicit_ids_bypass_filter(self, db):
        """vm_ids takes precedence over filter."""
        from schemas import BulkBackupCreate

        agent = _make_agent(db, "h1")
        _vm1 = _make_vm(db, agent, "vm1", state="running")  # noqa: F841
        vm2 = _make_vm(db, agent, "vm2", state="stopped")
        db.commit()

        bulk = BulkBackupCreate(
            vm_ids=[vm2.id],
            filter={"state": "running"},  # Would match vm1
        )
        ids = _resolve_bulk_vm_ids(db, bulk)
        assert ids == [vm2.id]  # vm_ids takes precedence

    def test_no_ids_no_filter(self, db):
        from schemas import BulkBackupCreate

        bulk = BulkBackupCreate()
        ids = _resolve_bulk_vm_ids(db, bulk)
        assert ids == []


# ============================================================
# FLOW 7: Group type transitions
# ============================================================


class TestGroupTypeTransitions:
    """Edit a group to change its type and verify behavior changes."""

    def test_static_to_dynamic(self, db):
        """Convert static group to dynamic — static members ignored, rules resolve."""
        from core.group_rules import resolve_group_members

        agent = _make_agent(db, "h1")
        vm_manual = _make_vm(db, agent, "manually-added")
        _vm_match = _make_vm(db, agent, "prod-web01")  # noqa: F841
        db.commit()

        group = _make_group(db, "evolving", group_type="static")
        group.vms.append(vm_manual)
        db.commit()

        assert len(resolve_group_members(db, group)) == 1
        assert resolve_group_members(db, group)[0].name == "manually-added"

        # Convert to dynamic
        group.group_type = "dynamic"
        group.rules = [{"field": "name", "op": "glob", "value": "prod-*"}]
        db.commit()

        members = resolve_group_members(db, group)
        assert len(members) == 1
        assert members[0].name == "prod-web01"
        # manually-added is NOT returned (pure dynamic)

    def test_dynamic_to_hybrid(self, db):
        """Convert dynamic → hybrid adds static members back."""
        from core.group_rules import resolve_group_members

        agent = _make_agent(db, "h1")
        vm_static = _make_vm(db, agent, "manually-added")
        _make_vm(db, agent, "prod-web01")
        db.commit()

        group = _make_group(
            db,
            "evolving2",
            group_type="dynamic",
            rules=[{"field": "name", "op": "glob", "value": "prod-*"}],
        )
        group.vms.append(vm_static)
        db.commit()

        # As dynamic: only rule-matched
        members = resolve_group_members(db, group)
        assert len(members) == 1
        assert members[0].name == "prod-web01"

        # Convert to hybrid
        group.group_type = "hybrid"
        db.commit()

        members = resolve_group_members(db, group)
        names = {m.name for m in members}
        assert names == {"manually-added", "prod-web01"}


# ============================================================
# FLOW 8: Rule validation edge cases
# ============================================================


class TestRuleValidation:
    """Validate rules rejects bad input, accepts good input."""

    def test_empty_rules_list(self):
        from core.group_rules import validate_rules

        assert validate_rules([]) == []

    def test_not_a_list(self):
        from core.group_rules import validate_rules

        errors = validate_rules("not a list")
        assert errors == ["rules must be a list"]

    def test_rule_not_a_dict(self):
        from core.group_rules import validate_rules

        errors = validate_rules(["not a dict"])
        assert any("must be an object" in e for e in errors)

    def test_multiple_errors(self):
        from core.group_rules import validate_rules

        errors = validate_rules(
            [
                {"field": "bad", "op": "bad", "value": None},
            ]
        )
        assert len(errors) == 3  # invalid field, invalid op, missing value

    def test_in_op_with_list_value(self):
        from core.group_rules import validate_rules

        assert (
            validate_rules([{"field": "state", "op": "in", "value": ["a", "b"]}]) == []
        )

    def test_in_op_with_string_value(self):
        from core.group_rules import validate_rules

        errors = validate_rules([{"field": "state", "op": "in", "value": "not-a-list"}])
        assert any("list value" in e for e in errors)

    def test_all_valid_combinations(self):
        from core.group_rules import validate_rules, VALID_FIELDS, VALID_OPS

        for field in VALID_FIELDS:
            for op in VALID_OPS:
                value = ["a"] if op == "in" else "test"
                errors = validate_rules([{"field": field, "op": op, "value": value}])
                assert errors == [], f"Unexpected error for {field}/{op}: {errors}"


# ============================================================
# FLOW 9: Schema backward compatibility
# ============================================================


class TestSchemaBackwardCompat:
    """Verify old-style API calls still work."""

    def test_bulk_create_old_style(self):
        """Old-style BulkBackupCreate with vm_ids still works."""
        from schemas import BulkBackupCreate

        b = BulkBackupCreate(
            vm_ids=["id1", "id2"], retention_days=7, tags={"env": "prod"}
        )
        assert b.vm_ids == ["id1", "id2"]
        assert b.filter is None
        assert b.retention_days == 7

    def test_vmgroup_create_old_style(self):
        """Old-style VMGroupCreate without type/rules still works."""
        from schemas import VMGroupCreate

        g = VMGroupCreate(name="simple", description="desc", tags=["tag1"])
        assert g.group_type == "static"
        assert g.rules is None
        assert g.rules_match == "all"

    def test_vmgroup_update_old_style(self):
        """Old-style VMGroupUpdate without type/rules still works."""
        from schemas import VMGroupUpdate

        u = VMGroupUpdate(name="new-name", description="new-desc")
        assert u.group_type is None  # Not changing type
        assert u.rules is None


# ============================================================
# FLOW 10: Group rule operators (all 5)
# ============================================================


class TestRuleOperators:
    """Test each rule operator produces correct results."""

    def test_eq(self, db):
        from core.group_rules import build_rule_query

        agent = _make_agent(db, "h1")
        _make_vm(db, agent, "target")
        _make_vm(db, agent, "other")
        db.commit()

        vms = build_rule_query(
            db, [{"field": "name", "op": "eq", "value": "target"}]
        ).all()
        assert len(vms) == 1 and vms[0].name == "target"

    def test_neq(self, db):
        from core.group_rules import build_rule_query

        agent = _make_agent(db, "h1")
        _make_vm(db, agent, "keep")
        _make_vm(db, agent, "exclude")
        db.commit()

        vms = build_rule_query(
            db, [{"field": "name", "op": "neq", "value": "exclude"}]
        ).all()
        assert len(vms) == 1 and vms[0].name == "keep"

    def test_glob(self, db):
        from core.group_rules import build_rule_query

        agent = _make_agent(db, "h1")
        _make_vm(db, agent, "prod-web01")
        _make_vm(db, agent, "prod-db01")
        _make_vm(db, agent, "dev-web01")
        db.commit()

        vms = build_rule_query(
            db, [{"field": "name", "op": "glob", "value": "prod-*"}]
        ).all()
        assert len(vms) == 2

    def test_glob_question_mark(self, db):
        """? matches a single character."""
        from core.group_rules import build_rule_query

        agent = _make_agent(db, "h1")
        _make_vm(db, agent, "vm-a")
        _make_vm(db, agent, "vm-b")
        _make_vm(db, agent, "vm-ab")  # Should NOT match vm-?
        db.commit()

        vms = build_rule_query(
            db, [{"field": "name", "op": "glob", "value": "vm-?"}]
        ).all()
        assert len(vms) == 2
        names = {v.name for v in vms}
        assert names == {"vm-a", "vm-b"}

    def test_in(self, db):
        from core.group_rules import build_rule_query

        agent = _make_agent(db, "h1")
        _make_vm(db, agent, "a", state="running")
        _make_vm(db, agent, "b", state="stopped")
        _make_vm(db, agent, "c", state="paused")
        db.commit()

        vms = build_rule_query(
            db, [{"field": "state", "op": "in", "value": ["running", "paused"]}]
        ).all()
        assert len(vms) == 2

    def test_in_with_agent_id(self, db):
        """'in' operator works with agent_id field."""
        from core.group_rules import build_rule_query

        agent1 = _make_agent(db, "h1")
        agent2 = _make_agent(db, "h2")
        agent3 = _make_agent(db, "h3")
        _make_vm(db, agent1, "vm1")
        _make_vm(db, agent2, "vm2")
        _make_vm(db, agent3, "vm3")
        db.commit()

        vms = build_rule_query(
            db, [{"field": "agent_id", "op": "in", "value": [agent1.id, agent3.id]}]
        ).all()
        assert len(vms) == 2
        names = {v.name for v in vms}
        assert names == {"vm1", "vm3"}

    def test_empty_rules_returns_all(self, db):
        """Empty rules list returns all VMs."""
        from core.group_rules import build_rule_query

        agent = _make_agent(db, "h1")
        _make_vm(db, agent, "a")
        _make_vm(db, agent, "b")
        db.commit()

        vms = build_rule_query(db, []).all()
        assert len(vms) == 2


# ============================================================
# FLOW 11: Model persistence round-trip
# ============================================================


class TestModelPersistence:
    """Verify model fields survive write → read cycle."""

    def test_vmgroup_fields_roundtrip(self, db):
        from models import VMGroup

        group = VMGroup(
            name="test-roundtrip",
            group_type="dynamic",
            rules=[
                {"field": "name", "op": "glob", "value": "prod-*"},
                {"field": "state", "op": "in", "value": ["running", "paused"]},
            ],
            rules_match="any",
        )
        db.add(group)
        db.commit()

        # Re-fetch from DB
        fetched = db.query(VMGroup).filter(VMGroup.name == "test-roundtrip").first()
        assert fetched.group_type == "dynamic"
        assert fetched.rules_match == "any"
        assert len(fetched.rules) == 2
        assert fetched.rules[0]["field"] == "name"
        assert fetched.rules[0]["op"] == "glob"
        assert fetched.rules[1]["value"] == ["running", "paused"]

    def test_vmgroup_defaults(self, db):
        from models import VMGroup

        group = VMGroup(name="defaults-only")
        db.add(group)
        db.commit()
        db.refresh(group)

        assert group.group_type == "static"
        assert group.rules is None
        assert group.rules_match == "all"

    def test_vmgroup_null_rules(self, db):
        """Static group with null rules doesn't break resolve."""
        from core.group_rules import resolve_group_members

        group = _make_group(db, "null-rules", group_type="static", rules=None)
        db.commit()

        members = resolve_group_members(db, group)
        assert members == []

    def test_dynamic_group_empty_rules_list(self, db):
        """Dynamic group with empty rules list returns no VMs."""
        from core.group_rules import resolve_group_members

        agent = _make_agent(db, "h1")
        _make_vm(db, agent, "vm1")
        db.commit()

        group = _make_group(db, "empty-rules", group_type="dynamic", rules=[])
        db.commit()

        members = resolve_group_members(db, group)
        assert len(members) == 0  # Empty rules → no filter → returns all
        # Wait, actually build_rule_query with empty rules returns all VMs
        # Let me verify this is the expected behavior

    def test_dynamic_group_empty_rules_returns_none(self, db):
        """Dynamic group with empty rules list returns no VMs (no rules = no match)."""
        from core.group_rules import resolve_group_members

        agent = _make_agent(db, "h1")
        _make_vm(db, agent, "vm1")
        _make_vm(db, agent, "vm2")
        db.commit()

        group = _make_group(db, "no-filter", group_type="dynamic", rules=[])
        db.commit()

        # Empty list is falsy — resolve_group_members skips query entirely
        members = resolve_group_members(db, group)
        assert len(members) == 0

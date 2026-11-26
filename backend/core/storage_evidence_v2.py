"""Closed unmounted evidence/2 contract; no installation or provider approval.

The immutable SQL migration snapshots this descriptor. Production validity and
trusted provider binding remain unapproved; this policy names local fixtures.
"""

from datetime import datetime, timezone
import re

DEPENDENCY_POLICY = "unmounted-custody/2"
VALIDITY_POLICY = "unmounted-fixture-86400s/1"
MAX_VALIDITY_SECONDS = 86400
STAMP = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$"
DIGEST = r"^[0-9a-f]{64}$"


def string(maximum=128, minimum=1, pattern=None):
    return dict(type="string", minimum=minimum, maximum=maximum, pattern=pattern)


def enum(*values):
    return dict(enum=list(values))


def obj(**properties):
    return dict(type="object", properties=properties)


def array(items, minimum, maximum):
    return dict(type="array", items=items, minimum=minimum, maximum=maximum)


SEMANTICS = {
    "mpu_create": obj(
        key_binding=enum("exact", "not_exact"),
        upload_id_attribution=enum("response", "not_attributable"),
    ),
    "upload_part": obj(
        upload_part_binding=enum("exact", "not_exact"),
        acknowledgment=enum("etag", "not_attributable"),
        same_number=enum("replaces", "refuses", "unestablished"),
    ),
    "complete_manifest": obj(
        selection=enum("explicit_etags", "not_exact"),
        stale_etag=enum("refuses", "ignored", "unestablished"),
        embedded_error=enum("parsed", "not_parsed"),
        result_identity=enum("exact_key", "not_exact"),
    ),
    "head_identity": obj(
        key_binding=enum("exact", "not_exact"),
        fields=enum("metadata_length", "insufficient"),
        missing=enum("not_found", "unestablished"),
    ),
    "list_parts": obj(
        pagination=enum("monotonic_marker", "not_exact"),
        unfinished=enum("omitted", "unestablished"),
        fields=enum("etag_size_checksum_optional", "insufficient"),
    ),
    "checksum": obj(
        algorithm=enum("sha256"),
        checksum_type=enum("composite", "full_object", "absent"),
        assurance=enum("enforced", "echoed", "absent"),
        mismatch=enum("refuses", "ignored", "unestablished"),
    ),
    "complete_preconditions": obj(
        header=enum("if-none-match-star"),
        collision=enum("refuses", "ignored", "unestablished"),
    ),
    "conditional_generation_create": obj(
        condition=enum("if-none-match-star"),
        collision=enum("refuses", "ignored", "unestablished"),
        identity=enum("etag", "version", "unestablished"),
    ),
    "conditional_tombstone_create": obj(
        condition=enum("if-none-match-star"),
        collision=enum("refuses", "ignored", "unestablished"),
        identity=enum("etag", "version", "unestablished"),
    ),
    "version_readback": obj(
        identifier=enum("available", "unavailable"),
        exact_read=enum("supported", "unsupported"),
        overwrite=enum("new_version", "replaces", "unestablished"),
        delete_marker=enum("supported", "unsupported", "unestablished"),
    ),
    "same_upload_post_complete": obj(
        **{
            ordering: obj(
                request=enum(
                    "rejected_no_such_upload",
                    "rejected_other",
                    "succeeds_without_selected_change",
                    "succeeds_with_selected_change",
                    "unestablished",
                ),
                selected_object=enum("unchanged", "changed", "unestablished"),
            )
            for ordering in (
                "complete_before_put",
                "put_before_complete",
                "overlap_same_number",
            )
        }
    ),
}
# Legal outcomes are independent of profile and permission. An ignored outcome
# cannot be upgraded to enforcement by an operation approval.
ENFORCED = {
    "mpu_create": obj(
        key_binding=enum("exact"), upload_id_attribution=enum("response")
    ),
    "upload_part": obj(
        upload_part_binding=enum("exact"),
        acknowledgment=enum("etag"),
        same_number=enum("replaces", "refuses"),
    ),
    "complete_manifest": obj(
        selection=enum("explicit_etags"),
        stale_etag=enum("refuses"),
        embedded_error=enum("parsed"),
        result_identity=enum("exact_key"),
    ),
    "head_identity": obj(
        key_binding=enum("exact"),
        fields=enum("metadata_length"),
        missing=enum("not_found"),
    ),
    "list_parts": obj(
        pagination=enum("monotonic_marker"),
        unfinished=enum("omitted"),
        fields=enum("etag_size_checksum_optional"),
    ),
    "checksum": obj(
        algorithm=enum("sha256"),
        checksum_type=enum("composite", "full_object"),
        assurance=enum("enforced"),
        mismatch=enum("refuses"),
    ),
    "complete_preconditions": obj(
        header=enum("if-none-match-star"), collision=enum("refuses")
    ),
    "conditional_generation_create": obj(
        condition=enum("if-none-match-star"),
        collision=enum("refuses"),
        identity=enum("etag", "version"),
    ),
    "conditional_tombstone_create": obj(
        condition=enum("if-none-match-star"),
        collision=enum("refuses"),
        identity=enum("etag", "version"),
    ),
    "version_readback": obj(
        identifier=enum("available"),
        exact_read=enum("supported"),
        overwrite=enum("new_version"),
        delete_marker=enum("supported"),
    ),
    "same_upload_post_complete": obj(
        **{
            ordering: obj(
                request=enum(
                    "rejected_no_such_upload",
                    "rejected_other",
                    "succeeds_without_selected_change",
                ),
                selected_object=enum("unchanged"),
            )
            for ordering in (
                "complete_before_put",
                "put_before_complete",
                "overlap_same_number",
            )
        }
    ),
}

# These five dimensions permit known negative combinations, not incomplete ones.
# A partially unobserved dimension uses unestablished/null, with its underlying
# measurement still retainable in evidence_cases but no asserted semantics.
KNOWN_OUTCOMES = {
    "mpu_create": SEMANTICS["mpu_create"],
    "upload_part": obj(
        upload_part_binding=enum("exact", "not_exact"),
        acknowledgment=enum("etag", "not_attributable"),
        same_number=enum("replaces", "refuses"),
    ),
    "complete_manifest": obj(
        selection=enum("explicit_etags", "not_exact"),
        stale_etag=enum("refuses", "ignored"),
        embedded_error=enum("parsed", "not_parsed"),
        result_identity=enum("exact_key", "not_exact"),
    ),
    "head_identity": obj(
        key_binding=enum("exact", "not_exact"),
        fields=enum("metadata_length", "insufficient"),
        missing=enum("not_found"),
    ),
    "list_parts": obj(
        pagination=enum("monotonic_marker", "not_exact"),
        unfinished=enum("omitted"),
        fields=enum("etag_size_checksum_optional", "insufficient"),
    ),
}
IGNORED = {
    name: {"all": [spec, {"not": ENFORCED[name]}]}
    for name, spec in KNOWN_OUTCOMES.items()
}
IGNORED.update(
    {
        "checksum": {
            "any": [
                obj(
                    algorithm=enum("sha256"),
                    checksum_type=enum("composite", "full_object"),
                    assurance=enum("echoed"),
                    mismatch=enum("ignored"),
                ),
                obj(
                    algorithm=enum("sha256"),
                    checksum_type=enum("absent"),
                    assurance=enum("absent"),
                    mismatch=enum("ignored"),
                ),
            ]
        },
        "complete_preconditions": obj(
            header=enum("if-none-match-star"), collision=enum("ignored")
        ),
        "conditional_generation_create": obj(
            condition=enum("if-none-match-star"),
            collision=enum("ignored"),
            identity=enum("etag", "version"),
        ),
        "conditional_tombstone_create": obj(
            condition=enum("if-none-match-star"),
            collision=enum("ignored"),
            identity=enum("etag", "version"),
        ),
        "version_readback": obj(
            identifier=enum("unavailable"),
            exact_read=enum("unsupported"),
            overwrite=enum("replaces"),
            delete_marker=enum("unsupported"),
        ),
        "same_upload_post_complete": {
            "all": [
                obj(
                    **{
                        ordering: {
                            "any": [
                                ENFORCED["same_upload_post_complete"]["properties"][
                                    ordering
                                ],
                                obj(
                                    request=enum("succeeds_with_selected_change"),
                                    selected_object=enum("changed"),
                                ),
                            ]
                        }
                        for ordering in (
                            "complete_before_put",
                            "put_before_complete",
                            "overlap_same_number",
                        )
                    }
                ),
                {"not": ENFORCED["same_upload_post_complete"]},
            ]
        },
    }
)


def consistent(name, behavior):
    status = behavior["status"]
    if status in ("unsupported", "unestablished"):
        return behavior["semantics"] is None
    rules = ENFORCED if status == "enforced" else IGNORED
    return shape(behavior["semantics"], rules[name])


CASE_ID = string(128, pattern=r"^[A-Za-z0-9._:/-]+$")
BEHAVIORS = {
    name: obj(
        status=enum("enforced", "ignored", "unsupported", "unestablished"),
        semantics=dict(any=[schema, enum(None)]),
        case_ids=array(CASE_ID, 0, 128),
    )
    for name, schema in SEMANTICS.items()
}
IDENTITY = dict(
    any=[
        obj(
            kind=enum("versioned"),
            product=string(),
            product_version=string(pattern=r"^[^*?]+$"),
            deployment_identity=string(256),
            configuration_sha256=string(64, 64, DIGEST),
        ),
        obj(
            kind=enum("managed_observation"),
            service=string(),
            observation_scope_id=string(256),
            configuration_sha256=string(64, 64, DIGEST),
            build_version_exposed=enum(False),
        ),
    ]
)
FACTS = obj(
    schema=enum(2),
    target=obj(
        endpoint=string(1024, pattern=r"^https://[^/?#@]+$"),
        bucket=string(1024),
        region=string(1024),
        configuration_prefix=string(1024, 0),
    ),
    profile=enum(
        "checksum-enforced/1", "consumer-verified/1", "db-rooted-consumer-verified/1"
    ),
    adapter=enum("vnbui-callback-provider/1"),
    wire=enum("vnbui-storage-transaction/1"),
    provider_identity=IDENTITY,
    observation=obj(
        started_at_utc=string(27, 27, STAMP),
        completed_at_utc=string(27, 27, STAMP),
        test_contract_revision=string(),
    ),
    validity=obj(
        not_before_utc=string(27, 27, STAMP),
        not_after_utc=string(27, 27, STAMP),
        invalidation_policy_revision=enum(VALIDITY_POLICY),
    ),
    behaviors=obj(**BEHAVIORS),
    evidence_cases=array(
        obj(case_id=CASE_ID, artifact_sha256=string(64, 64, DIGEST)), 1, 128
    ),
)
APPROVAL = obj(
    schema=enum(2),
    evidence_schema=enum(2),
    evidence_revision=dict(type="integer", minimum=1, maximum=2**63 - 1),
    evidence_sha256=string(64, 64, DIGEST),
    dependency_policy_revision=enum(DEPENDENCY_POLICY),
    validity_policy_revision=enum(VALIDITY_POLICY),
    reviewer=string(2048),
    reference=string(2048),
    approved_utc=string(27, 27, STAMP),
)
REQUIRED = {
    "create": {
        "mpu_create": {"key_binding": "exact", "upload_id_attribution": "response"}
    },
    "part_sign": {
        "upload_part": {"upload_part_binding": "exact", "acknowledgment": "etag"}
    },
    "complete": {
        "complete_manifest": {
            "selection": "explicit_etags",
            "stale_etag": "refuses",
            "embedded_error": "parsed",
            "result_identity": "exact_key",
        },
        "upload_part": {"upload_part_binding": "exact", "acknowledgment": "etag"},
    },
    "head": {
        "head_identity": {
            "key_binding": "exact",
            "fields": "metadata_length",
            "missing": "not_found",
        }
    },
    "list_parts": {
        "list_parts": {
            "pagination": "monotonic_marker",
            "unfinished": "omitted",
            "fields": "etag_size_checksum_optional",
        }
    },
}


def shape(value, spec):
    if "all" in spec:
        return all(shape(value, child) for child in spec["all"])
    if "not" in spec:
        return not shape(value, spec["not"])
    if "any" in spec:
        return any(shape(value, s) for s in spec["any"])
    if "enum" in spec:
        return any(type(value) is type(v) and value == v for v in spec["enum"])
    kind = spec["type"]
    if kind == "object":
        return (
            type(value) is dict
            and set(value) == set(spec["properties"])
            and all(shape(value[k], s) for k, s in spec["properties"].items())
        )
    if kind == "array":
        return (
            type(value) is list
            and spec["minimum"] <= len(value) <= spec["maximum"]
            and all(shape(v, spec["items"]) for v in value)
        )
    if kind == "integer":
        return type(value) is int and spec["minimum"] <= value <= spec["maximum"]
    return (
        type(value) is str
        and spec["minimum"] <= len(value.encode()) <= spec["maximum"]
        and (
            spec["pattern"] is None or re.fullmatch(spec["pattern"], value) is not None
        )
    )


def stamp(value):
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=timezone.utc
    )
    if f"{parsed.year:04d}" + parsed.strftime("-%m-%dT%H:%M:%S.%fZ") != value:
        raise ValueError("Noncanonical UTC time")
    return parsed


def validate_facts(facts):
    if not shape(facts, FACTS):
        raise ValueError("Evidence schema 2 shape invalid")
    times = [
        stamp(facts[a][b])
        for a, b in (
            ("observation", "started_at_utc"),
            ("observation", "completed_at_utc"),
            ("validity", "not_before_utc"),
            ("validity", "not_after_utc"),
        )
    ]
    if (
        not times[0] <= times[1] <= times[2] < times[3]
        or (times[3] - times[2]).total_seconds() > MAX_VALIDITY_SECONDS
    ):
        raise ValueError("Evidence validity interval invalid")
    cases = [c["case_id"] for c in facts["evidence_cases"]]
    if len(set(cases)) != len(cases):
        raise ValueError("Duplicate evidence case")
    for name, b in facts["behaviors"].items():
        if not consistent(name, b):
            raise ValueError("Capability status and outcomes inconsistent")
        if len(set(b["case_ids"])) != len(b["case_ids"]) or not set(
            b["case_ids"]
        ) <= set(cases):
            raise ValueError("Evidence case reference invalid")
        if b["status"] == "unestablished":
            if b["semantics"] is not None or b["case_ids"]:
                raise ValueError("Unestablished evidence cannot assert semantics")
        elif not b["case_ids"] or (
            b["status"] != "unsupported" and b["semantics"] is None
        ):
            raise ValueError("Asserted evidence lacks case or semantics")
    return facts


def qualified(facts, operation):
    if any(not consistent(name, b) for name, b in facts["behaviors"].items()):
        return False
    if operation not in REQUIRED:
        return False
    for name, expected in REQUIRED[operation].items():
        b = facts["behaviors"][name]
        if (
            b["status"] != "enforced"
            or not isinstance(b["semantics"], dict)
            or any(b["semantics"].get(k) != v for k, v in expected.items())
        ):
            return False
    if operation in ("complete", "head"):
        names = (
            ("checksum", "complete_preconditions")
            if operation == "complete"
            else ("checksum", "version_readback")
        )
        if any(facts["behaviors"][n]["status"] == "unestablished" for n in names):
            return False
        c = facts["behaviors"]["checksum"]
        if facts["profile"] == "checksum-enforced/1" and (
            c["status"] != "enforced"
            or c["semantics"]
            != {
                "algorithm": "sha256",
                "checksum_type": "composite",
                "assurance": "enforced",
                "mismatch": "refuses",
            }
        ):
            return False
    return True


def in_window(facts, now):
    return (
        stamp(facts["validity"]["not_before_utc"])
        <= now
        < stamp(facts["validity"]["not_after_utc"])
    )

"""Reviewed HTTP errors: static source map plus actual route dependency graph.

This module describes wire failures, without registering exception handlers.
"""

from copy import deepcopy

# Static authoring snapshot; runtime never opens or inspects Python source files.
SOURCE_ERRORS = {
    "GET /api/v1/vms/{vm_id}/backup-guidance": {
        "handler": "get_vm_backup_guidance",
        "source": "backend/routers/agents.py",
        "errors": [
            {
                "status": "404",
                "schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["detail"],
                    "properties": {"detail": {"type": "string"}},
                },
                "sources": ["backend/routers/agents.py:get_vm_backup_guidance"],
            }
        ],
    },
    "POST /api/v1/backups/{backup_id}/close-unreserved": {
        "handler": "close_unreserved_attempt",
        "source": "backend/routers/backups.py",
        "errors": [
            {
                "status": status,
                "schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["detail"],
                    "properties": {
                        "detail": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["code"],
                            "properties": {"code": {"type": "string"}},
                        }
                    },
                },
                "sources": ["backend/routers/backups.py:close_unreserved_attempt"],
            }
            for status in ("404", "409")
        ],
    },
    "DELETE /api/v1/agents/{agent_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/agents.py:691"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/agents.py:698"],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/agents.py:709"],
                "status": "409",
            },
        ],
        "handler": "delete_agent",
        "source": "backend/routers/agents.py",
    },
    "DELETE /api/v1/agents/{agent_id}/key-rotations/{rotation_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "agent_rotation_authority_revoked",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/core/agent_key_rotation.py:89"],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"const": "agent_not_found", "type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/core/agent_key_rotation.py:270"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "agent_rotation_not_found",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/core/agent_key_rotation.py:281"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "agent_rotation_not_pending",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/core/agent_key_rotation.py:446"],
                "status": "409",
            },
        ],
        "handler": "cancel_agent_key_rotation",
        "source": "backend/routers/agents.py",
    },
    "DELETE /api/v1/backups/queue/{queue_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/queue.py:204"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/queue.py:209"],
                "status": "400",
            },
        ],
        "handler": "cancel_queued_backup",
        "source": "backend/routers/queue.py",
    },
    "DELETE /api/v1/backups/{backup_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/backups.py:437"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/backups.py:441",
                    "backend/routers/backups.py:446",
                    "backend/routers/backups.py:462",
                ],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/backups.py:464"],
                "status": "502",
            },
        ],
        "handler": "delete_backup",
        "source": "backend/routers/backups.py",
    },
    "DELETE /api/v1/branding/{org_id}/logo": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["commercial/backend/modules/white_label.py:187"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["core/licensing.py:286 require_feature"],
                "status": "403",
            },
        ],
        "handler": "delete_logo",
        "source": "commercial/backend/modules/white_label.py",
    },
    "DELETE /api/v1/demo/sessions/current": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:55"],
                "status": "404",
            }
        ],
        "handler": "destroy_session",
        "source": "backend/routers/demo.py",
    },
    "DELETE /api/v1/groups/{group_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/groups.py:245"],
                "status": "404",
            }
        ],
        "handler": "delete_group",
        "source": "backend/routers/groups.py",
    },
    "DELETE /api/v1/groups/{group_id}/vms/{vm_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/groups.py:320",
                    "backend/routers/groups.py:330",
                    "backend/routers/groups.py:333",
                ],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/groups.py:323"],
                "status": "400",
            },
        ],
        "handler": "remove_vm_from_group",
        "source": "backend/routers/groups.py",
    },
    "DELETE /api/v1/licensing/acknowledgement": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "core/license_registration.py:38 "
                    "RegistrationError default "
                    "status; "
                    "routers/licensing.py:62 "
                    "_invoke"
                ],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "installation_authority_required",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["core/license_registration.py:334 _authorize"],
                "status": "403",
            },
        ],
        "handler": "clear_acknowledgement",
        "source": "backend/routers/licensing.py",
    },
    "DELETE /api/v1/notifications/rules/{rule_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/notifications.py:156 -> backend/deps.py:check_role"
                ],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/notifications.py:160"],
                "status": "404",
            },
        ],
        "handler": "delete_notification_rule",
        "source": "backend/routers/notifications.py",
    },
    "DELETE /api/v1/notifications/{notification_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/notifications.py:429"],
                "status": "404",
            }
        ],
        "handler": "delete_notification",
        "source": "backend/routers/notifications.py",
    },
    "DELETE /api/v1/orchestrator-keys/{key_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/api_keys.py:179"],
                "status": "404",
            }
        ],
        "handler": "delete_orchestrator_key",
        "source": "backend/routers/api_keys.py",
    },
    "DELETE /api/v1/organizations/{org_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["commercial/backend/modules/multi_tenant.py:328"],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["commercial/backend/modules/multi_tenant.py:343"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "organization_retains_operator_requests",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["commercial/backend/modules/multi_tenant.py:350"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["core/licensing.py:286 require_feature"],
                "status": "403",
            },
        ],
        "handler": "delete_organization",
        "source": "commercial/backend/modules/multi_tenant.py",
    },
    "DELETE /api/v1/registration-keys/{key_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/api_keys.py:362"],
                "status": "404",
            }
        ],
        "handler": "delete_registration_key",
        "source": "backend/routers/api_keys.py",
    },
    "DELETE /api/v1/reports/{report_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/reports.py:259"],
                "status": "404",
            }
        ],
        "handler": "delete_report",
        "source": "backend/routers/reports.py",
    },
    "DELETE /api/v1/saved-searches/{search_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/search.py:167"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/search.py:170"],
                "status": "403",
            },
        ],
        "handler": "delete_saved_search",
        "source": "backend/routers/search.py",
    },
    "DELETE /api/v1/schedules/{schedule_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/schedules.py:541"],
                "status": "404",
            }
        ],
        "handler": "delete_schedule",
        "source": "backend/routers/schedules.py",
    },
    "DELETE /api/v1/schedules/{schedule_id}/grant": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/schedules.py:153"],
                "status": "409",
            }
        ],
        "handler": "revoke_schedule_grant",
        "source": "backend/routers/schedules.py",
    },
    "DELETE /api/v1/users/{user_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/users.py:38",
                    "backend/routers/users.py:41",
                ],
                "status": "401",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/users.py:43",
                    "backend/routers/users.py:386",
                ],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/users.py:51"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/users.py:388"],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/users.py:62",
                    "backend/routers/users.py:411",
                ],
                "status": "409",
            },
        ],
        "handler": "delete_user",
        "source": "backend/routers/users.py",
    },
    "GET /api/v1/activity": {
        "errors": [],
        "handler": "get_activity",
        "source": "backend/routers/activity.py",
    },
    "GET /api/v1/activity/unified": {
        "errors": [],
        "handler": "get_unified_activity_deprecated",
        "source": "backend/routers/activity.py",
    },
    "GET /api/v1/agents": {
        "errors": [],
        "handler": "list_agents",
        "source": "backend/routers/agents.py",
    },
    "GET /api/v1/agents/{agent_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/agents.py:511"],
                "status": "404",
            }
        ],
        "handler": "get_agent_details",
        "source": "backend/routers/agents.py",
    },
    "GET /api/v1/agents/{agent_id}/key-rotations": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"const": "agent_not_found", "type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/core/agent_key_rotation.py:419"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "agent_rotation_not_found",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/core/agent_key_rotation.py:426"],
                "status": "404",
            },
        ],
        "handler": "list_agent_key_rotations",
        "source": "backend/routers/agents.py",
    },
    "GET /api/v1/agents/{agent_id}/key-rotations/{rotation_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"const": "agent_not_found", "type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/core/agent_key_rotation.py:419"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "agent_rotation_not_found",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/core/agent_key_rotation.py:426"],
                "status": "404",
            },
        ],
        "handler": "get_agent_key_rotation",
        "source": "backend/routers/agents.py",
    },
    "GET /api/v1/agents/{agent_id}/pending-jobs": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:1065"],
                "status": "403",
            }
        ],
        "handler": "get_agent_pending_jobs",
        "source": "backend/routers/health.py",
    },
    "GET /api/v1/auth/me": {
        "errors": [],
        "handler": "get_current_user_info",
        "source": "backend/routers/auth.py",
    },
    "GET /api/v1/auth/oidc/callback": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/auth.py:250",
                    "backend/routers/auth.py:278",
                    "backend/routers/auth.py:517",
                    "backend/routers/auth.py:523",
                    "backend/routers/auth.py:529",
                    "backend/routers/auth.py:535",
                ],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/auth.py:271",
                    "backend/routers/auth.py:262",
                ],
                "status": "503",
            },
        ],
        "handler": "oidc_callback",
        "source": "backend/routers/auth.py",
    },
    "GET /api/v1/auth/oidc/login": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/auth.py:250",
                    "backend/routers/auth.py:278",
                    "backend/routers/auth.py:429",
                ],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/auth.py:271",
                    "backend/routers/auth.py:262",
                ],
                "status": "503",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/auth.py:462"],
                "status": "500",
            },
        ],
        "handler": "oidc_login",
        "source": "backend/routers/auth.py",
    },
    "GET /api/v1/auth/oidc/status": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/auth.py:250",
                    "backend/routers/auth.py:278",
                ],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/auth.py:271",
                    "backend/routers/auth.py:262",
                ],
                "status": "503",
            },
        ],
        "handler": "get_oidc_status",
        "source": "backend/routers/auth.py",
    },
    "GET /api/v1/backups": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/backups.py:329",
                    "backend/routers/backups.py:307",
                    "backend/routers/backups.py:319",
                ],
                "status": "400",
            }
        ],
        "handler": "list_backups",
        "source": "backend/routers/backups.py",
    },
    "GET /api/v1/backups/queue": {
        "errors": [],
        "handler": "get_backup_queue",
        "source": "backend/routers/queue.py",
    },
    "GET /api/v1/backups/queue/{queue_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/queue.py:176"],
                "status": "404",
            }
        ],
        "handler": "get_backup_queue_item",
        "source": "backend/routers/queue.py",
    },
    "GET /api/v1/backups/{backup_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/backups.py:224"],
                "status": "404",
            }
        ],
        "handler": "get_backup",
        "source": "backend/routers/backups.py",
    },
    "GET /api/v1/backups/{backup_id}/restore-bundle": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/backups.py:208"],
                "status": "409",
            }
        ],
        "handler": "get_restore_bundle",
        "source": "backend/routers/backups.py",
    },
    "GET /api/v1/backups/{backup_id}/verifications": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/verification.py:188"],
                "status": "404",
            }
        ],
        "handler": "list_backup_verifications",
        "source": "backend/routers/verification.py",
    },
    "GET /api/v1/billing/pricing": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["core/licensing.py:286 require_feature"],
                "status": "403",
            }
        ],
        "handler": "get_pricing",
        "source": "commercial/backend/modules/billing.py",
    },
    "GET /api/v1/billing/usage": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["commercial/backend/modules/billing.py:88"],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["core/licensing.py:286 require_feature"],
                "status": "403",
            },
        ],
        "handler": "get_usage_all_orgs",
        "source": "commercial/backend/modules/billing.py",
    },
    "GET /api/v1/billing/usage/{org_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "commercial/backend/modules/billing.py:135",
                    "core/licensing.py:286 require_feature",
                ],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["commercial/backend/modules/billing.py:149"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["commercial/backend/modules/billing.py:142"],
                "status": "400",
            },
        ],
        "handler": "get_usage_for_org",
        "source": "commercial/backend/modules/billing.py",
    },
    "GET /api/v1/bootstrap": {
        "errors": [],
        "handler": "get_bootstrap",
        "source": "backend/routers/public.py",
    },
    "GET /api/v1/branding/{org_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["commercial/backend/modules/white_label.py:78"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["core/licensing.py:286 require_feature"],
                "status": "403",
            },
        ],
        "handler": "get_branding",
        "source": "commercial/backend/modules/white_label.py",
    },
    "GET /api/v1/compatibility": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/public.py:158"],
                "status": "503",
            }
        ],
        "handler": "get_compatibility",
        "source": "backend/routers/public.py",
    },
    "GET /api/v1/config/realtime": {
        "errors": [],
        "handler": "get_realtime_config",
        "source": "backend/routers/realtime.py",
    },
    "GET /api/v1/dashboard/backup-trends": {
        "errors": [],
        "handler": "get_backup_trends",
        "source": "backend/routers/dashboard.py",
    },
    "GET /api/v1/dashboard/storage-usage": {
        "errors": [],
        "handler": "get_storage_usage",
        "source": "backend/routers/dashboard.py",
    },
    "GET /api/v1/dashboard/summary": {
        "errors": [],
        "handler": "get_dashboard_summary",
        "source": "backend/routers/dashboard.py",
    },
    "GET /api/v1/demo/sessions/current": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:55"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:77"],
                "status": "401",
            },
        ],
        "handler": "current_session",
        "source": "backend/routers/demo.py",
    },
    "GET /api/v1/demo/state": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:55"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:77"],
                "status": "401",
            },
        ],
        "handler": "get_state",
        "source": "backend/routers/demo.py",
    },
    "GET /api/v1/encryption/keys": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/encryption.py:130 -> backend/deps.py:check_role"
                ],
                "status": "403",
            }
        ],
        "handler": "list_keys",
        "source": "backend/routers/encryption.py",
    },
    "GET /api/v1/encryption/keys/{key_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/encryption.py:148 -> backend/deps.py:check_role"
                ],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/encryption.py:156"],
                "status": "404",
            },
        ],
        "handler": "get_key",
        "source": "backend/routers/encryption.py",
    },
    "GET /api/v1/encryption/provider": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/encryption.py:334 -> backend/deps.py:check_role"
                ],
                "status": "403",
            }
        ],
        "handler": "get_provider_info",
        "source": "backend/routers/encryption.py",
    },
    "GET /api/v1/features": {
        "errors": [],
        "handler": "get_features",
        "source": "backend/routers/public.py",
    },
    "GET /api/v1/groups": {
        "errors": [],
        "handler": "list_groups",
        "source": "backend/routers/groups.py",
    },
    "GET /api/v1/groups/{group_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/groups.py:136"],
                "status": "404",
            }
        ],
        "handler": "get_group",
        "source": "backend/routers/groups.py",
    },
    "GET /api/v1/health": {
        "errors": [],
        "handler": "get_health",
        "source": "backend/routers/health.py",
    },
    "GET /api/v1/health/agents": {
        "errors": [],
        "handler": "get_agent_health_deprecated",
        "source": "backend/routers/health.py",
    },
    "GET /api/v1/health/backups": {
        "errors": [],
        "handler": "get_backup_health_deprecated",
        "source": "backend/routers/health.py",
    },
    "GET /api/v1/health/detailed": {
        "errors": [],
        "handler": "get_detailed_health_deprecated",
        "source": "backend/routers/health.py",
    },
    "GET /api/v1/health/diagnostics": {
        "errors": [],
        "handler": "support_diagnostics",
        "source": "backend/routers/health.py",
    },
    "GET /api/v1/health/system": {
        "errors": [],
        "handler": "get_system_health_deprecated",
        "source": "backend/routers/health.py",
    },
    "GET /api/v1/license/info": {
        "errors": [],
        "handler": "get_license_info",
        "source": "backend/routers/public.py",
    },
    "GET /api/v1/licensing": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "core/license_registration.py:38 "
                    "RegistrationError default status; "
                    "routers/licensing.py:62 _invoke"
                ],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "installation_authority_required",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["core/license_registration.py:334 _authorize"],
                "status": "403",
            },
        ],
        "handler": "licensing_details",
        "source": "backend/routers/licensing.py",
    },
    "GET /api/v1/licensing/status": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "core/license_registration.py:38 "
                    "RegistrationError default status; "
                    "routers/licensing.py:62 _invoke"
                ],
                "status": "422",
            }
        ],
        "handler": "licensing_status",
        "source": "backend/routers/licensing.py",
    },
    "GET /api/v1/notifications": {
        "errors": [],
        "handler": "list_notifications",
        "source": "backend/routers/notifications.py",
    },
    "GET /api/v1/notifications/logs": {
        "errors": [],
        "handler": "list_notification_logs",
        "source": "backend/routers/notifications.py",
    },
    "GET /api/v1/notifications/rules": {
        "errors": [],
        "handler": "list_notification_rules",
        "source": "backend/routers/notifications.py",
    },
    "GET /api/v1/notifications/rules/{rule_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/notifications.py:95"],
                "status": "404",
            }
        ],
        "handler": "get_notification_rule",
        "source": "backend/routers/notifications.py",
    },
    "GET /api/v1/notifications/settings": {
        "errors": [],
        "handler": "get_notification_settings",
        "source": "backend/routers/notifications.py",
    },
    "GET /api/v1/operator/capabilities": {
        "errors": [],
        "handler": "operator_capabilities",
        "source": "backend/routers/operator.py",
    },
    "GET /api/v1/operator/requests/{request_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "request_not_found",
                                    "type": "string",
                                },
                                "outcome": {"const": "unknown", "type": "string"},
                            },
                            "required": ["code", "outcome"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/operator.py:78",
                    "backend/routers/operator.py:64",
                ],
                "status": "404",
            }
        ],
        "handler": "operator_request_outcome",
        "source": "backend/routers/operator.py",
    },
    "GET /api/v1/orchestrator-keys": {
        "errors": [],
        "handler": "list_orchestrator_keys",
        "source": "backend/routers/api_keys.py",
    },
    "GET /api/v1/organizations": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["core/licensing.py:286 require_feature"],
                "status": "403",
            }
        ],
        "handler": "list_organizations",
        "source": "commercial/backend/modules/multi_tenant.py",
    },
    "GET /api/v1/organizations/{org_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "commercial/backend/modules/multi_tenant.py:202",
                    "core/licensing.py:286 require_feature",
                ],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["commercial/backend/modules/multi_tenant.py:211"],
                "status": "404",
            },
        ],
        "handler": "get_organization",
        "source": "commercial/backend/modules/multi_tenant.py",
    },
    "GET /api/v1/pki/backend-cert": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/pki.py:95"],
                "status": "404",
            }
        ],
        "handler": "get_backend_cert",
        "source": "backend/routers/pki.py",
    },
    "GET /api/v1/pki/ca": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/pki.py:70"],
                "status": "404",
            }
        ],
        "handler": "get_ca_cert",
        "source": "backend/routers/pki.py",
    },
    "GET /api/v1/pki/certificates": {
        "errors": [],
        "handler": "list_certificates",
        "source": "backend/routers/pki.py",
    },
    "GET /api/v1/pki/status": {
        "errors": [],
        "handler": "get_pki_status",
        "source": "backend/routers/pki.py",
    },
    "GET /api/v1/registration-keys": {
        "errors": [],
        "handler": "list_registration_keys",
        "source": "backend/routers/api_keys.py",
    },
    "GET /api/v1/report-executions/{execution_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/reports.py:444"],
                "status": "404",
            }
        ],
        "handler": "get_report_execution",
        "source": "backend/routers/reports.py",
    },
    "GET /api/v1/report-executions/{execution_id}/download": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/reports.py:479",
                    "backend/routers/reports.py:512",
                ],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/reports.py:482"],
                "status": "400",
            },
        ],
        "handler": "download_report",
        "source": "backend/routers/reports.py",
    },
    "GET /api/v1/reports": {
        "errors": [],
        "handler": "list_reports",
        "source": "backend/routers/reports.py",
    },
    "GET /api/v1/reports/{report_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/reports.py:151"],
                "status": "404",
            }
        ],
        "handler": "get_report",
        "source": "backend/routers/reports.py",
    },
    "GET /api/v1/reports/{report_id}/executions": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/reports.py:390"],
                "status": "404",
            }
        ],
        "handler": "list_report_executions",
        "source": "backend/routers/reports.py",
    },
    "GET /api/v1/restores": {
        "errors": [],
        "handler": "get_restores",
        "source": "backend/routers/restores.py",
    },
    "GET /api/v1/restores/{restore_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/restores.py:373"],
                "status": "404",
            }
        ],
        "handler": "get_restore",
        "source": "backend/routers/restores.py",
    },
    "GET /api/v1/s3/discover": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/s3_import.py:286 -> backend/deps.py:check_role"
                ],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/s3_import.py:81"],
                "status": "404",
            },
        ],
        "handler": "discover_chains",
        "source": "backend/routers/s3_import.py",
    },
    "GET /api/v1/saved-searches": {
        "errors": [],
        "handler": "list_saved_searches",
        "source": "backend/routers/search.py",
    },
    "GET /api/v1/saved-searches/{search_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/search.py:142"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/search.py:145"],
                "status": "403",
            },
        ],
        "handler": "get_saved_search",
        "source": "backend/routers/search.py",
    },
    "GET /api/v1/schedules": {
        "errors": [],
        "handler": "list_schedules",
        "source": "backend/routers/schedules.py",
    },
    "GET /api/v1/schedules/{schedule_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/schedules.py:341"],
                "status": "404",
            }
        ],
        "handler": "get_schedule",
        "source": "backend/routers/schedules.py",
    },
    "GET /api/v1/schedules/{schedule_id}/grant": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/schedules.py:77"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/schedules.py:81"],
                "status": "409",
            },
        ],
        "handler": "get_schedule_grant",
        "source": "backend/routers/schedules.py",
    },
    "GET /api/v1/settings": {
        "errors": [],
        "handler": "get_settings",
        "source": "backend/routers/config.py",
    },
    "GET /api/v1/settings/v3": {
        "errors": [],
        "handler": "get_settings_v3",
        "source": "backend/routers/config.py",
    },
    "GET /api/v1/stats": {
        "errors": [],
        "handler": "get_stats",
        "source": "backend/routers/stats.py",
    },
    "GET /api/v1/updates": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "realtime_contract_unsupported",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/realtime.py:267"],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "realtime_cursor_contract_required",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/realtime.py:299"],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "realtime_parameters_conflict",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/realtime.py:276"],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "realtime_cursor_invalid",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/realtime.py:291"],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "realtime_timestamp_invalid",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/realtime.py:314"],
                "status": "400",
            },
        ],
        "handler": "get_updates",
        "source": "backend/routers/realtime.py",
    },
    "GET /api/v1/users": {
        "errors": [],
        "handler": "list_users",
        "source": "backend/routers/users.py",
    },
    "GET /api/v1/users/{user_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/users.py:198"],
                "status": "404",
            }
        ],
        "handler": "get_user",
        "source": "backend/routers/users.py",
    },
    "GET /api/v1/verifications": {
        "errors": [],
        "handler": "list_all_verifications",
        "source": "backend/routers/verification.py",
    },
    "GET /api/v1/verifications/{verification_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/verification.py:268"],
                "status": "404",
            }
        ],
        "handler": "get_verification",
        "source": "backend/routers/verification.py",
    },
    "GET /api/v1/version": {
        "errors": [],
        "handler": "get_version",
        "source": "backend/routers/public.py",
    },
    "GET /api/v1/vms": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/agents.py:347",
                    "backend/routers/agents.py:352",
                ],
                "status": "400",
            }
        ],
        "handler": "list_vms",
        "source": "backend/routers/agents.py",
    },
    "GET /api/v1/vms/{vm_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/agents.py:474"],
                "status": "404",
            }
        ],
        "handler": "get_vm",
        "source": "backend/routers/agents.py",
    },
    "GET /health": {
        "errors": [],
        "handler": "health_check",
        "source": "backend/routers/public.py",
    },
    "GET /metrics": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/public.py:82"],
                "status": "404",
            }
        ],
        "handler": "prometheus_metrics",
        "source": "backend/routers/public.py",
    },
    "GET /ready": {
        "errors": [],
        "handler": "readiness_check",
        "source": "backend/routers/public.py",
    },
    "PATCH /api/v1/agents/{agent_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/agents.py:568"],
                "status": "404",
            }
        ],
        "handler": "update_agent",
        "source": "backend/routers/agents.py",
    },
    "PATCH /api/v1/agents/{agent_id}/settings": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/agents.py:615"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/agents.py:635"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "core/vm_inventory.py:49 "
                    "sync_inventory; "
                    "core/agent_scope.py:21 "
                    "namespace_list/validate_settings"
                ],
                "status": "422",
            },
        ],
        "handler": "update_agent_settings",
        "source": "backend/routers/agents.py",
    },
    "PATCH /api/v1/orchestrator-keys/{key_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/api_keys.py:137"],
                "status": "404",
            }
        ],
        "handler": "update_orchestrator_key",
        "source": "backend/routers/api_keys.py",
    },
    "PATCH /api/v1/registration-keys/{key_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/api_keys.py:309"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/api_keys.py:320"],
                "status": "409",
            },
        ],
        "handler": "update_registration_key",
        "source": "backend/routers/api_keys.py",
    },
    "PATCH /api/v1/restores/{restore_id}/cancel": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/restores.py:470 -> backend/deps.py:check_role"
                ],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/restores.py:476"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/restores.py:479"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/restores.py:486"],
                "status": "400",
            },
        ],
        "handler": "cancel_restore",
        "source": "backend/routers/restores.py",
    },
    "POST /api/v1/agents/backups/{backup_id}/checkpoint-proof": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:178"],
                "status": "413",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:183"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:192"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:196"],
                "status": "503",
            },
        ],
        "handler": "transaction_checkpoint_proof",
        "source": "backend/routers/health.py",
    },
    "POST /api/v1/agents/backups/{backup_id}/finalize-intent": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:178"],
                "status": "413",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:183"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:192"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:196"],
                "status": "503",
            },
        ],
        "handler": "transaction_finalize_intent",
        "source": "backend/routers/health.py",
    },
    "POST /api/v1/agents/backups/{backup_id}/native-admission": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:178"],
                "status": "413",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:183"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:192"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:196"],
                "status": "503",
            },
        ],
        "handler": "native_admission",
        "source": "backend/routers/health.py",
    },
    "POST /api/v1/agents/backups/{backup_id}/native-closed-failure": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:178"],
                "status": "413",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:183"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:192"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:196"],
                "status": "503",
            },
        ],
        "handler": "native_closed_failure",
        "source": "backend/routers/health.py",
    },
    "POST /api/v1/agents/backups/{backup_id}/native-fenced-failure": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:178"],
                "status": "413",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:183"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:192"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:196"],
                "status": "503",
            },
        ],
        "handler": "native_fenced_failure",
        "source": "backend/routers/health.py",
    },
    "POST /api/v1/agents/backups/{backup_id}/native-inventory": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:178"],
                "status": "413",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:183"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:192"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:196"],
                "status": "503",
            },
        ],
        "handler": "native_inventory",
        "source": "backend/routers/health.py",
    },
    "POST /api/v1/agents/backups/{backup_id}/native-no-effect": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:178"],
                "status": "413",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:183"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:192"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:196"],
                "status": "503",
            },
        ],
        "handler": "native_no_effect",
        "source": "backend/routers/health.py",
    },
    "POST /api/v1/agents/backups/{backup_id}/native-publication": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:178"],
                "status": "413",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:183"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:192"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:196"],
                "status": "503",
            },
        ],
        "handler": "native_publication",
        "source": "backend/routers/health.py",
    },
    "POST /api/v1/agents/backups/{backup_id}/native-transaction": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:178"],
                "status": "413",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:183"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:192"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:196"],
                "status": "503",
            },
        ],
        "handler": "native_transaction",
        "source": "backend/routers/health.py",
    },
    "POST /api/v1/agents/backups/{backup_id}/prepared-receipt": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:340"],
                "status": "413",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:345"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:357"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:361"],
                "status": "503",
            },
        ],
        "handler": "prepared_receipt",
        "source": "backend/routers/health.py",
    },
    "POST /api/v1/agents/backups/{backup_id}/storage-control": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:143"],
                "status": "413",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:150"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:159"],
                "status": "409",
            },
        ],
        "handler": "storage_control",
        "source": "backend/routers/health.py",
    },
    "POST /api/v1/agents/backups/{backup_id}/storage-retirement": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:79"],
                "status": "413",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:84"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:91"],
                "status": "409",
            },
        ],
        "handler": "storage_retirement",
        "source": "backend/routers/health.py",
    },
    "POST /api/v1/agents/backups/{backup_id}/transaction-key": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:109"],
                "status": "413",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:116"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:125"],
                "status": "409",
            },
        ],
        "handler": "transaction_key",
        "source": "backend/routers/health.py",
    },
    "POST /api/v1/agents/register": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/agents.py:60",
                    "backend/routers/agents.py:74",
                    "backend/routers/agents.py:86",
                ],
                "status": "401",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/agents.py:92"],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/agents.py:94"],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/agents.py:102",
                    "backend/routers/agents.py:207",
                ],
                "status": "503",
            },
        ],
        "handler": "register_agent",
        "source": "backend/routers/agents.py",
    },
    "POST /api/v1/agents/{agent_id}/key-rotations/{rotation_id}/activate": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "agent_candidate_invalid",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/core/agent_key_rotation.py:188",
                    "backend/core/agent_key_rotation.py:215",
                    "backend/core/agent_key_rotation.py:312",
                ],
                "status": "401",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "verified_certificate_required",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/core/agent_key_rotation.py:197",
                    "backend/core/agent_key_rotation.py:322",
                ],
                "status": "401",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "agent_candidate_superseded",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/core/agent_key_rotation.py:230"],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "agent_candidate_certificate_invalid",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/core/agent_key_rotation.py:244",
                    "backend/core/agent_key_rotation.py:338",
                ],
                "status": "401",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "agent_rotation_not_found",
                                    "type": "string",
                                }
                            },
                            "required": ["code"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/core/agent_key_rotation.py:304"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "agent_rotation_authority_revoked",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/core/agent_key_rotation.py:89"],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"const": "agent_not_found", "type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/core/agent_key_rotation.py:270"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "agent_rotation_not_found",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/core/agent_key_rotation.py:281"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "agent_rotation_not_pending",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/core/agent_key_rotation.py:357"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "agent_candidate_expired",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/core/agent_key_rotation.py:367"],
                "status": "410",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "agent_rotation_predecessor_changed",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/core/agent_key_rotation.py:375"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "agent_candidate_superseded",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/core/agent_key_rotation.py:348"],
                "status": "409",
            },
        ],
        "handler": "activate_agent_key",
        "source": "backend/routers/agents.py",
    },
    "POST /api/v1/agents/{agent_id}/rotate-key": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "agent_rotation_authority_revoked",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/core/agent_key_rotation.py:89"],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"const": "agent_not_found", "type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/core/agent_key_rotation.py:113"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "agent_rotation_predecessor_missing",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/core/agent_key_rotation.py:117"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "agent_rotation_pending",
                                    "type": "string",
                                },
                                "rotation_id": {"type": "string"},
                            },
                            "required": ["code", "rotation_id"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/core/agent_key_rotation.py:133"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "agent_rotation_configuration",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/core/agent_key_rotation.py:38",
                    "backend/core/agent_key_rotation.py:30",
                ],
                "status": "500",
            },
        ],
        "handler": "rotate_agent_key",
        "source": "backend/routers/agents.py",
    },
    "POST /api/v1/agents/{hostname}/vms": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/agents.py:260"],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "core/vm_inventory.py:49 "
                    "sync_inventory; "
                    "core/agent_scope.py:21 "
                    "namespace_list/validate_settings"
                ],
                "status": "422",
            },
        ],
        "handler": "sync_agent_vms",
        "source": "backend/routers/agents.py",
    },
    "POST /api/v1/auth/login": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/auth.py:101"],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/auth.py:99",
                    "backend/routers/auth.py:120",
                    "backend/routers/auth.py:128",
                    "backend/routers/auth.py:117",
                ],
                "status": "401",
            },
        ],
        "handler": "login",
        "source": "backend/routers/auth.py",
    },
    "POST /api/v1/auth/logout": {
        "errors": [],
        "handler": "logout",
        "source": "backend/routers/auth.py",
    },
    "POST /api/v1/auth/oidc/test": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/auth.py:331",
                    "backend/routers/auth.py:358",
                    "backend/routers/auth.py:375",
                    "backend/routers/auth.py:382",
                    "backend/routers/auth.py:405",
                    "backend/routers/auth.py:407",
                    "backend/routers/auth.py:327",
                    "backend/routers/auth.py:335",
                    "backend/routers/auth.py:366",
                    "backend/routers/auth.py:389",
                ],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/auth.py:412"],
                "status": "500",
            },
        ],
        "handler": "test_oidc_configuration",
        "source": "backend/routers/auth.py",
    },
    "POST /api/v1/auth/refresh": {
        "errors": [],
        "handler": "refresh_token",
        "source": "backend/routers/auth.py",
    },
    "POST /api/v1/backups": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "core/backup_service.py:115 can_start_backup -> "
                    "BackupCreateResult.error_code -> "
                    "routers/backups.py:163"
                ],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "core/backup_service.py:115 can_start_backup -> "
                    "BackupCreateResult.error_code -> "
                    "routers/backups.py:163"
                ],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "core/backup_service.py:115 can_start_backup -> "
                    "BackupCreateResult.error_code -> "
                    "routers/backups.py:163"
                ],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "core/backup_service.py:115 can_start_backup -> "
                    "BackupCreateResult.error_code -> "
                    "routers/backups.py:163"
                ],
                "status": "503",
            },
        ],
        "handler": "create_backup",
        "source": "backend/routers/backups.py",
    },
    "POST /api/v1/backups/bulk-create": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/bulk.py:78"],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "bulk_admission_limit",
                                    "type": "string",
                                },
                                "max_targets": {"type": "integer"},
                            },
                            "required": ["code", "max_targets"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/bulk.py:80"],
                "status": "422",
            },
        ],
        "handler": "bulk_create_backups",
        "source": "backend/routers/bulk.py",
    },
    "POST /api/v1/backups/bulk-delete": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/bulk.py:145"],
                "status": "400",
            }
        ],
        "handler": "bulk_delete_backups",
        "source": "backend/routers/bulk.py",
    },
    "POST /api/v1/backups/bulk-tag": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/bulk.py:241",
                    "backend/routers/bulk.py:247",
                ],
                "status": "400",
            }
        ],
        "handler": "bulk_tag_backups",
        "source": "backend/routers/bulk.py",
    },
    "POST /api/v1/backups/cleanup": {
        "errors": [],
        "handler": "cleanup_expired_backups",
        "source": "backend/routers/backups.py",
    },
    "POST /api/v1/backups/queue": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/queue.py:94"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/queue.py:105",
                    "backend/routers/queue.py:117",
                ],
                "status": "409",
            },
        ],
        "handler": "add_backup_to_queue",
        "source": "backend/routers/queue.py",
    },
    "POST /api/v1/backups/{backup_id}/resume": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "backup_id": {"type": "string"},
                                "capacity_retained": {"const": True, "type": "boolean"},
                                "reason": {"type": "string"},
                                "status": {"const": "held", "type": "string"},
                            },
                            "required": [
                                "status",
                                "backup_id",
                                "reason",
                                "capacity_retained",
                            ],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/backups.py:412"],
                "status": "423",
            }
        ],
        "handler": "resume_attempt",
        "source": "backend/routers/backups.py",
    },
    "POST /api/v1/backups/{backup_id}/retry-upload": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "reason": {"type": "string"},
                                "status": {"const": "held", "type": "string"},
                            },
                            "required": ["status", "reason"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/backups.py:389"],
                "status": "423",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "core/upload_retry.py:90 record_retry_hold",
                    "backend/core/upload_retry.py:110",
                ],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "core/upload_retry.py:90 record_retry_hold",
                    "backend/core/upload_retry.py:113",
                ],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "core/upload_retry.py:90 record_retry_hold",
                    "backend/core/upload_retry.py:120",
                    "backend/core/upload_retry.py:129",
                ],
                "status": "409",
            },
        ],
        "handler": "retry_upload",
        "source": "backend/routers/backups.py",
    },
    "POST /api/v1/backups/{backup_id}/verify": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/verification.py:116",
                    "backend/routers/verification.py:142",
                ],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/verification.py:119"],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/verification.py:168"],
                "status": "409",
            },
        ],
        "handler": "verify_backup",
        "source": "backend/routers/verification.py",
    },
    "POST /api/v1/billing/export": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["commercial/backend/modules/billing.py:295"],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["core/licensing.py:286 require_feature"],
                "status": "403",
            },
        ],
        "handler": "export_billing",
        "source": "commercial/backend/modules/billing.py",
    },
    "POST /api/v1/branding/{org_id}/logo": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "commercial/backend/modules/white_label.py:135",
                    "commercial/backend/modules/white_label.py:144",
                ],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["commercial/backend/modules/white_label.py:150"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["core/licensing.py:286 require_feature"],
                "status": "403",
            },
        ],
        "handler": "upload_logo",
        "source": "commercial/backend/modules/white_label.py",
    },
    "POST /api/v1/demo/backups": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:55"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:91"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:77"],
                "status": "401",
            },
        ],
        "handler": "create_backup",
        "source": "backend/routers/demo.py",
    },
    "POST /api/v1/demo/backups/{backup_id}/retry": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:55"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:91"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:77"],
                "status": "401",
            },
        ],
        "handler": "retry_backup",
        "source": "backend/routers/demo.py",
    },
    "POST /api/v1/demo/groups": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:55"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:77"],
                "status": "401",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:91"],
                "status": "422",
            },
        ],
        "handler": "create_group",
        "source": "backend/routers/demo.py",
    },
    "POST /api/v1/demo/groups/preview": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:55"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:77"],
                "status": "401",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:91"],
                "status": "422",
            },
        ],
        "handler": "preview_group",
        "source": "backend/routers/demo.py",
    },
    "POST /api/v1/demo/reset": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:55"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:267"],
                "status": "401",
            },
        ],
        "handler": "reset_session",
        "source": "backend/routers/demo.py",
    },
    "POST /api/v1/demo/restores": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:55"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:91"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:77"],
                "status": "401",
            },
        ],
        "handler": "create_restore",
        "source": "backend/routers/demo.py",
    },
    "POST /api/v1/demo/schedules": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:55"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:91"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:77"],
                "status": "401",
            },
        ],
        "handler": "create_schedule",
        "source": "backend/routers/demo.py",
    },
    "POST /api/v1/demo/schedules/{schedule_id}/run": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:55"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:91"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:77"],
                "status": "401",
            },
        ],
        "handler": "run_schedule",
        "source": "backend/routers/demo.py",
    },
    "POST /api/v1/demo/sessions": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:55"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:114"],
                "status": "503",
            },
        ],
        "handler": "create_session",
        "source": "backend/routers/demo.py",
    },
    "POST /api/v1/encryption/keys": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/encryption.py:99 -> backend/deps.py:check_role"
                ],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "provider_admission_contract_unavailable",
                                    "type": "string",
                                }
                            },
                            "required": ["code"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/encryption.py:102"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/encryption.py:111"],
                "status": "400",
            },
        ],
        "handler": "create_key",
        "source": "backend/routers/encryption.py",
    },
    "POST /api/v1/encryption/keys/confirm-export": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/encryption.py:303 -> backend/deps.py:check_role"
                ],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/encryption.py:306",
                    "backend/routers/encryption.py:315",
                ],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/encryption.py:311"],
                "status": "413",
            },
        ],
        "handler": "confirm_export_custody",
        "source": "backend/routers/encryption.py",
    },
    "POST /api/v1/encryption/keys/export": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/encryption.py:228 -> backend/deps.py:check_role"
                ],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/encryption.py:232",
                    "backend/routers/encryption.py:254",
                ],
                "status": "400",
            },
        ],
        "handler": "export_keys",
        "source": "backend/routers/encryption.py",
    },
    "POST /api/v1/encryption/keys/import": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/encryption.py:265 -> backend/deps.py:check_role"
                ],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/encryption.py:269",
                    "backend/routers/encryption.py:274",
                    "backend/routers/encryption.py:291",
                ],
                "status": "400",
            },
        ],
        "handler": "import_keys",
        "source": "backend/routers/encryption.py",
    },
    "POST /api/v1/encryption/keys/{key_id}/revoke": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/encryption.py:208 -> backend/deps.py:check_role"
                ],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/encryption.py:218"],
                "status": "400",
            },
        ],
        "handler": "revoke_key",
        "source": "backend/routers/encryption.py",
    },
    "POST /api/v1/encryption/keys/{key_id}/rotate": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/encryption.py:168 -> backend/deps.py:check_role"
                ],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "provider_admission_contract_unavailable",
                                    "type": "string",
                                }
                            },
                            "required": ["code"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/encryption.py:171"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "stale_key_predecessor",
                                    "type": "string",
                                }
                            },
                            "required": ["code"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/encryption.py:186"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/encryption.py:188"],
                "status": "400",
            },
        ],
        "handler": "rotate_key",
        "source": "backend/routers/encryption.py",
    },
    "POST /api/v1/groups": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/groups.py:82"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/groups.py:88",
                    "backend/routers/groups.py:102",
                    "backend/routers/groups.py:97",
                ],
                "status": "400",
            },
        ],
        "handler": "create_group",
        "source": "backend/routers/groups.py",
    },
    "POST /api/v1/groups/{group_id}/preview": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/groups.py:363",
                    "backend/routers/groups.py:367",
                ],
                "status": "400",
            }
        ],
        "handler": "preview_group_rules",
        "source": "backend/routers/groups.py",
    },
    "POST /api/v1/groups/{group_id}/vms": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/groups.py:268"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/groups.py:271"],
                "status": "400",
            },
        ],
        "handler": "add_vms_to_group",
        "source": "backend/routers/groups.py",
    },
    "POST /api/v1/health/agents/{agent_id}/heartbeat": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/health.py:903"],
                "status": "403",
            }
        ],
        "handler": "agent_heartbeat",
        "source": "backend/routers/health.py",
    },
    "POST /api/v1/licensing/acknowledgement/confirm": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "request_too_large",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/licensing.py:76"],
                "status": "413",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"const": "invalid_request", "type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/licensing.py:88"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "core/license_registration.py:38 "
                    "RegistrationError "
                    "default status; "
                    "routers/licensing.py:62 "
                    "_invoke"
                ],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "installation_authority_required",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["core/license_registration.py:334 _authorize"],
                "status": "403",
            },
        ],
        "handler": "confirm_acknowledgement",
        "source": "backend/routers/licensing.py",
    },
    "POST /api/v1/licensing/acknowledgement/prepare": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "request_too_large",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/licensing.py:76"],
                "status": "413",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"const": "invalid_request", "type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/licensing.py:88"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "core/license_registration.py:38 "
                    "RegistrationError "
                    "default status; "
                    "routers/licensing.py:62 "
                    "_invoke"
                ],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "installation_authority_required",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["core/license_registration.py:334 _authorize"],
                "status": "403",
            },
        ],
        "handler": "prepare_acknowledgement",
        "source": "backend/routers/licensing.py",
    },
    "POST /api/v1/licensing/import": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "request_too_large",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/licensing.py:76"],
                "status": "413",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"const": "invalid_request", "type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/licensing.py:88"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "core/license_registration.py:38 "
                    "RegistrationError default status; "
                    "routers/licensing.py:62 _invoke"
                ],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "installation_authority_required",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["core/license_registration.py:334 _authorize"],
                "status": "403",
            },
        ],
        "handler": "import_registration",
        "source": "backend/routers/licensing.py",
    },
    "POST /api/v1/notifications/mark-all-read": {
        "errors": [],
        "handler": "mark_all_notifications_read",
        "source": "backend/routers/notifications.py",
    },
    "POST /api/v1/notifications/rules": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/notifications.py:25 -> backend/deps.py:check_role"
                ],
                "status": "403",
            }
        ],
        "handler": "create_notification_rule",
        "source": "backend/routers/notifications.py",
    },
    "POST /api/v1/notifications/test": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/notifications.py:227",
                    "backend/routers/notifications.py:241",
                    "backend/routers/notifications.py:243",
                    "backend/routers/notifications.py:245",
                ],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/notifications.py:260",
                    "backend/routers/notifications.py:279",
                ],
                "status": "500",
            },
        ],
        "handler": "test_notification",
        "source": "backend/routers/notifications.py",
    },
    "POST /api/v1/orchestrator-keys": {
        "errors": [],
        "handler": "create_orchestrator_key",
        "source": "backend/routers/api_keys.py",
    },
    "POST /api/v1/organizations": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["commercial/backend/modules/multi_tenant.py:139"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["commercial/backend/modules/multi_tenant.py:153"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["core/licensing.py:286 require_feature"],
                "status": "403",
            },
        ],
        "handler": "create_organization",
        "source": "commercial/backend/modules/multi_tenant.py",
    },
    "POST /api/v1/pki/certificates/{cert_id}/revoke": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/pki.py:188"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/pki.py:191"],
                "status": "409",
            },
        ],
        "handler": "revoke_certificate",
        "source": "backend/routers/pki.py",
    },
    "POST /api/v1/pki/initialize": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/pki.py:34"],
                "status": "409",
            }
        ],
        "handler": "initialize_ca",
        "source": "backend/routers/pki.py",
    },
    "POST /api/v1/pki/renew": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/pki.py:230", "backend/routers/pki.py:239"],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/pki.py:234"],
                "status": "503",
            },
        ],
        "handler": "renew_certificate",
        "source": "backend/routers/pki.py",
    },
    "POST /api/v1/registration-keys": {
        "errors": [],
        "handler": "create_registration_key",
        "source": "backend/routers/api_keys.py",
    },
    "POST /api/v1/reports": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/reports.py:48",
                    "backend/routers/reports.py:55",
                ],
                "status": "400",
            }
        ],
        "handler": "create_report",
        "source": "backend/routers/reports.py",
    },
    "POST /api/v1/reports/{report_id}/generate": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/reports.py:292"],
                "status": "404",
            }
        ],
        "handler": "generate_report",
        "source": "backend/routers/reports.py",
    },
    "POST /api/v1/restores": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/restores.py:45 -> backend/deps.py:check_role"
                ],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/restores.py:61"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/restores.py:64",
                    "backend/routers/restores.py:86",
                    "backend/routers/restores.py:95",
                ],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/restores.py:234",
                    "backend/routers/restores.py:161",
                ],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/restores.py:268",
                    "backend/routers/restores.py:195",
                ],
                "status": "409",
            },
        ],
        "handler": "create_restore",
        "source": "backend/routers/restores.py",
    },
    "POST /api/v1/restores/{restore_id}/resume": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/restores.py:437 -> backend/deps.py:check_role",
                    "backend/routers/restores.py:444",
                ],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/restores.py:442"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/restores.py:452"],
                "status": "409",
            },
        ],
        "handler": "resume_kubevirt_restore",
        "source": "backend/routers/restores.py",
    },
    "POST /api/v1/s3/import": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/s3_import.py:309 -> backend/deps.py:check_role"
                ],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/s3_import.py:81",
                    "backend/routers/s3_import.py:334",
                ],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/s3_import.py:394",
                    "backend/routers/s3_import.py:405",
                ],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/s3_import.py:359"],
                "status": "400",
            },
        ],
        "handler": "import_chain",
        "source": "backend/routers/s3_import.py",
    },
    "POST /api/v1/saved-searches": {
        "errors": [],
        "handler": "create_saved_search",
        "source": "backend/routers/search.py",
    },
    "POST /api/v1/saved-searches/{search_id}/execute": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/search.py:198"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/search.py:201"],
                "status": "403",
            },
        ],
        "handler": "execute_saved_search",
        "source": "backend/routers/search.py",
    },
    "POST /api/v1/schedules": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/schedules.py:226"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/schedules.py:239",
                    "backend/routers/schedules.py:245",
                    "backend/routers/schedules.py:272",
                ],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/schedules.py:235"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/schedules.py:254",
                    "backend/routers/schedules.py:264",
                ],
                "status": "404",
            },
        ],
        "handler": "create_schedule",
        "source": "backend/routers/schedules.py",
    },
    "POST /api/v1/schedules/{schedule_id}/grant": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/schedules.py:125"],
                "status": "409",
            }
        ],
        "handler": "enroll_schedule_grant",
        "source": "backend/routers/schedules.py",
    },
    "POST /api/v1/schedules/{schedule_id}/run-now": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/schedules.py:580"],
                "status": "404",
            }
        ],
        "handler": "run_schedule_now",
        "source": "backend/routers/schedules.py",
    },
    "POST /api/v1/search": {
        "errors": [],
        "handler": "global_search",
        "source": "backend/routers/search.py",
    },
    "POST /api/v1/settings/test-email": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/config.py:379",
                    "backend/routers/config.py:399",
                    "backend/routers/config.py:403",
                    "backend/routers/config.py:405",
                ],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/config.py:417",
                    "backend/routers/config.py:432",
                ],
                "status": "500",
            },
        ],
        "handler": "test_email_settings",
        "source": "backend/routers/config.py",
    },
    "POST /api/v1/settings/test-s3": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/config.py:273",
                    "backend/routers/config.py:319",
                    "backend/routers/config.py:316",
                ],
                "status": "400",
            }
        ],
        "handler": "test_s3_connection",
        "source": "backend/routers/config.py",
    },
    "POST /api/v1/users": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/users.py:127",
                    "backend/routers/users.py:135",
                    "backend/routers/users.py:143",
                    "backend/routers/users.py:182",
                ],
                "status": "400",
            }
        ],
        "handler": "create_user",
        "source": "backend/routers/users.py",
    },
    "POST /api/v1/vms/ids-by-filter": {
        "errors": [],
        "handler": "get_vm_ids_by_filter",
        "source": "backend/routers/agents.py",
    },
    "PUT /api/v1/branding/{org_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["commercial/backend/modules/white_label.py:104"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["core/licensing.py:286 require_feature"],
                "status": "403",
            },
        ],
        "handler": "update_branding",
        "source": "commercial/backend/modules/white_label.py",
    },
    "PUT /api/v1/demo/groups/{group_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:55"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:91"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/demo.py:77"],
                "status": "401",
            },
        ],
        "handler": "update_group",
        "source": "backend/routers/demo.py",
    },
    "PUT /api/v1/groups/{group_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/groups.py:182"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/groups.py:187"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/groups.py:200",
                    "backend/routers/groups.py:209",
                    "backend/routers/groups.py:216",
                ],
                "status": "400",
            },
        ],
        "handler": "update_group",
        "source": "backend/routers/groups.py",
    },
    "PUT /api/v1/licensing/registration-url": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "request_too_large",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/licensing.py:76"],
                "status": "413",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"const": "invalid_request", "type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/licensing.py:88"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "core/license_registration.py:38 "
                    "RegistrationError default "
                    "status; "
                    "routers/licensing.py:62 "
                    "_invoke"
                ],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "additionalProperties": False,
                            "properties": {
                                "code": {
                                    "const": "installation_authority_required",
                                    "type": "string",
                                },
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                            "type": "object",
                        }
                    },
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["core/license_registration.py:334 _authorize"],
                "status": "403",
            },
        ],
        "handler": "registration_url",
        "source": "backend/routers/licensing.py",
    },
    "PUT /api/v1/notifications/rules/{rule_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/notifications.py:118 -> backend/deps.py:check_role"
                ],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/notifications.py:122"],
                "status": "404",
            },
        ],
        "handler": "update_notification_rule",
        "source": "backend/routers/notifications.py",
    },
    "PUT /api/v1/notifications/settings": {
        "errors": [],
        "handler": "update_notification_settings",
        "source": "backend/routers/notifications.py",
    },
    "PUT /api/v1/notifications/{notification_id}/read": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/notifications.py:400"],
                "status": "404",
            }
        ],
        "handler": "mark_notification_read",
        "source": "backend/routers/notifications.py",
    },
    "PUT /api/v1/organizations/{org_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["commercial/backend/modules/multi_tenant.py:244"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["core/licensing.py:286 require_feature"],
                "status": "403",
            },
        ],
        "handler": "update_organization",
        "source": "commercial/backend/modules/multi_tenant.py",
    },
    "PUT /api/v1/reports/{report_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/reports.py:204"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/reports.py:213"],
                "status": "400",
            },
        ],
        "handler": "update_report",
        "source": "backend/routers/reports.py",
    },
    "PUT /api/v1/schedules/{schedule_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/schedules.py:387"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/schedules.py:392",
                    "backend/routers/schedules.py:424",
                ],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/schedules.py:401"],
                "status": "422",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/schedules.py:439"],
                "status": "400",
            },
        ],
        "handler": "update_schedule",
        "source": "backend/routers/schedules.py",
    },
    "PUT /api/v1/settings": {
        "errors": [],
        "handler": "update_settings_bulk",
        "source": "backend/routers/config.py",
    },
    "PUT /api/v1/settings/v3": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/config.py:196",
                    "backend/routers/config.py:194",
                    "backend/routers/config.py:218",
                    "backend/routers/config.py:231",
                ],
                "status": "400",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/config.py:253"],
                "status": "500",
            },
        ],
        "handler": "update_settings_v3",
        "source": "backend/routers/config.py",
    },
    "PUT /api/v1/settings/{setting_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/config.py:334"],
                "status": "404",
            }
        ],
        "handler": "update_setting",
        "source": "backend/routers/config.py",
    },
    "PUT /api/v1/users/{user_id}": {
        "errors": [
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/users.py:38",
                    "backend/routers/users.py:41",
                ],
                "status": "401",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/users.py:43",
                    "backend/routers/users.py:230",
                ],
                "status": "403",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/users.py:51"],
                "status": "404",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": ["backend/routers/users.py:62"],
                "status": "409",
            },
            {
                "schema": {
                    "additionalProperties": False,
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                    "type": "object",
                },
                "sources": [
                    "backend/routers/users.py:236",
                    "backend/routers/users.py:238",
                    "backend/routers/users.py:241",
                    "backend/routers/users.py:245",
                    "backend/routers/users.py:248",
                    "backend/routers/users.py:253",
                    "backend/routers/users.py:257",
                    "backend/routers/users.py:267",
                    "backend/routers/users.py:273",
                    "backend/routers/users.py:299",
                    "backend/routers/users.py:310",
                    "backend/routers/users.py:317",
                    "backend/routers/users.py:330",
                    "backend/routers/users.py:368",
                ],
                "status": "400",
            },
        ],
        "handler": "update_user",
        "source": "backend/routers/users.py",
    },
}


def apply_error_contracts(document, routes=()):
    """Add reviewed route/helper errors, preserving already-described variants.

    Route dependencies supply authentication/authority refusal reachability.
    Middleware errors apply independently of route-level authorization and can
    therefore also occur on otherwise public or HTML callback routes.
    """
    from operator_contracts import dependency_names, effective_http_routes, obj

    string = {"type": "string"}
    detail = obj({"detail": string})
    names_by_operation = {}
    for route, _ in effective_http_routes(routes):
        for method in route.methods:
            names_by_operation[(route.path_format, method.lower())] = dependency_names(
                route.dependant
            )

    def add(
        operation,
        status,
        schema,
        source,
        *,
        media="application/json",
        description=None,
        headers=()
    ):
        response = operation.setdefault("responses", {}).setdefault(
            str(status), {"description": description or "Request refused or failed"}
        )
        content = response.setdefault("content", {}).setdefault(media, {})
        old = content.get("schema")
        if old is None or old == {}:
            content["schema"] = deepcopy(schema)
        elif old != schema:
            variants = old.get("anyOf") if set(old) == {"anyOf"} else [old]
            if schema not in variants:
                content["schema"] = {"anyOf": [*deepcopy(variants), deepcopy(schema)]}
        evidence = response.setdefault("x-error-sources", [])
        if source not in evidence:
            evidence.append(source)
        if description and "x-error-conditions" not in response:
            response["x-error-conditions"] = [description]
        elif description and description not in response["x-error-conditions"]:
            response["x-error-conditions"].append(description)
        for header in headers:
            response.setdefault("headers", {}).setdefault(header, {"schema": string})

    demo_denied = obj(
        {
            "detail": obj(
                {
                    "code": {"const": "DEMO_POLICY_DENIED", "type": "string"},
                    "message": string,
                }
            ),
            "environment": {"const": "demo", "type": "string"},
            "simulated": {"const": True, "type": "boolean"},
        }
    )
    demo_limited = obj(
        {
            "detail": obj(
                {
                    "code": {"const": "DEMO_RATE_LIMITED", "type": "string"},
                    "message": string,
                }
            ),
            "environment": {"const": "demo", "type": "string"},
            "simulated": {"const": True, "type": "boolean"},
        }
    )
    public_demo_allowed = {"/health", "/ready", "/metrics", "/api/v1/version"}
    methods = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
    for path, operations in document.get("paths", {}).items():
        for method, operation in operations.items():
            if method not in methods:
                continue
            callback = path == "/api/v1/auth/oidc/callback"
            login = path == "/api/v1/auth/login"
            row = SOURCE_ERRORS.get(method.upper() + " " + path)
            if row:
                for error in row["errors"]:
                    status = error["status"]
                    if callback:
                        # AuthRoute intercepts HTTPException + validation and
                        # renders HTML at the same status (validation is400).
                        media = "text/html"
                        schema = string
                    else:
                        media = "application/json"
                        schema = error["schema"]
                    if login and status in {"400", "401", "403", "422"}:
                        status = "401"
                        schema = obj(
                            {
                                "detail": {
                                    "type": "string",
                                    "const": "Invalid credentials",
                                }
                            }
                        )
                    for source in error["sources"]:
                        add(operation, status, schema, source, media=media)

            names = names_by_operation.get((path, method), set())
            if "get_current_user" in names:
                add(
                    operation,
                    "401",
                    detail,
                    "backend/deps.py:get_current_user/require_enabled_organization",
                    description=(
                        "Bearer absent, invalid, disabled, stale or organization"
                        " unavailable"
                    ),
                    headers=["WWW-Authenticate"],
                )
            if names.intersection(
                {
                    "get_admin_user",
                    "get_platform_admin",
                    "get_installation_admin",
                    "get_organization_admin_db",
                    "get_operator_or_admin",
                    "role_dependency",
                }
            ):
                add(
                    operation,
                    "403",
                    detail,
                    "backend/deps.py:RBAC dependencies",
                    description=(
                        "Persisted identity lacks required role or"
                        " installation/platform authority"
                    ),
                )
            if names.intersection(
                {
                    "verify_agent_api_key",
                    "authenticate_callback",
                    "registration_database",
                }
            ):
                add(
                    operation,
                    "401",
                    detail,
                    "backend/deps.py:_authenticate_agent/registration_database;"
                    " core/callback_identity.py:authenticate_callback",
                    description=(
                        "Missing/invalid agent or registration credential, or required"
                        " verified TLS transport unavailable"
                    ),
                )
            if names.intersection({"verify_agent_api_key", "authenticate_callback"}):
                add(
                    operation,
                    "403",
                    detail,
                    "backend/deps.py:_verify_agent_cert/_verify_agent_key",
                    description=(
                        "Agent identity or key is invalid, disabled, expired or no"
                        " longer available"
                    ),
                )
            # Global tenant middleware executes outside route exception wrappers.
            add(
                operation,
                "401",
                obj(
                    {
                        "detail": {
                            "type": "string",
                            "const": "Invalid tenant credentials",
                        }
                    }
                ),
                "backend/core/tenant_context.py:184 tenant_middleware",
                description=(
                    "If a Bearer header is supplied, middleware may reject malformed"
                    " tenant credentials before route dispatch"
                ),
            )
            add(
                operation,
                "500",
                {"type": "string", "const": "Internal Server Error"},
                "Starlette ServerErrorMiddleware (application debug=False)",
                media="text/plain",
                description=(
                    "Unhandled exception outside route-level conversion; body is plain"
                    " text"
                ),
            )
            if (
                method != "options"
                and path not in public_demo_allowed
                and path.startswith(("/api/", "/ws"))
                and not path.startswith("/api/v1/demo/")
            ):
                add(
                    operation,
                    "403",
                    demo_denied,
                    "backend/middleware.py:DemoPolicyMiddleware.dispatch",
                    description=(
                        "Only in demo deployment mode: ordinary API surface is denied"
                        " before handlers"
                    ),
                    headers=["X-Vnbui-Environment", "X-Vnbui-Simulated"],
                )
            if path.startswith("/api/v1/demo/"):
                add(
                    operation,
                    "429",
                    demo_limited,
                    "backend/middleware.py:DemoPolicyMiddleware._demo_rate_limits;"
                    " demo/limits.py:DemoRateLimiter.check",
                    description=(
                        "Only in demo deployment mode: per-source/session window limit"
                        " reached"
                    ),
                    headers=["Retry-After", "X-Vnbui-Environment", "X-Vnbui-Simulated"],
                )
            if login:
                operation["responses"].pop("422", None)
                # AuthRoute maps request validation failures to generic401.
                add(
                    operation,
                    "401",
                    obj({"detail": {"type": "string", "const": "Invalid credentials"}}),
                    "backend/routers/auth.py:AuthRoute.get_route_handler",
                    headers=["WWW-Authenticate"],
                )
            if callback:
                operation["responses"].pop("422", None)
                for status in ("400", "500", "503"):
                    add(
                        operation,
                        status,
                        string,
                        "backend/routers/auth.py:AuthRoute.get_route_handler",
                        media="text/html",
                        headers=["Set-Cookie"],
                    )
    document["x-registered-rate-limit-error"] = {
        "status": 429,
        "schema": obj({"error": string}),
        "source": (
            "backend/middleware.py:setup_rate_limiting ->"
            " slowapi._rate_limit_exceeded_handler"
        ),
        "reachability": (
            "Handler registered when enabled, but shipped routes have no limiter"
            " decorators or SlowAPIMiddleware; not asserted as an active route error."
        ),
    }
    return document

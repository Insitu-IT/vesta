"""Supported local-administrator recovery command."""

import argparse
import logging

from core.admin_credentials import (
    recover_missing_admin,
    reset_existing_admin,
    recover_platform_access,
)
from database import SessionLocal


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    reset = subparsers.add_parser(
        "reset-password", help="reset an existing local admin password"
    )
    reset.add_argument("--username", required=True)
    reset.add_argument(
        "--org-id", help="persisted organization UUID; required in commercial mode"
    )
    reset.add_argument(
        "--password-file",
        required=True,
        help="path to a mounted secret file; password values are not accepted",
    )
    recover = subparsers.add_parser(
        "recover-access",
        help="create or reactivate a local admin when no active admin exists",
    )
    recover.add_argument("--username", required=True)
    recover.add_argument(
        "--org-id", help="persisted organization UUID; required in commercial mode"
    )
    recover.add_argument(
        "--password-file",
        required=True,
        help="path to a mounted secret file; password values are not accepted",
    )
    platform = subparsers.add_parser(
        "recover-platform-access",
        help="operator-only recovery when no active platform authority remains",
    )
    platform.add_argument("--username", required=True)
    platform.add_argument("--org-id", required=True)
    platform.add_argument("--password-file", required=True)
    platform.add_argument(
        "--reason", required=True, help="non-secret audit justification"
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    db = SessionLocal()
    try:
        if args.command == "recover-platform-access":
            recover_platform_access(
                db, args.org_id, args.username, args.password_file, args.reason
            )
            return 0
        from core.tenant_context import TenantContext, identity

        with TenantContext(args.org_id):
            identity()  # Missing commercial identity fails before recovery SQL.
            return recover_organization_admin(args, db)
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def recover_organization_admin(args, db):
    if args.command == "reset-password":
        reset_existing_admin(db, args.username, args.password_file)
        logging.getLogger(__name__).info(
            "Reset password for local admin %s", args.username
        )
    elif args.command == "recover-access":
        recover_missing_admin(db, args.username, args.password_file)
        logging.getLogger(__name__).warning(
            "Recovered local administrator access for %s", args.username
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

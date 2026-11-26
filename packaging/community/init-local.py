#!/usr/bin/env python3
"""Create the private input files for a local Community quickstart."""

import base64
import os
from pathlib import Path
import re
import secrets
import stat

TOKEN = r"[A-Za-z0-9_-]{43}"
SECRET_FORMATS = {
    "postgres-password": TOKEN,
    "owner-password": TOKEN,
    "runtime-password": TOKEN,
    "jwt-secret": TOKEN,
    "fernet-key": TOKEN + "=",
    "admin-password": TOKEN + "Aa1!",
}
PROJECT_FORMAT = r"COMPOSE_PROJECT_NAME=vesta-community-[0-9a-f]{12}"


def existing_configuration(directory):
    info = directory.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_uid != os.getuid()
    ):
        raise ValueError("The quickstart directory must be owned by you with mode 0700")

    expected = {**SECRET_FORMATS, "compose.env": PROJECT_FORMAT}
    for name, pattern in expected.items():
        path = directory / name
        mode = 0o600 if name == "compose.env" else 0o644
        try:
            info = path.lstat()
        except FileNotFoundError:
            return False
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != mode
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or not 1 <= info.st_size <= 128
        ):
            return False
        if not re.fullmatch(pattern + r"\n", path.read_text(encoding="ascii")):
            return False
    return True


def write_new(path, contents, mode):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as stream:
        stream.write(contents)
        stream.flush()
        os.fchmod(stream.fileno(), mode)
        os.fsync(stream.fileno())


def initialize(directory):
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        if not existing_configuration(directory):
            raise ValueError(
                "Quickstart inputs are incomplete or have unexpected permissions. "
                "Keep them with the corresponding database and inspect before recreating."
            )
        return False

    # A permissive file mode allows read-only bind mounts to be read by
    # PostgreSQL and backend container UIDs. The parent directory is private.
    directory.chmod(0o700)
    values = {name: secrets.token_urlsafe(32) for name in SECRET_FORMATS}
    values["fernet-key"] = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(
        "ascii"
    )
    # Satisfy the configured default password complexity on every run.
    values["admin-password"] += "Aa1!"
    for name, value in values.items():
        write_new(directory / name, value + "\n", 0o644)

    # Publish the environment file last as the completion marker. Keep all
    # credentials in individual files, out of Compose interpolation.
    write_new(
        directory / "compose.env",
        f"COMPOSE_PROJECT_NAME=vesta-community-{secrets.token_hex(6)}\n",
        0o600,
    )
    return True


def main():
    directory = Path(__file__).resolve().parent / ".local"
    try:
        created = initialize(directory)
    except (OSError, ValueError) as error:
        raise SystemExit(f"Quickstart initialization refused. {error}") from None

    state = "created" if created else "already exist"
    print(f"Local quickstart inputs {state} in packaging/community/.local.")


if __name__ == "__main__":
    main()

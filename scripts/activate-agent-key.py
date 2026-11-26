#!/usr/bin/env python3
"""Deliberately activate a saved candidate with verified HTTPS; never print it."""
import argparse
import json
import os
import ssl
import stat
import sys
from urllib import error, parse, request
from uuid import UUID


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward a credential to another URL or origin.


def private_candidate(path):
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
        ):
            raise ValueError(
                "Candidate file must be a regular file owned by the current user with mode 0600 or stricter"
            )
        if info.st_size > 4096:
            raise ValueError("Candidate file too large")
        value = os.read(fd, 4097).decode("utf-8").strip()
    finally:
        os.close(fd)
    if value.startswith("{"):
        document = json.loads(value)
        value = document.get("api_key")
    if (
        not isinstance(value, str)
        or not 32 <= len(value) <= 1024
        or any(
            char
            not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
            for char in value
        )
    ):
        raise ValueError("Candidate file has no valid saved credential")
    return value


def uuid_value(value):
    return str(UUID(value))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--api-url",
        required=True,
        help="HTTPS API origin, optionally with a gateway prefix",
    )
    parser.add_argument("--agent-id", required=True, type=uuid_value)
    parser.add_argument("--rotation-id", required=True, type=uuid_value)
    parser.add_argument(
        "--candidate-file",
        required=True,
        help="Private file containing the saved key or original JSON response",
    )
    parser.add_argument("--ca-file")
    parser.add_argument("--client-cert")
    parser.add_argument("--client-key")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument(
        "--activate",
        required=True,
        action="store_true",
        help="Explicitly switch the active server credential",
    )
    args = parser.parse_args(argv)
    try:
        origin = parse.urlsplit(args.api_url)
        if (
            origin.scheme != "https"
            or not origin.netloc
            or origin.username
            or origin.password
            or origin.query
            or origin.fragment
        ):
            raise ValueError(
                "An HTTPS API URL without credentials, query or fragment is required"
            )
        if not 1 <= args.timeout <= 120:
            raise ValueError("Timeout must be between 1 and 120 seconds")
        if bool(args.client_cert) != bool(args.client_key):
            raise ValueError("Client certificate and key must be supplied together")
        context = ssl.create_default_context(cafile=args.ca_file)
        if args.client_cert:
            context.load_cert_chain(args.client_cert, args.client_key)
        candidate = private_candidate(args.candidate_file)
        url = (
            args.api_url.rstrip("/")
            + f"/api/v1/agents/{args.agent_id}/key-rotations/{args.rotation_id}/activate"
        )
        opener = request.build_opener(
            NoRedirect(), request.HTTPSHandler(context=context)
        )
        req = request.Request(
            url,
            method="POST",
            data=b"",
            headers={"X-Agent-Key": candidate, "Accept": "application/json"},
        )
        with opener.open(req, timeout=args.timeout) as response:
            payload = response.read(65537)
            if len(payload) > 65536:
                raise ValueError("Activation response too large")
            result = json.loads(payload)
            if (
                result.get("state") != "activated"
                or result.get("rotation_id") != args.rotation_id
                or result.get("agent_id") != args.agent_id
            ):
                raise ValueError("Activation receipt does not match the saved rotation")
        print(
            json.dumps(
                {
                    "agent_id": args.agent_id,
                    "rotation_id": args.rotation_id,
                    "state": "activated",
                }
            )
        )
        return 0
    except error.HTTPError as exc:
        print(
            f"Activation refused with HTTP {exc.code}; reconcile the saved rotation before another action.",
            file=sys.stderr,
        )
    except (error.URLError, TimeoutError, OSError):
        print(
            "Activation response unavailable; outcome may be unknown. Retry proof for the same rotation to reconcile.",
            file=sys.stderr,
        )
    except (ValueError, ssl.SSLError):
        print(
            "Activation input or receipt invalid; candidate was not displayed. Reconcile the saved rotation.",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

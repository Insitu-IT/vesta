"""Customer database TLS policy shared by schema-owner and runtime connections."""

import os
import ssl
from urllib.parse import parse_qs, unquote, urlsplit

from sqlalchemy.engine import make_url


class CustomerPostgresPrerequisiteError(RuntimeError):
    """Only fixed, non-secret prerequisite reasons may be emitted to logs."""


def customer_postgresql_profile():
    profile = os.environ.get("VESTA_DELIVERY_PROFILE", "full")
    if profile not in {"full", "customer-postgresql"}:
        raise CustomerPostgresPrerequisiteError("Unknown database delivery profile")
    return profile == "customer-postgresql"


def connection_parameters(database_url, *, asynchronous=False):
    """Enforce TLS before opening a connection; preserve unrelated URL options.

    asyncpg uses an SSLContext rather than libpq's sslmode/sslrootcert keyword
    arguments. Parse/rebuild URLs with SQLAlchemy to preserve escaped passwords.
    """
    if not customer_postgresql_profile():
        return database_url, {}
    url = make_url(database_url)
    if url.get_backend_name() != "postgresql":
        raise CustomerPostgresPrerequisiteError("Customer database requires PostgreSQL")
    # libpq/asyncpg ignore TLS on Unix sockets. Require an explicit TCP endpoint;
    # do not let an empty authority fall back through PGHOST or a service file.
    raw_hosts = parse_qs(urlsplit(database_url).query, keep_blank_values=True).get(
        "host"
    )
    host = (
        tuple(raw_hosts) if raw_hosts is not None else url.query.get("host", url.host)
    )
    hosts = host if isinstance(host, tuple) else (host,)
    if not hosts or any(
        not isinstance(value, str)
        or not value
        or any(
            not item
            or "/" in item
            or "\\" in item
            or "@" in item
            or any(character.isspace() for character in item)
            for item in unquote(value).split(",")
        )
        for value in hosts
    ):
        raise CustomerPostgresPrerequisiteError(
            "Customer PostgreSQL requires an explicit TCP host; socket and empty-host URLs are unsupported"
        )
    # GSS encryption can replace TLS in libpq even with sslmode=verify-full.
    # Disable that transport choice explicitly, matching the owner ssl_in_use check.
    if (
        url.query.get("gssencmode", os.environ.get("PGGSSENCMODE", "disable"))
        != "disable"
    ):
        raise CustomerPostgresPrerequisiteError(
            "Customer PostgreSQL requires gssencmode=disable to enforce TLS"
        )
    mode = url.query.get("sslmode", os.environ.get("PGSSLMODE"))
    ca = url.query.get("sslrootcert", os.environ.get("PGSSLROOTCERT"))
    if mode != "verify-full" or not isinstance(ca, str) or not ca:
        raise CustomerPostgresPrerequisiteError(
            "Customer PostgreSQL requires verify-full TLS and an explicit CA trust file"
        )
    if "ssl" in url.query:
        raise CustomerPostgresPrerequisiteError(
            "Customer PostgreSQL does not accept a separate ssl URL override"
        )
    if not asynchronous:
        return database_url, {
            "sslmode": "verify-full",
            "sslrootcert": ca,
            "gssencmode": "disable",
        }
    try:
        context = ssl.create_default_context(cafile=ca)
        # Optional client certificates retain their libpq URL/env meaning.
        cert = url.query.get("sslcert", os.environ.get("PGSSLCERT"))
        key = url.query.get("sslkey", os.environ.get("PGSSLKEY"))
        if cert:
            if not isinstance(cert, str) or (
                key is not None and not isinstance(key, str)
            ):
                raise ValueError("Invalid client certificate inputs")
            context.load_cert_chain(cert, key)
    except (OSError, ValueError, ssl.SSLError):
        raise CustomerPostgresPrerequisiteError(
            "Customer PostgreSQL CA or client certificate input is unusable"
        ) from None
    query = {
        name: value
        for name, value in url.query.items()
        if name not in {"sslmode", "sslrootcert", "sslcert", "sslkey", "gssencmode"}
    }
    return url.set(query=query).render_as_string(hide_password=False), {"ssl": context}

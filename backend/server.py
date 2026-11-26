"""Backend entrypoint with optional end-to-end verified agent TLS."""

import os
import ssl

import uvicorn
from core.verified_tls import VerifiedPeerH11


def configuration(environment=None):
    env = os.environ if environment is None else environment
    required = env.get("REQUIRE_MTLS", "false").lower() == "true"
    certificate = env.get("BACKEND_TLS_CERT_FILE")
    key = env.get("BACKEND_TLS_KEY_FILE")
    ca = env.get("BACKEND_TLS_CLIENT_CA_FILE")
    if bool(certificate) != bool(key) or (ca and not certificate):
        raise RuntimeError("Backend TLS requires an explicit certificate/key pair")
    if required and not (certificate and key and ca):
        raise RuntimeError(
            "REQUIRE_MTLS requires backend TLS certificate, key and client CA"
        )
    options = dict(
        host=env.get("BACKEND_HOST", "0.0.0.0"),
        port=int(env.get("BACKEND_PORT", "8000")),
        http=VerifiedPeerH11,
    )
    if certificate:
        options.update(
            ssl_certfile=certificate,
            ssl_keyfile=key,
            ssl_ca_certs=ca,
            # Browser/UI clients need not hold agent certs. Agent callbacks
            # require a verified peer at admission when REQUIRE_MTLS is true.
            ssl_cert_reqs=ssl.CERT_OPTIONAL if ca else ssl.CERT_NONE,
        )
    return options


if __name__ == "__main__":
    uvicorn.run("app:app", **configuration())

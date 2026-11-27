"""Public certificate identity for authenticated file-agent heartbeats."""

import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes


def current_file_controller_fingerprint(settings_service):
    """Match the cert selection used by the backend's outbound mTLS client."""
    path = os.environ.get("ORCHESTRATOR_CLIENT_CERT")
    if path:
        with Path(path).open("rb") as stream:
            pem = stream.read(65537)
    else:
        pem = (settings_service.get_secret("pki.backend_cert") or "").encode()
    if not pem or len(pem) > 65536:
        return ""
    return x509.load_pem_x509_certificate(pem).fingerprint(hashes.SHA256()).hex()

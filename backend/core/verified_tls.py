"""Bind callback identity to the actual verified TLS peer, never HTTP headers."""

from dataclasses import dataclass
import hashlib
import ssl

from uvicorn.protocols.http.h11_impl import H11Protocol

PEER_SCOPE = "vnbui.verified_tls_peer"


@dataclass(frozen=True)
class VerifiedPeer:
    fingerprint: str


def verified_peer(scope):
    peer = scope.get(PEER_SCOPE)
    return peer.fingerprint if type(peer) is VerifiedPeer else None


class VerifiedPeerH11(H11Protocol):
    """Per-connection adapter: OpenSSL verifies the chain before HTTP exists."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        application = self.app

        async def attest(scope, receive, send):
            scope = dict(scope)
            scope.pop(PEER_SCOPE, None)
            peer = self.transport.get_extra_info("ssl_object")
            if peer is not None and peer.context.verify_mode in (
                ssl.CERT_OPTIONAL,
                ssl.CERT_REQUIRED,
            ):
                certificate = peer.getpeercert(binary_form=True)
                if certificate:
                    scope[PEER_SCOPE] = VerifiedPeer(
                        hashlib.sha256(certificate).hexdigest()
                    )
            await application(scope, receive, send)

        self.app = attest

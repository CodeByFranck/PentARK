"""TLS hygiene analysis using the standard-library ``ssl`` module.

No external dependency (sslyze etc.) is required: we perform handshakes with the
stdlib and read the negotiated protocol/cipher and certificate. The analyzer is a
plain class so :class:`WeakTlsCheck` can be handed a stub in tests and never touch
a real socket. If ``sslyze`` is later desired for deeper cipher enumeration it can
wrap this same :class:`TlsInfo` shape.
"""

from __future__ import annotations

import datetime as _dt
import socket
import ssl
from dataclasses import dataclass, field

# Protocols considered obsolete/weak if the server still accepts them.
_DEPRECATED = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
}
_WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "ANON")


@dataclass
class TlsInfo:
    host: str
    port: int
    connected: bool = False
    protocol: str | None = None            # negotiated, e.g. "TLSv1.2"
    cipher: str | None = None              # negotiated cipher suite name
    not_after: _dt.datetime | None = None
    not_before: _dt.datetime | None = None
    expired: bool = False
    self_signed: bool = False
    hostname_mismatch: bool = False
    verify_error: str | None = None
    weak_protocols: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def negotiated_below_tls12(self) -> bool:
        return self.protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2")

    @property
    def weak_cipher(self) -> str | None:
        if not self.cipher:
            return None
        up = self.cipher.upper()
        return next((t for t in _WEAK_CIPHER_TOKENS if t in up), None)


class TlsAnalyzer:
    def __init__(self, *, timeout: float = 10.0) -> None:
        self.timeout = timeout

    def analyze(self, host: str, port: int = 443) -> TlsInfo:
        info = TlsInfo(host=host, port=port)

        # 1. Verifying handshake — succeeds only for a valid, trusted, in-date cert.
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    info.connected = True
                    info.protocol = ssock.version()
                    ci = ssock.cipher()
                    info.cipher = ci[0] if ci else None
                    _read_cert_dates(ssock.getpeercert(), info)
        except ssl.SSLCertVerificationError as exc:
            info.verify_error = str(exc)
            reason = (getattr(exc, "verify_message", "") or str(exc)).lower()
            info.expired = "expired" in reason
            info.self_signed = "self signed" in reason or "self-signed" in reason
            info.hostname_mismatch = "hostname mismatch" in reason or "doesn't match" in reason
            self._unverified_probe(host, port, info)
        except (ssl.SSLError, OSError) as exc:
            info.error = str(exc)
            return info

        # 2. Do the deprecated protocols still negotiate?
        for label, version in _DEPRECATED.items():
            if self._accepts_protocol(host, port, version):
                info.weak_protocols.append(label)
        return info

    def _unverified_probe(self, host: str, port: int, info: TlsInfo) -> None:
        """Even with an untrusted cert, capture the negotiated protocol/cipher."""
        ctx = ssl._create_unverified_context()
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    info.connected = True
                    info.protocol = ssock.version()
                    ci = ssock.cipher()
                    info.cipher = ci[0] if ci else None
                    _read_cert_dates(ssock.getpeercert(), info)
        except (ssl.SSLError, OSError):
            pass

    def _accepts_protocol(self, host: str, port: int, version: ssl.TLSVersion) -> bool:
        ctx = ssl._create_unverified_context()
        try:
            ctx.minimum_version = version
            ctx.maximum_version = version
        except (ValueError, ssl.SSLError):
            return False  # this OpenSSL build refuses to even offer it
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    return True
        except (ssl.SSLError, OSError):
            return False


def _read_cert_dates(cert: dict | None, info: TlsInfo) -> None:
    if not cert:
        return
    if cert.get("notAfter"):
        info.not_after = _parse_cert_time(cert["notAfter"])
    if cert.get("notBefore"):
        info.not_before = _parse_cert_time(cert["notBefore"])
    if info.not_after and info.not_after < _dt.datetime.now(_dt.timezone.utc):
        info.expired = True


def _parse_cert_time(value: str) -> _dt.datetime | None:
    # OpenSSL format, e.g. "Jun  1 12:00:00 2025 GMT".
    try:
        return _dt.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=_dt.timezone.utc)
    except ValueError:
        return None


__all__ = ["TlsAnalyzer", "TlsInfo"]

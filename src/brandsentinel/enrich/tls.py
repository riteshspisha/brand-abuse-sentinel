"""TLS certificate facts for a candidate host (U10).

The host is validated by netguard and the connection goes to a validated address
on 443 with the hostname as SNI. The leaf certificate is captured in binary form
without verification and parsed with `cryptography`; whether verification would
pass is decided by a second, normal handshake to the same address. No HTTP is
sent. The issuer (Let's Encrypt or any other) and self-signed status are facts,
not maliciousness indicators by themselves.
"""

import asyncio
import contextlib
import hashlib
import ssl
from datetime import UTC

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from brandsentinel.net.fetcher import unverified_context, verified_context
from brandsentinel.net.netguard import NetGuard

COLLECTOR_VERSION = "tls/1"
MAX_SANS = 500


class TlsCollectError(Exception):
    def __init__(self, kind: str, message: str = "") -> None:
        super().__init__(f"{kind}: {message}" if message else kind)
        self.kind = kind


def _key_info(cert: x509.Certificate) -> dict:
    try:
        key = cert.public_key()
    except Exception as e:  # unsupported or malformed key
        return {"type": "unknown", "error": type(e).__name__}
    if isinstance(key, rsa.RSAPublicKey):
        return {"type": "rsa", "bits": key.key_size}
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {"type": "ec", "curve": key.curve.name}
    if isinstance(key, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
        return {"type": "eddsa"}
    if isinstance(key, dsa.DSAPublicKey):
        return {"type": "dsa", "bits": key.key_size}
    return {"type": type(key).__name__}


def parse_certificate(der: bytes) -> dict:
    """Facts from a DER certificate. Raises ValueError if it does not parse."""
    cert = x509.load_der_x509_certificate(der)
    dns_names: list[str] = []
    ip_names: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = [str(n) for n in san.get_values_for_type(x509.DNSName)][:MAX_SANS]
        ip_names = [str(n) for n in san.get_values_for_type(x509.IPAddress)][:MAX_SANS]
    except x509.ExtensionNotFound:
        pass
    try:
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = None
    try:
        signature_algorithm = (
            cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
        )
    except Exception:  # unsupported algorithm
        signature_algorithm = None
    return {
        "sha256": hashlib.sha256(der).hexdigest(),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc.astimezone(UTC).isoformat(),
        "not_after": cert.not_valid_after_utc.astimezone(UTC).isoformat(),
        "validity_days": (cert.not_valid_after_utc - cert.not_valid_before_utc).days,
        "san_dns": dns_names,
        "san_ip": ip_names,
        "self_signed": cert.issuer == cert.subject,
        "is_ca": is_ca,
        "signature_hash": signature_algorithm,
        "public_key": _key_info(cert),
    }


async def _handshake(address: str, port: int, host: str, ctx: ssl.SSLContext, timeout: float):
    _reader, writer = await asyncio.wait_for(
        asyncio.open_connection(
            address, port, ssl=ctx, server_hostname=host, ssl_handshake_timeout=timeout
        ),
        timeout,
    )
    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        der = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
        cipher = ssl_obj.cipher() if ssl_obj else None
        return der, ssl_obj.version() if ssl_obj else None, cipher[0] if cipher else None
    finally:
        writer.close()
        with contextlib.suppress(TimeoutError, OSError, ssl.SSLError):
            await asyncio.wait_for(writer.wait_closed(), 1.0)


async def collect_tls(
    guard: NetGuard,
    host: str,
    *,
    port: int = 443,
    timeout: float = 10.0,
    verify_context: ssl.SSLContext | None = None,
) -> dict:
    """Raises TlsCollectError (or a netguard error) when nothing was collected."""
    if guard.lab_mode:
        raise TlsCollectError("lab_transport_unavailable")
    target = await guard.validate(f"https://{host}:{port}/" if port != 443 else f"https://{host}/")
    address = target.addresses[0]
    try:
        der, version, cipher = await _handshake(address, port, host, unverified_context(), timeout)
    except TimeoutError as e:
        raise TlsCollectError("timeout", f"{address}:{port}") from e
    except ssl.SSLError as e:
        raise TlsCollectError("handshake_failed", str(e)[:300]) from e
    except OSError as e:
        raise TlsCollectError("connect_error", str(e)[:300]) from e
    if not der:
        raise TlsCollectError("no_certificate")
    try:
        cert = parse_certificate(der)
    except ValueError as e:
        raise TlsCollectError("unparseable_certificate", str(e)[:300]) from e

    ctx = verify_context or verified_context()
    try:
        await _handshake(address, port, host, ctx, timeout)
        passes, error = True, None
    except ssl.SSLCertVerificationError as e:
        passes, error = False, (e.verify_message or str(e))[:300]
    except (ssl.SSLError, OSError, TimeoutError) as e:
        passes, error = None, f"verification handshake failed: {type(e).__name__}"
    return {
        "host": host,
        "address": address,
        "port": port,
        "tls_version": version,
        "cipher": cipher,
        "certificate": cert,
        "verification_passes": passes,
        "verification_error": error,
    }

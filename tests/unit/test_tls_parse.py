"""DER certificate parsing for TLS facts (U10)."""

import pytest
from tests.security.harness import make_cert

from brandsentinel.enrich.tls import parse_certificate


def test_self_signed_certificate_fields():
    pair, _, _ = make_cert("evil.example", ["evil.example", "*.evil.example", "sadhguru.org"])
    c = parse_certificate(pair.der)
    assert c["self_signed"] and c["subject"] == c["issuer"] == "CN=evil.example"
    assert c["san_dns"] == ["evil.example", "*.evil.example", "sadhguru.org"]
    assert c["public_key"] == {"type": "ec", "curve": "secp256r1"}
    assert c["validity_days"] == 31 and len(c["sha256"]) == 64 and c["is_ca"] is False


def test_ca_signed_certificate_is_not_self_signed():
    _, ca, key = make_cert("Test CA", [], ca=True)
    pair, _, _ = make_cert("leaf.example", ["leaf.example"], issuer=(ca, key))
    c = parse_certificate(pair.der)
    assert not c["self_signed"] and c["issuer"] == "CN=Test CA"


def test_certificate_without_sans():
    pair, _, _ = make_cert("nosan.example", [])
    assert parse_certificate(pair.der)["san_dns"] == []


@pytest.mark.parametrize("der", [b"", b"\x30\x03\x02\x01\x01", b"not a certificate" * 10])
def test_garbage_der_is_rejected(der):
    with pytest.raises(ValueError):
        parse_certificate(der)

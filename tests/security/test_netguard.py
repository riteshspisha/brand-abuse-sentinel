"""netguard: one network policy for every connection to an untrusted host (U8, AE8)."""

import asyncio
import ipaddress

import pytest

from brandsentinel.config import Config, ConfigError, LabSettings, NetSettings, load_config
from brandsentinel.net.netguard import (
    NetGuard,
    PolicyViolation,
    ResolutionFailed,
    StaticResolver,
    classify_ip,
    parse_url,
)

pytestmark = pytest.mark.security

LAB_HOST = "donate.lumina.lab"


def guard(answers: dict, **kw) -> NetGuard:
    return NetGuard(NetSettings(**kw.pop("settings", {})), StaticResolver(answers), **kw)


def validate(g: NetGuard, url: str):
    return asyncio.run(g.validate(url))


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("10.0.0.5", "private"),
        ("172.16.0.1", "private"),
        ("192.168.1.1", "private"),
        ("127.0.0.1", "loopback"),
        ("169.254.169.254", "link_local"),
        ("100.64.1.1", "cgnat"),
        ("0.0.0.0", "unspecified"),  # noqa: S104 - an address under test, not a bind
        ("255.255.255.255", "broadcast"),
        ("224.0.0.1", "multicast"),
        ("192.0.2.1", "documentation"),
        ("198.18.0.1", "benchmarking"),
        ("240.0.0.1", "reserved"),
        ("::1", "loopback"),
        ("::", "unspecified"),
        ("fd00::1", "unique_local"),
        ("fe80::1", "link_local"),
        ("fec0::1", "site_local"),
        ("ff02::1", "multicast"),
        ("2001:db8::1", "documentation"),
        ("::ffff:127.0.0.1", "ipv4_mapped:loopback"),
        ("::ffff:169.254.169.254", "ipv4_mapped:link_local"),
        ("::127.0.0.1", "ipv4_compatible:loopback"),
        ("64:ff9b::a00:1", "nat64:private"),
        ("64:ff9b::7f00:1", "nat64:loopback"),
        ("64:ff9b:1::1", "nat64_local"),
        ("2002:7f00:1::1", "6to4:loopback"),
        ("2002:808:808::1", "6to4"),
        ("2001:0:4136:e378::1", "teredo"),
        ("::ffff:0:7f00:1", "ipv4_translated:loopback"),
        ("::ffff:0:a00:5", "ipv4_translated:private"),
        ("::ffff:0:808:808", "ipv4_translated"),
    ],
)
def test_non_public_addresses_are_classified(address, expected):
    assert classify_ip(ipaddress.ip_address(address)) == expected


@pytest.mark.parametrize(
    "address", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "64:ff9b::808:808"]
)
def test_public_addresses_are_allowed(address):
    assert classify_ip(ipaddress.ip_address(address)) is None


@pytest.mark.parametrize(
    ("address", "cls"),
    [
        ("10.0.0.5", "private"),
        ("127.0.0.1", "loopback"),
        ("169.254.169.254", "link_local"),
        ("100.64.1.1", "cgnat"),
        ("::1", "loopback"),
        ("fd00::1", "unique_local"),
        ("::ffff:127.0.0.1", "ipv4_mapped:loopback"),
        ("64:ff9b::a00:1", "nat64:private"),
    ],
)
def test_hostname_resolving_to_a_blocked_address_is_refused(address, cls):
    # Covers AE8.
    g = guard({"evil.example": [address]})
    with pytest.raises(PolicyViolation) as e:
        validate(g, "https://evil.example/")
    assert e.value.reason == "blocked_address"
    assert e.value.detail["class"] == cls


def test_mixed_public_and_private_answers_are_refused():
    g = guard({"mixed.example": ["93.184.215.14", "10.0.0.5"]})
    with pytest.raises(PolicyViolation) as e:
        validate(g, "http://mixed.example/")
    assert e.value.reason == "dns_mixed_private"
    assert e.value.detail["blocked"] == [{"ip": "10.0.0.5", "class": "private"}]


def test_public_answers_yield_a_pinned_target():
    g = guard({"ok.example": ["2606:4700::1", "93.184.215.14"]})
    v = validate(g, "https://OK.example./a b?q=\u00fc#frag")
    assert v.host == "ok.example" and v.port == 443 and v.scheme == "https"
    assert v.addresses == ("93.184.215.14", "2606:4700::1")  # IPv4 first by default
    assert v.target == "/a%20b?q=%C3%BC"
    assert v.url == "https://ok.example/a%20b?q=%C3%BC"


@pytest.mark.parametrize(
    ("url", "cls"),
    [
        ("http://2130706433/", "loopback"),
        ("http://0x7f.1/", "loopback"),
        ("http://0177.0.0.1/", "loopback"),
        ("http://127.1/", "loopback"),
        ("http://[::]/", "unspecified"),
        ("http://[::ffff:7f00:1]/", "ipv4_mapped:loopback"),
        ("http://169.254.169.254/latest/meta-data/", "link_local"),
        ("http://[fe80::1%25eth0]/", None),  # zone ids are refused as invalid
    ],
)
def test_ip_literal_tricks_are_refused(url, cls):
    g = guard({})
    with pytest.raises(PolicyViolation) as e:
        validate(g, url)
    if cls is None:
        assert e.value.reason == "invalid_url"
    else:
        assert e.value.reason == "blocked_address" and e.value.detail["class"] == cls


def test_public_ip_literal_needs_no_dns():
    v = validate(guard({}), "http://93.184.215.14/x")
    assert v.addresses == ("93.184.215.14",) and v.ip_literal


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/",
        "file:///etc/passwd",
        "gopher://example.com/",
        "javascript:alert(1)",
        "data:text/html,hi",
        "//example.com/",
    ],
)
def test_non_http_schemes_are_refused(url):
    with pytest.raises(PolicyViolation) as e:
        parse_url(url, allowed_ports=(80, 443))
    assert e.value.reason == "scheme_not_allowed"


def test_port_outside_the_allowlist_is_refused_unless_configured():
    with pytest.raises(PolicyViolation) as e:
        parse_url("http://example.com:8080/", allowed_ports=(80, 443))
    assert e.value.reason == "port_not_allowed"
    assert parse_url("http://example.com:8080/", allowed_ports=(80, 443, 8080)).port == 8080
    with pytest.raises(PolicyViolation):
        parse_url("https://example.com:0/", allowed_ports=(80, 443))


@pytest.mark.parametrize(
    "url", ["http://user:pw@example.com/", "http://user@example.com/", "http://@example.com/"]
)
def test_userinfo_is_refused(url):
    with pytest.raises(PolicyViolation) as e:
        parse_url(url, allowed_ports=(80, 443))
    assert e.value.reason == "userinfo_not_allowed"


@pytest.mark.parametrize(
    "url",
    [
        "http://evil.com\\@127.0.0.1/",
        "http://exa mple.com/",
        "http://example.com\x00.evil/",
        "http://%31%32%37.0.0.1/",
        "http://[::1/",
        "http://example.com:99999/",
        "http:///path",
        "http://" + "a" * 300 + ".com/",
        "http://1.2.3.4.5/",
        "http://0x100000000/",
    ],
)
def test_malformed_urls_are_refused(url):
    with pytest.raises(PolicyViolation) as e:
        parse_url(url, allowed_ports=(80, 443))
    assert e.value.reason in ("invalid_url", "userinfo_not_allowed", "port_not_allowed")


def test_idn_hostnames_are_normalized():
    t = parse_url("https://sadhgur\u00fc.com/", allowed_ports=(443,))
    assert t.host == "xn--sadhgur-t2a.com"


def test_resolution_failures_are_reported_not_allowed():
    g = guard({"gone.example": ResolutionFailed("dns_nxdomain", {"name": "gone.example"})})
    with pytest.raises(ResolutionFailed) as e:
        validate(g, "https://gone.example/")
    assert e.value.reason == "dns_nxdomain"
    with pytest.raises(ResolutionFailed) as e:
        validate(guard({"empty.example": []}), "https://empty.example/")
    assert e.value.reason == "dns_no_address"


# --- lab mode (KTD13) ----------------------------------------------------------


def lab_guard(enabled: bool) -> NetGuard:
    lab = LabSettings(enabled=enabled, hosts={LAB_HOST: "172.31.250.10"} if enabled else {})
    resolver = StaticResolver({LAB_HOST: ["172.31.250.10"]})  # what a leaky resolver might say
    return NetGuard(NetSettings(lab=lab), resolver)


def test_lab_mode_allows_only_the_lab_subnet_for_lab_hosts():
    g = lab_guard(True)
    v = validate(g, f"http://{LAB_HOST}/")
    assert v.addresses == ("172.31.250.10",) and v.lab
    for url in ("http://169.254.169.254/", "http://127.0.0.1/", "http://10.0.0.5/"):
        with pytest.raises(PolicyViolation):
            validate(g, url)


def test_lab_subnet_literal_is_refused_even_in_lab_mode_unless_a_lab_host():
    with pytest.raises(PolicyViolation):
        validate(lab_guard(True), "http://172.31.250.10/")


def test_lab_host_is_refused_when_lab_mode_is_off():
    with pytest.raises(PolicyViolation) as e:
        validate(lab_guard(False), f"http://{LAB_HOST}/")
    assert e.value.detail["class"] == "private"


def test_lab_config_with_another_subnet_fails_validation():
    with pytest.raises(ValueError):
        LabSettings(enabled=True, subnet="10.0.0.0/8")
    with pytest.raises(ValueError):
        LabSettings(enabled=True, hosts={LAB_HOST: "10.0.0.5"})


def test_lab_mode_with_live_discovery_fails_validation():
    with pytest.raises(ValueError, match="lab mode"):
        Config(net={"lab": {"enabled": True}})
    Config(
        net={"lab": {"enabled": True}},
        discovery={"certstream": {"enabled": False}, "dnstwist": {"enabled": False}},
    )


def test_test_address_ranges_cannot_come_from_config_or_environment(tmp_path, monkeypatch):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("net:\n  test_networks: ['127.0.0.0/8']\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(cfg)
    monkeypatch.setenv("BRANDSENTINEL_TEST_NETWORKS", "127.0.0.0/8")
    with pytest.raises(ConfigError, match="BRANDSENTINEL_TEST_NETWORKS"):
        load_config(None)


def test_test_networks_are_a_constructor_argument_only():
    g = guard(
        {"harness.test": ["127.77.0.1"]}, test_networks=[ipaddress.ip_network("127.77.0.0/16")]
    )
    assert validate(g, "http://harness.test/").addresses == ("127.77.0.1",)
    with pytest.raises(PolicyViolation):  # the rest of loopback stays blocked
        validate(g, "http://127.0.0.1/")

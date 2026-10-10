"""Lab fixtures and container definitions stay consistent (U11, U18, U23).

Offline checks: lab hostnames agree across nginx, config/lab.yaml and every
expected.yaml; the lab config is valid and offline; the overlay merges only in
lab mode; and the compose files keep the hardening and network topology the
Docker suites prove at runtime.
"""

import ipaddress
import re
from pathlib import Path

import pytest
import yaml

from brandsentinel.cli import _overlay
from brandsentinel.config import LAB_SUBNET, Config, load_config
from brandsentinel.matching.normalize import registrable_domain
from brandsentinel.registry.loader import RegistryError, load_registry

REPO = Path(__file__).parents[2]
LAB = REPO / "labsites"
SITES = {p.parent.name: yaml.safe_load(p.read_text()) for p in LAB.glob("*/expected.yaml")}


def nginx_hosts() -> dict[str, str]:
    """server_name -> root (or the cloaking variable) from labsites/nginx.conf."""
    conf = (LAB / "nginx.conf").read_text()
    out = {}
    for block in re.findall(r"server \{(.*?)\n    \}", conf, re.S):
        name = re.search(r"server_name ([^;]+);", block).group(1)
        root = re.search(r"root ([^;]+);", block)
        if name != "_":
            out[name] = root.group(1) if root else None
    return out


def compose(name: str) -> dict:
    return yaml.safe_load((REPO / "docker" / name).read_text())


def test_every_site_has_an_expected_file_and_page():
    dirs = {p.name for p in LAB.iterdir() if p.is_dir()}
    assert dirs == set(SITES)
    for site, doc in SITES.items():
        assert doc["site"] == site and doc["url"] == f"http://{doc['hostname']}/"
        assert {"category", "priority", "labels", "evidence"} <= set(doc["expected"])
        assert doc["detected_by"] in ("static", "media", "browser")
        pages = list((LAB / site).rglob("index.html"))
        assert pages, site


def test_hostnames_agree_across_nginx_lab_config_and_expected_files():
    config = load_config(REPO / "config" / "lab.yaml")
    expected = {doc["hostname"] for doc in SITES.values()}
    assert set(nginx_hosts()) == expected == set(config.net.lab.hosts)
    web_ip = compose("lab.compose.yaml")["services"]["lab-web"]["networks"]["bs_lab"]
    assert set(config.net.lab.hosts.values()) == {web_ip["ipv4_address"]}


def test_nginx_roots_point_at_site_directories():
    for host, root in nginx_hosts().items():
        if root == "$cloak_root":
            continue
        assert (LAB / Path(root).name).is_dir(), host


def test_lab_hostnames_are_reserved_test_names_with_registrable_domains():
    for doc in SITES.values():
        host = doc["hostname"]
        assert host.endswith(".test") and registrable_domain(host) == host


def test_lab_pages_load_nothing_from_the_internet_except_the_marked_fixture():
    external = re.compile(r"""(?:src|href)=["']https?://(?!([a-z0-9-]+\.)*[a-z0-9-]+\.test[/"'])""")
    offenders = []
    for page in LAB.rglob("*.html"):
        for _ in external.finditer(page.read_text()):
            offenders.append(page.relative_to(LAB).as_posix())
    # The yoga studio's Stripe tag is a static indicator; the offline lab never loads it.
    assert offenders == ["unrelated-yoga/index.html"]


def test_lab_config_is_offline_and_lab_only():
    config = load_config(REPO / "config" / "lab.yaml")
    assert config.net.lab.enabled and config.proxy.lab_only
    assert not config.discovery.certstream.enabled and not config.discovery.dnstwist.enabled
    assert config.data_dir != Config().data_dir  # lab data never mixes with production
    assert config.sandbox.lab_proxy_url == "http://127.0.0.1:3129"


def test_lab_overlay_merges_only_in_lab_mode():
    lab = load_config(REPO / "config" / "lab.yaml")
    assert _overlay(lab) == Path("registry/lab-overlay.yaml")
    assert _overlay(Config()) is None
    registry, _ = load_registry(REPO / "registry/brands.yaml", REPO / "registry/lab-overlay.yaml")
    assert "lumina-foundation" in {b.id for b in registry.brands}
    plain, _ = load_registry(REPO / "registry/brands.yaml")
    assert "lumina-foundation" not in {b.id for b in plain.brands}


def test_overlay_cannot_replace_production_entries(tmp_path):
    data = yaml.safe_load((REPO / "registry/brands.yaml").read_text())
    overlay = tmp_path / "overlay.yaml"
    overlay.write_text(yaml.safe_dump({"version": 1, "brands": [data["brands"][0]]}))
    with pytest.raises(RegistryError, match="duplicate brand id"):
        load_registry(REPO / "registry/brands.yaml", overlay)


def test_lab_network_subnet_is_the_pinned_one():
    nets = compose("lab.compose.yaml")["networks"]
    assert nets["bs_lab"]["internal"] is True
    assert nets["bs_lab"]["ipam"]["config"][0]["subnet"] == LAB_SUBNET
    assert ipaddress.ip_network(nets["bs_lab_edge"]["ipam"]["config"][0]["subnet"])


HARDENING = {"read_only": True, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"]}


@pytest.mark.parametrize(
    ("file", "service"),
    [
        ("compose.yaml", "egress-proxy"),
        ("lab.compose.yaml", "lab-proxy"),
        ("lab.compose.yaml", "lab-web"),
    ],
)
def test_long_running_containers_are_hardened(file, service):
    svc = compose(file)["services"][service]
    for key, value in HARDENING.items():
        assert svc[key] == value, (service, key)
    assert svc["mem_limit"] and svc["pids_limit"] and svc["cpus"]
    assert all(v.endswith(":ro") for v in svc.get("volumes", []))
    assert svc.get("privileged") is not True and "cap_add" not in svc
    assert "network_mode" not in svc
    for port in svc.get("ports", []):
        assert port.startswith("127.0.0.1:"), port


def test_sandbox_network_is_internal_and_the_proxy_bridges_it():
    c = compose("compose.yaml")
    assert c["networks"]["bs_sandbox"]["internal"] is True
    assert c["networks"]["bs_sandbox"]["enable_ipv6"] is False
    proxy = c["services"]["egress-proxy"]
    assert set(proxy["networks"]) == {"bs_sandbox", "bs_egress"}
    listen = proxy["command"][proxy["command"].index("--listen") + 1]
    assert listen == f"{proxy['networks']['bs_sandbox']['ipv4_address']}:3128"
    assert "ports" not in proxy
    settings = Config().sandbox
    assert settings.proxy_url == f"http://{listen}"
    assert proxy["container_name"] == settings.proxy_container


def test_lab_proxy_reads_only_the_lab_config():
    proxy = compose("lab.compose.yaml")["services"]["lab-proxy"]
    assert proxy["volumes"] == ["../config/lab.yaml:/etc/brandsentinel/lab.yaml:ro"]
    assert "/etc/brandsentinel/lab.yaml" in proxy["command"]
    assert "bs_sandbox" not in proxy["networks"] and "bs_egress" not in proxy["networks"]

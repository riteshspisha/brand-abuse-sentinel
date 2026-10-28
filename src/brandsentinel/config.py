"""Configuration: one YAML file validated by pydantic.

Unknown keys are rejected so a typo never silently falls back to a default.
Environment variables may override paths only.
"""

import ipaddress
import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PositiveFloat,
    ValidationError,
    field_validator,
    model_validator,
)

ENV_CONFIG = "BRANDSENTINEL_CONFIG"
ENV_DATA_DIR = "BRANDSENTINEL_DATA_DIR"
_KNOWN_ENV = frozenset({ENV_CONFIG, ENV_DATA_DIR})

# The lab network's subnet is pinned in docker/compose.yaml (KTD13). Lab mode may
# add exactly this subnet to the network policy and nothing else.
LAB_SUBNET = "172.31.250.0/24"
# Lab-mode sandboxes (M7) join only this internal network, pinned in
# docker/lab.compose.yaml, whose one long-running member is a lab-only proxy that
# also sits on the lab network. It is a transport hop, never a fetch target:
# netguard's lab exception stays LAB_SUBNET alone.
LAB_SANDBOX_NETWORK = "bs_lab_sandbox"
LAB_SANDBOX_SUBNET = "172.31.254.0/24"
LAB_SANDBOX_PROXY = "bs-lab-sandbox-proxy"
LAB_SANDBOX_PROXY_URL = "http://172.31.254.2:3128"

STAGES = ("enrich", "fetch", "media", "render", "decision")

MiB = 1024 * 1024
GiB = 1024 * MiB


class ConfigError(Exception):
    """Configuration file missing, unreadable, or invalid."""


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class StageLimits(_Section):
    """Maximum concurrent jobs per pipeline stage."""

    enrich: int = Field(8, ge=1)
    fetch: int = Field(4, ge=1)
    media: int = Field(2, ge=1)
    render: int = Field(1, ge=1)
    decision: int = Field(1, ge=1)
    # Jobs of one registrable domain that may run at once in a stage, so one
    # domain with many subdomains cannot occupy every worker.
    per_domain_enrich: int = Field(2, ge=1)
    per_domain_fetch: int = Field(1, ge=1)


class JobSettings(_Section):
    max_attempts: int = Field(3, ge=1)
    # A lease must outlive the stage's maximum wall time; long jobs renew it.
    lease_seconds: dict[str, PositiveFloat] = Field(
        default_factory=lambda: {
            "enrich": 120.0,
            "fetch": 120.0,
            "media": 180.0,
            "render": 300.0,
            "decision": 120.0,
        }
    )
    default_lease_seconds: float = Field(300.0, gt=0)

    @field_validator("lease_seconds")
    @classmethod
    def _known_stages(cls, value: dict[str, float]) -> dict[str, float]:
        unknown = sorted(set(value) - set(STAGES))
        if unknown:
            raise ValueError(f"unknown stage(s) {unknown}; expected some of {list(STAGES)}")
        return value

    def lease_for(self, stage: str) -> float:
        return self.lease_seconds.get(stage, self.default_lease_seconds)


class ArtifactQuotas(_Section):
    max_blob_bytes: int = Field(10 * MiB, gt=0)
    max_case_count: int = Field(200, gt=0)
    max_case_bytes: int = Field(50 * MiB, gt=0)
    max_domain_bytes: int = Field(200 * MiB, gt=0)
    max_store_bytes: int = Field(2 * GiB, gt=0)
    # Share of the store kept free for strong-strength and manual cases.
    reserve_fraction: float = Field(0.1, ge=0, lt=1)


class FirehoseSettings(_Section):
    """Optional storage of the unmatched CertStream feed. Off by default."""

    enabled: bool = False
    max_total_bytes: int = Field(2 * GiB, gt=0)
    max_age_days: int = Field(7, gt=0)


class RawLogSettings(_Section):
    flush_every_records: int = Field(100, ge=1)
    discovery_rotation: Literal["hour", "day"] = "day"
    # Discovery log segments and discovery event rows older than this are pruned.
    discovery_max_age_days: int = Field(365, gt=0)
    # Below this much free disk the firehose pauses; discovery logging continues.
    min_free_bytes: int = Field(1 * GiB, ge=0)
    firehose: FirehoseSettings = FirehoseSettings()


class CertStreamSettings(_Section):
    enabled: bool = True
    # certstream-server-go full stream (docker/compose.yaml, profile certstream).
    url: str = "ws://localhost:8080/full-stream"
    ping_interval_seconds: float = Field(30.0, gt=0)  # the server requires client pings
    open_timeout_seconds: float = Field(15.0, gt=0)
    max_message_bytes: int = Field(4 * MiB, gt=0)
    backoff_initial_seconds: float = Field(1.0, gt=0)
    backoff_max_seconds: float = Field(60.0, gt=0)
    # Recently seen certificate fingerprints kept in memory to skip duplicates
    # cheaply; persistence is idempotent regardless.
    dedupe_cache_size: int = Field(100_000, ge=1)
    max_names_per_cert: int = Field(1000, ge=1, le=1000)
    stale_after_seconds: float = Field(300.0, gt=0)

    @field_validator("url")
    @classmethod
    def _websocket_url(cls, v: str) -> str:
        if not v.startswith(("ws://", "wss://")):
            raise ValueError("must be a ws:// or wss:// URL")
        return v


class DnstwistSettings(_Section):
    enabled: bool = True
    # Executable name or path; a bare name is looked up next to the running
    # Python first, then on PATH.
    binary: str = "dnstwist"
    dictionary: Path | None = Path("registry/dictionaries/brand-words.dict")
    interval_hours: float = Field(24.0, gt=0)
    # Failed or abandoned sweeps retry after this, if shorter than the interval.
    retry_hours: float = Field(1.0, gt=0)
    threads: int = Field(8, ge=1, le=64)
    # The sweep timeout is floor + permutations / rate, capped at max.
    resolution_rate_per_second: float = Field(20.0, gt=0)
    timeout_floor_seconds: float = Field(120.0, gt=0)
    timeout_max_seconds: float = Field(4 * 3600.0, gt=0)
    count_timeout_seconds: float = Field(60.0, gt=0)
    max_permutations: int = Field(100_000, ge=1)
    max_output_bytes: int = Field(64 * MiB, gt=0)


class DiscoverySettings(_Section):
    certstream: CertStreamSettings = CertStreamSettings()
    dnstwist: DnstwistSettings = DnstwistSettings()


class SchedulingSettings(_Section):
    """Per-registrable-domain backlog limits (subdomain flooding control).

    A domain may have this many live (pending or running) jobs per stage; further
    work for it is deferred, not dropped, and promoted as its jobs finish.
    Strong-strength work has a larger allowance; manual submissions bypass it."""

    max_queued_per_domain_strong: int = Field(16, ge=1)
    max_queued_per_domain_weak: int = Field(4, ge=1)
    promote_interval_seconds: float = Field(5.0, gt=0)
    promote_batch: int = Field(500, ge=1)
    # Re-run enrichment and the static fetch this many days after first analysis.
    recheck_after_days: list[PositiveFloat] = Field(default_factory=lambda: [1.0, 7.0])


class DnsSettings(_Section):
    # Empty: the system resolver configuration (/etc/resolv.conf).
    nameservers: list[str] = []
    timeout_seconds: float = Field(3.0, gt=0)  # per query attempt
    lifetime_seconds: float = Field(6.0, gt=0)  # per name and record type

    @field_validator("nameservers")
    @classmethod
    def _ips(cls, v: list[str]) -> list[str]:
        for ns in v:
            ipaddress.ip_address(ns)
        return v


class LabSettings(_Section):
    """Lab mode (KTD13): adds exactly the pinned lab subnet and a hostname map."""

    enabled: bool = False
    subnet: str = LAB_SUBNET
    hosts: dict[str, str] = {}
    # Synthetic lab brand, merged into the registry only in lab mode.
    registry_overlay: Path = Path("registry/lab-overlay.yaml")

    @model_validator(mode="after")
    def _pinned(self):
        if self.subnet != LAB_SUBNET:
            raise ValueError(f"lab subnet must be {LAB_SUBNET}")
        net = ipaddress.ip_network(LAB_SUBNET)
        for name, ip in self.hosts.items():
            if ipaddress.ip_address(ip) not in net:
                raise ValueError(f"lab host {name!r} address {ip} is outside {LAB_SUBNET}")
        return self


class NetSettings(_Section):
    """Network policy for every connection to untrusted hosts (netguard)."""

    allowed_ports: list[int] = Field(default_factory=lambda: [80, 443])
    prefer_ipv6: bool = False
    dns: DnsSettings = DnsSettings()
    lab: LabSettings = LabSettings()

    @field_validator("allowed_ports")
    @classmethod
    def _ports(cls, v: list[int]) -> list[int]:
        if not v or any(not 0 < p < 65536 for p in v):
            raise ValueError("ports must be in 1..65535 and the list non-empty")
        return v


class FetchSettings(_Section):
    """Hardened static fetcher (U9)."""

    enabled: bool = True
    user_agent: str = "BrandSentinel/0.1 (brand-protection research)"
    max_redirects: int = Field(5, ge=0, le=10)
    connect_timeout_seconds: float = Field(10.0, gt=0)
    read_timeout_seconds: float = Field(15.0, gt=0)
    total_timeout_seconds: float = Field(30.0, gt=0)  # whole fetch, all hops
    max_raw_bytes: int = Field(5 * MiB, gt=0)  # bytes read from the wire
    max_decoded_bytes: int = Field(10 * MiB, gt=0)  # after decompression
    max_addresses_tried: int = Field(2, ge=1, le=8)
    accept_types: list[str] = Field(
        default_factory=lambda: ["text/html", "application/xhtml+xml", "text/plain"]
    )
    # Delay before retrying a transient failure (connect error, timeout).
    retry_delay_seconds: float = Field(300.0, ge=0)


class EnrichSettings(_Section):
    """Passive enrichment (U10)."""

    enabled: bool = True
    rdap_bootstrap_url: str = "https://data.iana.org/rdap/dns.json"
    rdap_bootstrap_max_age_days: float = Field(7.0, gt=0)
    rdap_max_bytes: int = Field(512 * 1024, gt=0)
    # RDAP describes the registrable domain, so subdomains share one lookup.
    rdap_cache_hours: float = Field(24.0, ge=0)
    tls_timeout_seconds: float = Field(10.0, gt=0)

    @field_validator("rdap_bootstrap_url")
    @classmethod
    def _https(cls, v: str) -> str:
        if not v.startswith("https://"):
            raise ValueError("must be an https:// URL")
        return v


class AnalysisSettings(_Section):
    """Static detection and triage (M5)."""

    # Payment provider catalog read by the payment extractor.
    payment_providers: Path = Path("config/payment_providers.yaml")
    # Policy points and thresholds (U14).
    policy: Path = Path("config/policy.yaml")


class RuntimeSettings(_Section):
    """The account and container runtime the application runs under (U23, R50)."""

    # Rootless Docker endpoint of the service account. Empty: the account's
    # default rootless socket, unix://$XDG_RUNTIME_DIR/docker.sock.
    docker_host: str = ""
    docker_binary: str = "docker"
    # Development only: lets the application run as the account that owns its
    # code and that can reach a rootful Docker socket. `status` warns while set.
    allow_developer_account: bool = False

    @field_validator("docker_host")
    @classmethod
    def _unix_only(cls, v: str) -> str:
        # A TCP endpoint would expose the daemon to anything that can reach it.
        if v and not v.startswith("unix:///"):
            raise ValueError("must be empty or a unix:/// socket path")
        return v


class SandboxLimits(_Section):
    """Resource limits for one sandbox container, enforced by the runtime."""

    memory_mb: int = Field(512, ge=32)
    cpus: float = Field(1.0, gt=0, le=16)
    pids: int = Field(128, ge=8, le=4096)
    wall_seconds: float = Field(60.0, gt=0, le=3600)
    tmpfs_mb: int = Field(64, ge=1, le=1024)
    shm_mb: int = Field(64, ge=1, le=2048)
    stdout_max_bytes: int = Field(16 * MiB, gt=0, le=256 * MiB)
    stderr_max_bytes: int = Field(64 * 1024, gt=0, le=16 * MiB)


class SandboxSettings(_Section):
    """Sandbox containers (U23) and their networks (U18)."""

    enabled: bool = True
    # Separates containers of several BrandSentinel instances on one runtime.
    instance: str = Field("main", pattern=r"^[a-z0-9]{1,16}$")
    image: str = "brandsentinel-sandbox:local"
    # Pinned in docker/compose.yaml: internal (no route out) and egress subnets.
    network: str = "bs_sandbox"
    proxy_url: str = "http://172.31.251.2:3128"
    proxy_container: str = "bs-egress-proxy"
    # Host-side transport to the lab proxy's loopback-published port (KTD13).
    lab_proxy_url: str = "http://127.0.0.1:3129"
    limits: SandboxLimits = SandboxLimits()
    # Grace after `docker kill` for the container and CLI to exit.
    kill_grace_seconds: float = Field(10.0, gt=0)

    @field_validator("proxy_url", "lab_proxy_url")
    @classmethod
    def _http_ip_url(cls, v: str) -> str:
        from urllib.parse import urlsplit

        parts = urlsplit(v)
        if parts.scheme != "http" or parts.path not in ("", "/") or not parts.port:
            raise ValueError("must be http://<ip>:<port>")
        ipaddress.ip_address(parts.hostname or "")  # no DNS for the proxy hop
        return v


def _media_limits() -> SandboxLimits:
    return SandboxLimits(
        memory_mb=512,
        cpus=1.0,
        pids=64,
        wall_seconds=90.0,
        tmpfs_mb=64,  # Tesseract's temporary image files
        shm_mb=16,
        stdout_max_bytes=2 * MiB,
        stderr_max_bytes=64 * 1024,
    )


class MediaMatching(_Section):
    """Visual matching against the reference corpus (U17)."""

    # A perceptual match needs both hashes within these Hamming distances (of 64).
    phash_max_distance: int = Field(10, ge=0, le=32)
    dhash_max_distance: int = Field(8, ge=0, le=32)
    # Images flatter than this (grayscale standard deviation, 0-255) carry too
    # little structure for a perceptual hash; they match only by exact hash.
    min_luma_stddev: float = Field(12.0, ge=0, le=128)
    # Width/height ratios of candidate and reference may differ by at most this factor.
    max_aspect_ratio_factor: float = Field(1.35, ge=1.0, le=4.0)


class MediaSettings(_Section):
    """Untrusted image collection and the media sandbox worker (U16, R21, R42)."""

    enabled: bool = True
    # Images of one case collected and analyzed per analysis round.
    max_images_per_case: int = Field(8, ge=1, le=32)
    max_image_bytes: int = Field(2 * MiB, gt=0, le=16 * MiB)
    # All images sent to one worker container together (before base64).
    max_batch_bytes: int = Field(12 * MiB, gt=0, le=64 * MiB)
    # Checked from the image header, before any pixel is decoded.
    max_pixels: int = Field(16_000_000, ge=1, le=100_000_000)
    max_dimension: int = Field(8192, ge=16, le=65535)
    max_frames: int = Field(32, ge=1, le=1000)  # animated GIF and WebP
    max_ico_images: int = Field(16, ge=1, le=256)
    ocr: bool = True
    # Larger images are downscaled before OCR and QR decoding.
    max_ocr_pixels: int = Field(4_000_000, ge=10_000, le=40_000_000)
    ocr_timeout_seconds: float = Field(20.0, gt=0, le=300)
    max_ocr_chars: int = Field(4000, ge=1, le=100_000)
    max_qr_codes: int = Field(8, ge=0, le=64)
    max_qr_chars: int = Field(2048, ge=1, le=16_384)
    # Wall-clock budget for fetching one case's images (each fetch is also
    # bounded by the fetcher's own timeouts).
    collect_timeout_seconds: float = Field(60.0, gt=0, le=1800)
    # Content types kept by the image fetch. The worker decides by magic bytes,
    # so a mislabelled body is still checked, never trusted.
    accept_types: list[str] = Field(
        default_factory=lambda: [
            "image/png",
            "image/jpeg",
            "image/gif",
            "image/webp",
            "image/x-icon",
            "image/vnd.microsoft.icon",
            "application/octet-stream",
        ]
    )
    limits: SandboxLimits = Field(default_factory=_media_limits)
    matching: MediaMatching = MediaMatching()

    @model_validator(mode="after")
    def _consistent(self):
        if self.max_batch_bytes < self.max_image_bytes:
            raise ValueError("max_batch_bytes must be at least max_image_bytes")
        if any(t.startswith(("text/", "image/svg")) for t in self.accept_types):
            raise ValueError("accept_types are raster image types only")
        return self


def _browser_limits() -> SandboxLimits:
    return SandboxLimits(
        memory_mb=1536,
        cpus=2.0,
        pids=512,  # Chromium's processes and threads
        wall_seconds=60.0,
        tmpfs_mb=256,  # the throwaway browser profile
        shm_mb=256,
        stdout_max_bytes=12 * MiB,  # rendered HTML and the screenshot, base64
        stderr_max_bytes=256 * 1024,
    )


class BrowserSettings(_Section):
    """Isolated browser rendering (U19, KTD9, KTD23). The browser container joins
    only the sandbox network (lab mode: the lab sandbox network); its proxy is the
    only way out, and the network check must pass before any page is rendered."""

    enabled: bool = True
    # Share of strong-strength cases rendered without another trigger (KTD23).
    sample_rate: float = Field(0.1, ge=0.0, le=1.0)
    # A brand-matching page with less visible static text than this renders.
    little_text_chars: int = Field(200, ge=0, le=100_000)
    viewport_width: int = Field(1280, ge=320, le=1920)
    viewport_height: int = Field(800, ge=240, le=1920)
    navigation_timeout_seconds: float = Field(20.0, gt=0, le=600)
    # After the load event, how long to wait for the network to go idle.
    settle_seconds: float = Field(8.0, ge=0, le=600)
    max_html_bytes: int = Field(2 * MiB, gt=0, le=8 * MiB)
    max_text_chars: int = Field(50_000, gt=0, le=1_000_000)
    max_requests: int = Field(300, ge=1, le=5000)
    max_forms: int = Field(32, ge=1, le=256)
    max_inputs: int = Field(256, ge=1, le=4096)
    max_screenshot_bytes: int = Field(3 * MiB, gt=0, le=8 * MiB)
    # None: Chromium's own user agent (the cloaking comparison relies on it).
    user_agent: str | None = None
    # The Chromium seccomp profile; None: the one shipped with the package.
    seccomp_profile: Path | None = None
    limits: SandboxLimits = Field(default_factory=_browser_limits)

    @model_validator(mode="after")
    def _fits(self):
        budget = self.navigation_timeout_seconds + self.settle_seconds + 10
        if budget >= self.limits.wall_seconds:
            raise ValueError(
                "navigation_timeout_seconds + settle_seconds + 10 must be under"
                " limits.wall_seconds, so the worker reports before it is killed"
            )
        b64 = (self.max_html_bytes + self.max_screenshot_bytes) * 4 // 3
        if b64 + self.max_text_chars * 6 + 4 * MiB > self.limits.stdout_max_bytes:
            raise ValueError("limits.stdout_max_bytes is too small for the output caps")
        return self


class ProxySettings(_Section):
    """The egress proxy (U18): the only way out of the sandbox network."""

    max_connections: int = Field(64, ge=1, le=4096)
    # One sandbox (client address) cannot take every slot from the others.
    max_connections_per_client: int = Field(32, ge=1, le=4096)
    max_header_bytes: int = Field(16 * 1024, ge=1024, le=256 * 1024)
    header_timeout_seconds: float = Field(10.0, gt=0)
    connect_timeout_seconds: float = Field(10.0, gt=0)
    idle_timeout_seconds: float = Field(30.0, gt=0)
    total_timeout_seconds: float = Field(120.0, gt=0)  # one tunnel or request, end to end
    max_connection_bytes: int = Field(64 * MiB, gt=0)  # both directions, per connection
    max_addresses_tried: int = Field(2, ge=1, le=8)
    # Lab proxy only: refuse everything but lab hostnames (requires lab mode).
    lab_only: bool = False


class TextSettings(_Section):
    max_fact_chars: int = Field(4096, gt=0)  # per string
    max_fact_bytes: int = Field(256 * 1024, gt=0)  # per serialized fact value


class Config(_Section):
    data_dir: Path = Path("data")
    registry_path: Path = Path("registry/brands.yaml")
    stages: StageLimits = StageLimits()
    jobs: JobSettings = JobSettings()
    artifacts: ArtifactQuotas = ArtifactQuotas()
    rawlog: RawLogSettings = RawLogSettings()
    text: TextSettings = TextSettings()
    discovery: DiscoverySettings = DiscoverySettings()
    scheduling: SchedulingSettings = SchedulingSettings()
    net: NetSettings = NetSettings()
    fetch: FetchSettings = FetchSettings()
    enrich: EnrichSettings = EnrichSettings()
    analysis: AnalysisSettings = AnalysisSettings()
    runtime: RuntimeSettings = RuntimeSettings()
    sandbox: SandboxSettings = SandboxSettings()
    media: MediaSettings = MediaSettings()
    browser: BrowserSettings = BrowserSettings()
    proxy: ProxySettings = ProxySettings()

    @model_validator(mode="after")
    def _lab_is_offline(self):
        d = self.discovery
        if self.net.lab.enabled and (d.certstream.enabled or d.dnstwist.enabled):
            raise ValueError(
                "lab mode requires discovery.certstream.enabled and"
                " discovery.dnstwist.enabled to be false"
            )
        if self.proxy.lab_only and not self.net.lab.enabled:
            raise ValueError("proxy.lab_only requires net.lab.enabled")
        sb = self.sandbox
        lab_side = (sb.network, sb.proxy_url, sb.proxy_container)
        pinned = (LAB_SANDBOX_NETWORK, LAB_SANDBOX_PROXY_URL, LAB_SANDBOX_PROXY)
        if self.net.lab.enabled and sb.enabled and lab_side != pinned:
            # bs_sandbox's proxy reaches the Internet and not the lab; lab-mode
            # sandboxes use only the pinned lab sandbox network and its proxy.
            raise ValueError(
                "lab mode sandboxes need sandbox.network, proxy_url and proxy_container"
                f" = {', '.join(pinned)}"
            )
        if not self.net.lab.enabled and (
            sb.network == LAB_SANDBOX_NETWORK or sb.proxy_container == LAB_SANDBOX_PROXY
        ):
            raise ValueError(f"{LAB_SANDBOX_NETWORK} and its proxy are for lab mode only")
        return self

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "brandsentinel.db"

    @property
    def raw_dir(self) -> Path:
        return self.data_dir / "raw"

    @property
    def artifacts_dir(self) -> Path:
        return self.data_dir / "artifacts"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"


def _format_errors(err: ValidationError) -> str:
    parts = []
    for e in err.errors():
        loc = ".".join(str(p) for p in e["loc"]) or "<root>"
        parts.append(f"{loc}: {e['msg']}")
    return "; ".join(parts)


def load_config(path: Path | None = None) -> Config:
    """Load config from `path`, else $BRANDSENTINEL_CONFIG, else built-in defaults."""
    if path is None and os.environ.get(ENV_CONFIG):
        path = Path(os.environ[ENV_CONFIG])

    raw: dict = {}
    if path is not None:
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        except OSError as e:
            raise ConfigError(f"cannot read config {path}: {e}") from e
        except yaml.YAMLError as e:
            raise ConfigError(f"invalid YAML in {path}: {e}") from e
        if loaded is not None and not isinstance(loaded, dict):
            raise ConfigError(f"config {path} must be a mapping")
        raw = loaded or {}

    # Only paths may come from the environment; anything else that looks like
    # BrandSentinel configuration (for example network ranges) is refused.
    unknown = sorted(
        k for k in os.environ if k.startswith("BRANDSENTINEL_") and k not in _KNOWN_ENV
    )
    if unknown:
        raise ConfigError(f"unsupported environment variable(s): {', '.join(unknown)}")

    if os.environ.get(ENV_DATA_DIR):
        raw = {**raw, "data_dir": os.environ[ENV_DATA_DIR]}

    try:
        return Config.model_validate(raw)
    except ValidationError as e:
        raise ConfigError(f"invalid config: {_format_errors(e)}") from e

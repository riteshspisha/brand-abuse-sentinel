"""Brand Registry data model.

Every entry carries a verification status and provenance. Status decides what an
entry may do: only `confirmed` domains and relationships can suppress findings,
and only `confirmed` payees count as known. `rejected` entries are kept for the
record and otherwise ignored. Cross-entry checks live in `loader.validate`.
"""

import re
from datetime import date
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator, model_validator

Status = Literal["confirmed", "candidate", "legacy-unverified", "rejected"]
Tier = Literal["high", "low"]

_TERM_RE = re.compile(r"^[a-z0-9]+$")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


class _Entry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Provenance(_Entry):
    # Where the entry came from: "legacy/<file>:<line>", a URL, or "maintainer".
    source: str = Field(min_length=1)
    recorded_by: str = Field(min_length=1)
    recorded_at: date
    verified_by: str | None = None
    verified_at: date | None = None
    note: str | None = None


class _Tracked(_Entry):
    status: Status
    provenance: list[Provenance] = Field(min_length=1)

    @model_validator(mode="after")
    def _confirmed_needs_verifier(self):
        if self.status == "confirmed" and not any(
            p.verified_by and p.verified_at for p in self.provenance
        ):
            raise ValueError("a confirmed entry needs verified_by and verified_at in provenance")
        return self

    @property
    def active(self) -> bool:
        return self.status != "rejected"


def _term(value: str) -> str:
    if not _TERM_RE.match(value):
        raise ValueError(f"{value!r} must be lowercase ASCII letters and digits only")
    return value


Term = Annotated[str, AfterValidator(_term)]


class Keyword(_Tracked):
    """A brand term matched against hyphen-folded names.

    `high` tier terms match as substrings; the `low` tier term (`isha`) counts
    only as a whole token, inside an official-domain lookalike, or with brand or
    ecosystem context. `fuzzy` also matches labels within edit distance 2.
    """

    term: Term
    tier: Tier
    fuzzy: bool = False


class Brand(_Tracked):
    id: str
    name: str = Field(min_length=1)
    aliases: list[str] = []
    keywords: list[Keyword] = []

    @field_validator("id")
    @classmethod
    def _check_id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError(f"brand id {v!r} must be lowercase letters, digits and hyphens")
        return v


class ContextTerm(_Tracked):
    """Ecosystem term (yoga, donate, ...) that qualifies a low-tier keyword hit."""

    term: Term


class Exclusion(_Tracked):
    """A word inside which hits of one keyword are cancelled (e.g. odisha for isha)."""

    term: Term
    scope: str  # the keyword term this exclusion applies to


class Domain(_Tracked):
    """A known property. `name` is canonical lowercase ASCII (punycode for IDN)."""

    name: str
    brand: str
    kind: Literal["official", "third_party"] = "official"
    suppresses: bool = False


class Relationship(_Tracked):
    """A typed link between registry entities, written `brand:<id>`,
    `domain:<name>` or `payee:<id>`."""

    from_: str = Field(alias="from")
    to: str
    type: str = Field(min_length=1)

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class PayeeIdentifier(_Entry):
    type: Literal["upi_vpa", "bank_account", "merchant_id", "other"]
    value: str = Field(min_length=1)


class Payee(_Tracked):
    id: str
    name: str = Field(min_length=1)
    brand: str
    identifiers: list[PayeeIdentifier] = []


class ReferencePage(_Tracked):
    """Official page the reference collector may fetch once confirmed (HTTPS only)."""

    url: str
    brand: str

    @field_validator("url")
    @classmethod
    def _https_only(cls, v: str) -> str:
        if not v.startswith("https://"):
            raise ValueError("reference pages must use https://")
        return v


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ASSET_PATH_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*(/[A-Za-z0-9_][A-Za-z0-9_.-]*)*$")


class ReferenceAsset(_Tracked):
    """A brand reference image (U17, R10, R13): a logo, favicon or other image a
    maintainer verified as the brand's own.

    The image is either a file under `registry/assets/` (`path`, curated) or an
    https URL (`url`), which the collector fetches with verified TLS only from a
    confirmed official domain of the brand. `sha256` pins the exact bytes. Only a
    confirmed entry whose content matches its pin enters the reference corpus;
    a changed file or URL is reported, never trusted."""

    id: str
    brand: str
    kind: Literal["logo", "favicon", "og_image", "image"]
    path: str | None = None
    url: str | None = None
    sha256: str | None = None

    @field_validator("id")
    @classmethod
    def _check_id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError(f"asset id {v!r} must be lowercase letters, digits and hyphens")
        return v

    @field_validator("path")
    @classmethod
    def _relative_path(cls, v: str | None) -> str | None:
        if v is not None and (not _ASSET_PATH_RE.match(v) or ".." in v.split("/")):
            raise ValueError("path must be relative to registry/assets/, without '..'")
        return v

    @field_validator("url")
    @classmethod
    def _https_url(cls, v: str | None) -> str | None:
        if v is not None and not v.startswith("https://"):
            raise ValueError("reference asset URLs must use https://")
        return v

    @field_validator("sha256")
    @classmethod
    def _digest(cls, v: str | None) -> str | None:
        if v is not None and not _SHA256_RE.match(v):
            raise ValueError("sha256 must be 64 lowercase hex digits")
        return v

    @model_validator(mode="after")
    def _source(self):
        if (self.path is None) == (self.url is None):
            raise ValueError("a reference asset has exactly one of path or url")
        if self.status == "confirmed" and self.sha256 is None:
            raise ValueError("a confirmed reference asset pins its content with sha256")
        return self


class Registry(_Entry):
    version: Literal[1]
    brands: list[Brand]
    context_terms: list[ContextTerm] = []
    exclusions: list[Exclusion] = []
    domains: list[Domain] = []
    relationships: list[Relationship] = []
    payees: list[Payee] = []
    reference_pages: list[ReferencePage] = []
    reference_assets: list[ReferenceAsset] = []

    def confirmed_official_domains(self, brand: str) -> list[str]:
        return [
            d.name
            for d in self.domains
            if d.brand == brand and d.kind == "official" and d.status == "confirmed"
        ]

    def on_confirmed_official_domain(self, brand: str, host: str | None) -> bool:
        """True when `host` is a confirmed official domain of `brand`, or under one."""
        return bool(host) and any(
            host == d or host.endswith("." + d) for d in self.confirmed_official_domains(brand)
        )

    def keywords(self) -> list[tuple[Brand, Keyword]]:
        return [(b, k) for b in self.brands if b.active for k in b.keywords if k.active]

    def suppressing_domains(self) -> list[Domain]:
        return [d for d in self.domains if d.suppresses and d.status == "confirmed"]

    def dnstwist_targets(self) -> list[Domain]:
        return [
            d
            for d in self.domains
            if d.kind == "official" and d.status in ("confirmed", "legacy-unverified")
        ]

    def confirmed_payees(self) -> list[Payee]:
        return [p for p in self.payees if p.status == "confirmed"]

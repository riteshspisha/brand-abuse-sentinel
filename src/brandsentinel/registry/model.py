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


class Registry(_Entry):
    version: Literal[1]
    brands: list[Brand]
    context_terms: list[ContextTerm] = []
    exclusions: list[Exclusion] = []
    domains: list[Domain] = []
    relationships: list[Relationship] = []
    payees: list[Payee] = []
    reference_pages: list[ReferencePage] = []

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

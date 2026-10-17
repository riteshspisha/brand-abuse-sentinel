"""The reference collector against the local TLS harness (U17, R13, R14, FA3).

Pages and images are served by the harness (a test CA for secure.harness.test,
an expired certificate for expired.harness.test); images are hashed by the real
worker code in process (InProcessRunner)."""

import asyncio
import hashlib
import json

import pytest
from tests import media_support as M
from tests.security.harness import harness_fetcher

from brandsentinel.config import MediaSettings
from brandsentinel.net.fetcher import FetchResult
from brandsentinel.registry.loader import validate
from brandsentinel.registry.model import Registry
from brandsentinel.sandbox.media_client import MediaClient
from brandsentinel.visual.collector import Collector
from brandsentinel.visual.corpus import load_corpus

PROV = [
    {
        "source": "maintainer",
        "recorded_by": "t",
        "recorded_at": "2026-10-11",
        "verified_by": "m",
        "verified_at": "2026-10-11",
    }
]


def secure(h, path: str) -> str:
    return f"https://secure.harness.test:{h.secure.port}{path}"


def official_page(h) -> bytes:
    offsite = f"https://site.harness.test:{h.http.port}/blob?k=cdnlogo"
    return f"""<!doctype html><html><head><title>Lumina Foundation</title>
<link rel="icon" href="/blob?k=fav">
<meta property="og:image" content="/blob?k=og"></head>
<body><header><img src="/blob?k=logo" alt="Lumina Foundation logo"></header>
<img class="logo" src="{offsite}">
<p>Lumina Foundation, the official site. Donate through our partner
<a href="https://givewell-platform.org/lumina">GiveWell Platform</a> or by UPI
<a href="upi://pay?pa=lumina.foundation@lumenbank&amp;pn=Lumina%20Foundation">here</a>.</p>
</body></html>""".encode()


def make_registry(h, pages=(), assets=(), extra_domains=()) -> Registry:
    reg = Registry.model_validate(
        {
            "version": 1,
            "brands": [{"id": "lumina", "name": "Lumina Foundation", "status": "confirmed",
                        "provenance": PROV}],
            "domains": [{"name": d, "brand": "lumina", "status": "confirmed", "provenance": PROV}
                        for d in ("secure.harness.test", *extra_domains)],
            "reference_pages": list(pages),
            "reference_assets": list(assets),
        }
    )  # fmt: skip
    validate(reg)
    return reg


def page(url, status="confirmed"):
    return {"url": url, "brand": "lumina", "status": status, "provenance": PROV}


@pytest.fixture
def env(harness, store, tmp_path):
    rec = harness.recorder
    rec.pages["home"] = official_page(harness)
    rec.blobs.update(
        fav=(M.as_ico(), "image/x-icon"),
        og=(M.watermarked(), "image/png"),
        logo=(M.lab_logo(), "image/png"),
        cdnlogo=(M.lab_logo(), "image/png"),
    )
    assets = tmp_path / "assets"
    (assets / "lab").mkdir(parents=True)
    (assets / "lab" / "logo.png").write_bytes(M.lab_logo())
    yield harness, store, assets
    for k in ("fav", "og", "logo", "cdnlogo"):
        rec.blobs.pop(k, None)


def collect(h, store, registry, assets, runner=None, fetcher=None):
    collector = Collector(
        store.conn,
        registry,
        fetcher or harness_fetcher(h),
        MediaClient(runner or M.InProcessRunner(), MediaSettings()),
        MediaSettings(),
        assets,
    )
    return asyncio.run(collector.collect())


def corpus_rows(store):
    return store.conn.execute(
        "SELECT kind, origin, source, tls_mode, trusted_reference, active FROM reference_corpus"
        " ORDER BY id"
    ).fetchall()


def test_confirmed_https_page_yields_favicon_logo_and_og_image(env):
    h, store, assets = env
    reg = make_registry(h, pages=[page(secure(h, "/mutable?k=home"))])
    report = collect(h, store, reg, assets)
    assert report.pages == [
        {"url": secure(h, "/mutable?k=home"), "brand": "lumina", "result": "collected", "images": 3}
    ]
    rows = corpus_rows(store)
    assert sorted(r[0] for r in rows) == ["favicon", "logo", "og_image"]
    assert all(r[1] == "collected" and r[3] == "verified" and r[4] == 1 for r in rows)
    corpus = load_corpus(store.conn, reg)
    assert len(corpus.entries) == 3 and not corpus.rejected
    snap = store.conn.execute(
        "SELECT outcome, trusted_reference, title FROM reference_page_snapshots"
    ).fetchone()
    assert tuple(snap) == ("ok", 1, "Lumina Foundation")


def test_r14_third_parties_and_payment_destinations_become_candidate_observations(env):
    """Covers R14: an official page linking to a third-party donation platform
    records that platform as a candidate observation, never a confirmed domain."""
    h, store, assets = env
    reg = make_registry(h, pages=[page(secure(h, "/mutable?k=home"))])
    collect(h, store, reg, assets)
    obs = {
        (r[0], r[1]): r[2]
        for r in store.conn.execute("SELECT kind, value, status FROM reference_observations")
    }
    assert obs[("third_party_domain", "givewell-platform.org")] == "candidate"
    assert obs[("payment_destination", "lumina.foundation@lumenbank")] == "candidate"
    offsite = f"https://site.harness.test:{h.http.port}/blob?k=cdnlogo"
    assert obs[("offsite_image", offsite)] == "candidate"
    assert all(v == "candidate" for v in obs.values())
    # Nothing was added to the registry and nothing offsite entered the corpus.
    assert {d.name for d in reg.domains} == {"secure.harness.test"}
    assert all("site.harness.test" not in r[2] for r in corpus_rows(store))
    assert ("GET", "/blob?k=cdnlogo") not in {(m, p) for m, p, _ in h.recorder.requests}


def test_candidate_reference_page_is_skipped(env):
    h, store, assets = env
    reg = make_registry(h, pages=[page(secure(h, "/mutable?k=home"), status="candidate")])
    report = collect(h, store, reg, assets)
    assert report.pages[0]["result"] == "skipped" and corpus_rows(store) == []


def test_page_with_a_failing_certificate_is_refused_and_adds_nothing(env):
    h, store, assets = env
    url = f"https://expired.harness.test:{h.expired.port}/mutable?k=home"
    reg = make_registry(h, pages=[page(url)], extra_domains=["expired.harness.test"])
    report = collect(h, store, reg, assets)
    assert report.pages[0]["result"] == "refused" and "tls_error" in report.pages[0]["why"]
    assert corpus_rows(store) == []


@pytest.mark.parametrize(
    "target",
    [
        "http://site.harness.test:{http}/mutable?k=home",  # downgrade to http
        "https://expired.harness.test:{expired}/mutable?k=home",  # not a registry host
    ],
    ids=["http", "non-registry"],
)
def test_redirect_off_https_or_off_registry_hosts_is_refused(env, target):
    h, store, assets = env
    to = target.format(http=h.http.port, expired=h.expired.port)
    url = secure(h, f"/redirect?to={to}")
    report = collect(h, store, make_registry(h, pages=[page(url)]), assets)
    assert report.pages[0]["result"] == "refused"
    assert "blocked_redirect" in report.pages[0]["why"]
    assert corpus_rows(store) == []


def test_confirmed_registry_asset_enters_only_with_its_pinned_bytes(env):
    h, store, assets = env
    pin = hashlib.sha256(M.lab_logo()).hexdigest()
    good = {"id": "logo", "brand": "lumina", "kind": "logo", "path": "lab/logo.png",
            "sha256": pin, "status": "confirmed", "provenance": PROV}  # fmt: skip
    report = collect(h, store, make_registry(h, assets=[good]), assets)
    assert report.assets[0]["result"] == "hashed" and report.added == 1
    ((_, origin, source, _, _, active),) = corpus_rows(store)
    assert (origin, source, active) == ("registry_asset", "registry/assets/lab/logo.png", 1)

    # The file is replaced: the new bytes are refused and reported. The entry for
    # the pinned bytes (what the maintainer verified) stays; the new image never
    # enters until a maintainer pins it.
    (assets / "lab" / "logo.png").write_bytes(M.other_sun())
    report = collect(h, store, make_registry(h, assets=[good]), assets)
    assert report.assets[0]["result"] == "refused" and "differs from pin" in report.assets[0]["why"]
    kinds = [r[0] for r in store.conn.execute("SELECT kind FROM reference_observations")]
    assert kinds == ["asset_changed"]
    assert [
        r[2] for r in store.conn.execute("SELECT sha256, active, sha256 FROM reference_corpus")
    ] == [pin]

    # The maintainer withdraws the asset: its entry is retired.
    report = collect(h, store, make_registry(h, assets=[{**good, "status": "rejected"}]), assets)
    assert report.retired == 1 and [r[5] for r in corpus_rows(store)] == [0]


def test_candidate_and_escaping_assets_never_enter(env):
    h, store, assets = env
    pin = hashlib.sha256(M.lab_logo()).hexdigest()
    cand = {"id": "c", "brand": "lumina", "kind": "logo", "path": "lab/logo.png",
            "sha256": pin, "status": "candidate", "provenance": PROV}  # fmt: skip
    (assets.parent / "outside.png").write_bytes(M.lab_logo())
    (assets / "lab" / "link.png").symlink_to(assets.parent / "outside.png")
    link = {**cand, "id": "l", "path": "lab/link.png", "status": "confirmed"}
    report = collect(h, store, make_registry(h, assets=[cand, link]), assets)
    results = {a["id"]: a for a in report.assets}
    assert results["c"]["result"] == "skipped"
    assert results["l"]["result"] == "refused" and "leaves registry/assets" in results["l"]["why"]
    assert corpus_rows(store) == []


class Down:
    """A fetcher for which every site is unreachable."""

    async def fetch(self, url, **kw):
        return FetchResult(
            requested_url=url,
            mode="verified",
            purpose="reference",
            started_at="",
            outcome="connect_error",
            error={"kind": "connection_refused"},
        )


def test_a_page_that_cannot_be_fetched_keeps_its_earlier_entries(env):
    h, store, assets = env
    reg = make_registry(h, pages=[page(secure(h, "/mutable?k=home"))])
    collect(h, store, reg, assets)
    report = collect(h, store, reg, assets, fetcher=Down())
    assert report.pages[0]["result"] == "refused" and "connect_error" in report.pages[0]["why"]
    assert report.retired == 0 and sum(r[5] for r in corpus_rows(store)) == 3


def test_recollection_retires_only_what_the_page_no_longer_shows(env):
    h, store, assets = env
    reg = make_registry(h, pages=[page(secure(h, "/mutable?k=home"))])
    collect(h, store, reg, assets)
    h.recorder.pages["home"] = official_page(h).replace(b'<meta property="og:image"', b"<meta x")
    report = collect(h, store, reg, assets)
    assert report.retired == 1 and report.unchanged == 2
    assert {r[0] for r in corpus_rows(store) if r[5]} == {"favicon", "logo"}


def test_image_the_sandbox_rejects_is_reported_not_stored(env):
    h, store, assets = env
    h.recorder.blobs["og"] = (b"<html>not an image</html>", "image/png")
    report = collect(h, store, make_registry(h, pages=[page(secure(h, "/mutable?k=home"))]), assets)
    (bad,) = report.images
    assert bad["kind"] == "og_image" and bad["result"] == "rejected"
    assert "not_an_image" in bad["why"]
    assert sorted(r[0] for r in corpus_rows(store)) == ["favicon", "logo"]


def test_provenance_records_both_fetches(env):
    h, store, assets = env
    collect(h, store, make_registry(h, pages=[page(secure(h, "/mutable?k=home"))]), assets)
    (prov,) = store.conn.execute(
        "SELECT provenance_json FROM reference_corpus WHERE kind = 'logo'"
    ).fetchone()
    prov = json.loads(prov)
    assert prov["page_fetch"]["trusted_reference"] and prov["image_fetch"]["mode"] == "verified"
    assert prov["image_fetch"]["hops"][0]["tls"] == "verified"


class OneImageDown:
    """The harness fetcher, except that one image URL fails (a transient 503)."""

    def __init__(self, inner, broken: str) -> None:
        self.inner, self.broken = inner, broken

    async def fetch(self, url, **kw):
        if url.endswith(self.broken):
            return FetchResult(
                requested_url=url, mode="verified", purpose="reference", started_at="",
                outcome="connect_error", error={"kind": "unavailable"},
            )  # fmt: skip
        return await self.inner.fetch(url, **kw)


def test_a_transient_image_failure_keeps_the_pages_entries(env):
    """Review fix: the page is not examined completely, so nothing is retired."""
    h, store, assets = env
    reg = make_registry(h, pages=[page(secure(h, "/mutable?k=home"))])
    collect(h, store, reg, assets)
    report = collect(h, store, reg, assets, fetcher=OneImageDown(harness_fetcher(h), "k=og"))
    assert any(i["kind"] == "og_image" and i["result"] == "refused" for i in report.images)
    assert report.retired == 0 and sum(r[5] for r in corpus_rows(store)) == 3


def test_the_same_image_on_two_pages_is_two_entries(env):
    h, store, assets = env
    h.recorder.pages["home2"] = official_page(h)
    reg = make_registry(
        h, pages=[page(secure(h, "/mutable?k=home")), page(secure(h, "/mutable?k=home2"))]
    )
    collect(h, store, reg, assets)
    assert len([r for r in corpus_rows(store) if r[0] == "logo" and r[5]]) == 2
    # The first page drops the logo: the second page's entry survives.
    h.recorder.pages["home"] = official_page(h).replace(
        b'<header><img src="/blob?k=logo" alt="Lumina Foundation logo"></header>', b""
    )
    collect(h, store, reg, assets)
    assert len([r for r in corpus_rows(store) if r[0] == "logo" and r[5]]) == 1
    del h.recorder.pages["home2"]

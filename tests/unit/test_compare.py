"""Visual matching (U17, R22): positives are altered copies of the official logo,
hard negatives are unrelated images that look alike. Hashes come from the real
worker code run in process."""

import pytest
from tests import media_support as M

from brandsentinel.config import MediaMatching
from brandsentinel.visual.compare import HashMatcher, ImageHashes, hamming
from brandsentinel.visual.corpus import Corpus, CorpusEntry


def entry(data: bytes, id=1, brand="lumina-foundation", kind="logo") -> CorpusEntry:
    h = M.hashes(data)
    return CorpusEntry(
        id=id,
        brand=brand,
        kind=kind,
        origin="registry_asset",
        asset_id="lumina-logo",
        reference_page=None,
        source="registry/assets/lab/lumina-logo.png",
        sha256=h["sha256"],
        phash=h["phash"],
        dhash=h["dhash"],
        favicon_mmh3=h["favicon_mmh3"],
        width=h["width"],
        height=h["height"],
        luma_stddev=h["luma_stddev"],
        tls_mode=None,
        trusted_reference=True,
    )


CORPUS = Corpus((entry(M.lab_logo()),))
MATCHER = HashMatcher(MediaMatching())


def match(data: bytes, corpus=CORPUS):
    h = M.hashes(data)
    assert h["status"] == "ok", h
    return MATCHER.match(ImageHashes.from_media(h), corpus)


def test_identical_image_matches_by_exact_hash():
    (m,) = match(M.lab_logo())
    assert m.method == "sha256" and m.phash_distance == 0
    assert m.reference.asset_id == "lumina-logo"
    assert m.to_dict()["reference"]["source"] == "registry/assets/lab/lumina-logo.png"


@pytest.mark.parametrize(
    "variant",
    ["resized_jpeg", "recoloured", "watermarked", "bordered", "with_alpha", "as_gif", "as_ico"],
)
def test_altered_copies_of_the_logo_match_perceptually(variant):
    (m,) = match(getattr(M, variant)())
    assert m.method == "perceptual"
    assert m.phash_distance <= 10 and m.dhash_distance <= 8


def test_the_lab_clone_logo_matches_with_its_reference_source():
    (m,) = match((M.REPO / "labsites/copied-assets/static/logo.png").read_bytes())
    assert m.method == "perceptual" and m.reference.brand == "lumina-foundation"


@pytest.mark.parametrize(
    "negative",
    [
        M.other_sun,
        lambda: M.other_sun("LUMEN", 12, M.GOLD),  # closest unrelated sun found
        lambda: M.other_sun("SUNRISE", 10, M.NAVY),
        lambda: M.other_sun("SOLIS", 12, M.GOLD),
        M.gold_circle,
        M.flat,
        M.gradient,
        M.payment_screenshot,
        lambda: M.text_image("Lumina Foundation"),
    ],
    ids=["sun", "lumen-sun", "sunrise", "solis", "gold-circle", "flat", "gradient",
         "payment-screenshot", "brand-text"],
)  # fmt: skip
def test_unrelated_similar_images_do_not_match(negative):
    assert match(negative()) == []


def test_heavily_altered_copies_are_not_claimed_as_matches():
    # Known limits of the initial method, pinned so a change is deliberate:
    # mirroring and cropping defeat pHash (a stronger VisualMatcher may replace it).
    assert match(M.mirrored()) == []
    assert match(M.cropped()) == []


def test_flat_images_match_only_by_exact_hash():
    corpus = Corpus((entry(M.flat((240, 240, 240))),))
    assert match(M.flat((235, 235, 235)), corpus) == []
    (m,) = match(M.flat((240, 240, 240)), corpus)
    assert m.method == "sha256"


def test_proportions_must_agree():
    # Squashed to 256x150 (aspect 1.71, over the 1.35 factor): hashes alone
    # might still be close, the proportions are not.
    assert match(M.encode(M._logo_img().resize((256, 150)))) == []


def test_matches_are_ordered_exact_first_and_capped():
    corpus = Corpus(
        tuple(entry(d, id=i) for i, d in enumerate([M.resized_jpeg(), M.lab_logo()], start=1))
    )
    ms = match(M.lab_logo(), corpus)
    assert [m.method for m in ms] == ["sha256", "perceptual"]


def test_hamming():
    assert hamming("ff00", "0f00") == 4 and hamming("0" * 16, "0" * 16) == 0


def test_describe_records_thresholds():
    d = MATCHER.describe()
    assert d["version"] == "hash_matcher/1" and d["phash_max_distance"] == 10

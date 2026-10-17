"""Visual matching of candidate images against the reference corpus (U17, R22).

`VisualMatcher` is the replaceable interface: it takes one analyzed image (the
media worker's hashes) and the corpus, and returns matches with method, scores
and the matched reference. `HashMatcher` is the initial, cheap method:

- `sha256`: byte-identical to a reference image;
- `perceptual`: pHash *and* dHash within their Hamming thresholds, similar
  proportions, and enough structure in both images (flat or near-flat images
  hash alike whatever they show, so they match only by exact hash).

A match says the images look alike, nothing more. Whether that is evidence of
impersonation is the policy's decision, which requires corroboration from the
page or domain (KTD17); a match alone never reaches P1 or P2.
"""

from dataclasses import dataclass
from typing import Protocol

from brandsentinel.config import MediaMatching
from brandsentinel.visual.corpus import Corpus, CorpusEntry

MAX_MATCHES = 5


@dataclass(frozen=True)
class ImageHashes:
    sha256: str
    phash: str
    dhash: str
    width: int
    height: int
    luma_stddev: float

    @classmethod
    def from_media(cls, item: dict) -> "ImageHashes":
        return cls(
            item["sha256"],
            item["phash"],
            item["dhash"],
            item["width"],
            item["height"],
            float(item["luma_stddev"]),
        )


@dataclass(frozen=True)
class Match:
    method: str  # sha256 | perceptual
    reference: CorpusEntry
    phash_distance: int
    dhash_distance: int

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "phash_distance": self.phash_distance,
            "dhash_distance": self.dhash_distance,
            "reference": self.reference.reference(),
        }


class VisualMatcher(Protocol):
    name: str
    version: str

    def match(self, image: ImageHashes, corpus: Corpus) -> list[Match]: ...

    def describe(self) -> dict: ...


def hamming(a: str, b: str) -> int:
    return (int(a, 16) ^ int(b, 16)).bit_count()


def _aspect(w: int, h: int) -> float:
    return w / h if h else 0.0


class HashMatcher:
    name = "hash"
    version = "hash_matcher/1"

    def __init__(self, settings: MediaMatching) -> None:
        self.s = settings

    def describe(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "phash_max_distance": self.s.phash_max_distance,
            "dhash_max_distance": self.s.dhash_max_distance,
            "min_luma_stddev": self.s.min_luma_stddev,
            "max_aspect_ratio_factor": self.s.max_aspect_ratio_factor,
        }

    def informative(self, image: ImageHashes) -> bool:
        return image.luma_stddev >= self.s.min_luma_stddev

    def match(self, image: ImageHashes, corpus: Corpus) -> list[Match]:
        out: list[Match] = []
        for ref in corpus.entries:
            p, d = hamming(image.phash, ref.phash), hamming(image.dhash, ref.dhash)
            if image.sha256 == ref.sha256:
                out.append(Match("sha256", ref, p, d))
                continue
            if not (self.informative(image) and ref.luma_stddev >= self.s.min_luma_stddev):
                continue
            a, b = _aspect(image.width, image.height), _aspect(ref.width, ref.height)
            if not a or not b or max(a, b) / min(a, b) > self.s.max_aspect_ratio_factor:
                continue
            if p <= self.s.phash_max_distance and d <= self.s.dhash_max_distance:
                out.append(Match("perceptual", ref, p, d))
        out.sort(
            key=lambda m: (
                m.method != "sha256",
                m.phash_distance + m.dhash_distance,
                m.reference.id,
            )
        )
        return out[:MAX_MATCHES]

"""Generate the synthetic images shipped for `brandsentinel sandbox selftest media`.

Run from the repository root (needs the dev group, which has Pillow):

    uv run python scripts/generate-media-selftest.py

The output under src/brandsentinel/sandbox/selftest/ is committed. Everything is
synthetic (KTD14): the fictional lab brand, never a real asset.
"""

import shutil
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).parents[1]
OUT = ROOT / "src" / "brandsentinel" / "sandbox" / "selftest"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    img = Image.new("RGB", (720, 120), (255, 255, 255))
    ImageDraw.Draw(img).text(
        (20, 34), "Donate to Lumina Foundation", fill=(0, 0, 0), font=ImageFont.load_default(44)
    )
    img.save(OUT / "ocr-donate.png", optimize=True)
    shutil.copyfile(
        ROOT / "labsites" / "donation-fraud" / "static" / "upi-qr.png", OUT / "upi-qr.png"
    )


if __name__ == "__main__":
    main()

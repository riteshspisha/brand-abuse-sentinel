"""Image fixtures and an in-process media runner for tests (U16, U17).

Fixtures are synthetic (KTD14) and built at test time with Pillow from the dev
group, so the positive and hard-negative sets live in code rather than binary
files: the lab's official logo and altered copies of it (resized and
recompressed, recoloured, watermarked, bordered, mirrored, cropped), unrelated
but similar-looking logos, flat images, and a screenshot of a payment screen.

`InProcessRunner` stands in for SandboxRunner: it runs the worker module in this
process, which is how unit and integration tests exercise the real worker code
without a container. Container behaviour is covered by the docker-marked tests.
"""

import io
import json
import math
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageFont, ImageOps

from brandsentinel.sandbox import media_worker
from brandsentinel.sandbox.runner import SandboxResult

REPO = Path(__file__).parents[1]
LAB_LOGO = REPO / "labsites" / "official" / "static" / "lumina-logo.png"
LAB_QR = REPO / "labsites" / "donation-fraud" / "static" / "upi-qr.png"
GOLD, NAVY, WHITE, RED = (232, 170, 40), (20, 36, 80), (255, 255, 255), (200, 40, 40)


def encode(img: Image.Image, fmt: str = "PNG", **kw) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format=fmt, **kw)
    return buf.getvalue()


def lab_logo() -> bytes:
    return LAB_LOGO.read_bytes()


def _logo_img() -> Image.Image:
    return Image.open(io.BytesIO(lab_logo())).convert("RGB")


def font(size: int):
    return ImageFont.load_default(size=size)


# --- altered copies of the official logo -------------------------------------------


def resized_jpeg() -> bytes:
    """What a clone does without thinking: smaller and recompressed."""
    return encode(_logo_img().resize((150, 150), Image.Resampling.LANCZOS), "JPEG", quality=60)


def recoloured() -> bytes:
    img = _logo_img()
    r, g, b = img.split()
    return encode(Image.merge("RGB", (b, r, g)))


def watermarked() -> bytes:
    img = _logo_img()
    ImageDraw.Draw(img).text((8, 8), "SALE", fill=RED, font=font(18))
    return encode(img)


def bordered() -> bytes:
    return encode(ImageOps.expand(_logo_img(), border=8, fill=WHITE))


def with_alpha() -> bytes:
    """The logo with a transparent background instead of white."""
    img = _logo_img()
    r, g, b = img.split()
    darkest = ImageChops.darker(ImageChops.darker(r, g), b)
    rgba = img.convert("RGBA")
    rgba.putalpha(darkest.point(lambda v: 0 if v == 255 else 255))
    return encode(rgba)


def as_gif() -> bytes:
    return encode(_logo_img().convert("P", palette=Image.Palette.ADAPTIVE), "GIF")


def as_ico() -> bytes:
    return encode(_logo_img(), "ICO", sizes=[(64, 64)])


def mirrored() -> bytes:
    return encode(ImageOps.mirror(_logo_img()))


def cropped() -> bytes:
    img = _logo_img()
    return encode(img.crop((0, 0, img.width, img.height // 2)))


# --- hard negatives -------------------------------------------------------------------


def other_sun(text: str = "SOLARA", rays: int = 8, colour=RED) -> bytes:
    """An unrelated sun logo: same idea, different drawing."""
    size = 256
    img = Image.new("RGB", (size, size), WHITE)
    d = ImageDraw.Draw(img)
    c, r = size // 2, size // 4
    for i in range(rays):
        a = i * 2 * math.pi / rays + 0.2
        d.line(
            [
                (c + r * 1.2 * math.cos(a), c - 10 + r * 1.2 * math.sin(a)),
                (c + r * 1.8 * math.cos(a), c - 10 + r * 1.8 * math.sin(a)),
            ],
            fill=colour,
            width=10,
        )
    d.ellipse([c - r, c - 10 - r, c + r, c - 10 + r], fill=colour)
    d.text((c, size - 30), text, fill=(0, 0, 0), font=font(30), anchor="mm")
    return encode(img)


def gold_circle() -> bytes:
    """A plain gold disc on white, close to the logo's centre shape."""
    img = Image.new("RGB", (256, 256), WHITE)
    ImageDraw.Draw(img).ellipse([76, 56, 180, 160], fill=GOLD, outline=NAVY, width=4)
    return encode(img)


def flat(colour=(240, 240, 240), size=(256, 256)) -> bytes:
    return encode(Image.new("RGB", size, colour))


def gradient() -> bytes:
    img = Image.new("L", (256, 256))
    img.putdata([x for _ in range(256) for x in range(256)])
    return encode(img.convert("RGB"))


def payment_screenshot() -> bytes:
    """A screenshot of a payment screen: payee, UPI ID, bank details and a QR."""
    img = Image.new("RGB", (820, 560), WHITE)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, 820, 70], fill=NAVY)
    d.text((24, 18), "QuickPay Wallet", fill=WHITE, font=font(32))
    lines = [
        "Pay to: Lumina Foundation Relief",
        "UPI ID: rivers.relief.fund@quickpaybank",
        "Account 000123456789 IFSC LUMN0000001",
        "Amount: INR 1000",
    ]
    for n, line in enumerate(lines):
        d.text((24, 110 + n * 56), line, fill=(0, 0, 0), font=font(30))
    qr = Image.open(LAB_QR).convert("RGB").resize((220, 220), Image.Resampling.NEAREST)
    img.paste(qr, (580, 320))
    return encode(img)


def text_image(text: str, size=(720, 120)) -> bytes:
    img = Image.new("RGB", size, WHITE)
    ImageDraw.Draw(img).text((20, 34), text, fill=(0, 0, 0), font=font(44))
    return encode(img)


# --- running the worker ---------------------------------------------------------------


def hashes(data: bytes, **opts) -> dict:
    """The worker's analysis of one image, in process."""
    from tests.media_support import worker_opts

    return media_worker.analyze(data, worker_opts(**opts), ocr=False, qr=True)


def worker_opts(**over) -> dict:
    from brandsentinel.config import MediaSettings
    from brandsentinel.sandbox.media_client import worker_options

    return {**worker_options(MediaSettings()), **over}


class InProcessRunner:
    """Duck-types SandboxRunner.run for the media client: runs the worker here.

    `fail` maps a job id prefix to a sandbox status, to simulate a container
    killed by a limit (for example {"j1": "oom"} fails job j1 but not its
    per-image retries j1-i0...). `tamper` may rewrite the output document."""

    def __init__(self, fail: dict | None = None, tamper=None) -> None:
        self.fail = fail or {}
        self.tamper = tamper
        self.calls: list[tuple] = []

    async def run(self, spec, *, job, attempt, stdin=b""):
        self.calls.append((spec, str(job), attempt, len(stdin)))
        name = f"bs-test-{spec.role}-{job}-{attempt}"
        if str(job) in self.fail:
            return SandboxResult(name=name, status=self.fail[str(job)], killed=True, removed=True)
        argv = list(spec.command[spec.command.index("--max-input-bytes") :])
        out = io.StringIO()
        media_worker.main(argv, io.BytesIO(stdin), out)
        doc = json.loads(out.getvalue())
        if self.tamper:
            doc = self.tamper(doc)
        return SandboxResult(
            name=name, status="ok", exit_code=0, removed=True, stdout=b"", output=doc
        )

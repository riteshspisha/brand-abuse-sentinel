"""Generate the lab's synthetic images (KTD14: no real brand assets).

Run from the repository root:

    uv run --no-project --with pillow==11.3.0 --with qrcode==8.2 \
        python labsites/generate_assets.py

The output is committed; re-running with the same library versions reproduces it.
"""

import math
from pathlib import Path

import qrcode
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).parent
GOLD, NAVY, WHITE = (232, 170, 40), (20, 36, 80), (255, 255, 255)


def font(size: int) -> ImageFont.ImageFont:
    return ImageFont.load_default(size=size)


def logo(size: int = 256) -> Image.Image:
    img = Image.new("RGB", (size, size), WHITE)
    d = ImageDraw.Draw(img)
    c, r = size // 2, size // 5
    for i in range(12):  # rays
        a = i * math.pi / 6
        d.line(
            [
                (c + r * 1.3 * math.cos(a), c - 20 + r * 1.3 * math.sin(a)),
                (c + r * 1.9 * math.cos(a), c - 20 + r * 1.9 * math.sin(a)),
            ],
            fill=GOLD,
            width=6,
        )
    d.ellipse([c - r, c - 20 - r, c + r, c - 20 + r], fill=GOLD, outline=NAVY, width=4)
    d.text((c, size - 40), "LUMINA", fill=NAVY, font=font(size // 7), anchor="mm")
    return img


def qr(data: str) -> Image.Image:
    q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=6, border=2)
    q.add_data(data)
    q.make(fit=True)
    return q.make_image(fill_color="black", back_color="white").get_image().convert("RGB")


def appeal() -> Image.Image:
    img = Image.new("RGB", (640, 360), NAVY)
    img.paste(logo(128), (24, 24))
    d = ImageDraw.Draw(img)
    d.text((176, 40), "Lumina Foundation", fill=GOLD, font=font(40))
    d.text((176, 96), "Flood Relief Appeal", fill=WHITE, font=font(30))
    d.text((24, 200), "Master Orin asks you to donate today.", fill=WHITE, font=font(24))
    d.text((24, 250), "UPI: rivers.relief.fund@quickpaybank", fill=GOLD, font=font(24))
    return img


def save(img: Image.Image, rel: str) -> None:
    path = ROOT / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path, optimize=True)


def main() -> None:
    official = logo()
    save(official, "official/static/lumina-logo.png")
    # The clone re-encodes a resized copy: same picture, different bytes.
    save(official.resize((200, 200), Image.LANCZOS), "copied-assets/static/logo.png")
    save(appeal(), "image-only/static/appeal.png")
    relief = "upi://pay?pa=rivers.relief.fund@quickpaybank&pn=Lumina%20Relief&am=1000&cu=INR"
    save(qr(relief), "donation-fraud/static/upi-qr.png")
    save(qr(relief), "image-only/static/upi-qr.png")
    save(
        qr("upi://pay?pa=programs.fee@quickpaybank&pn=Lumina%20Programs&am=2500&cu=INR"),
        "js-payment/static/upi-qr.png",
    )
    save(
        qr("upi://pay?pa=festival.gifts@quickpaybank&pn=Lumina%20Gifts&am=2100&cu=INR"),
        "cloaking/fraud/static/upi-qr.png",
    )


if __name__ == "__main__":
    main()

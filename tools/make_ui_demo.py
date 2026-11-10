"""Render docs/demo-ui.gif: an animated walkthrough of the web UI.

Input: .pytest_cache/ui/<page>.png captured at 1440x900 from the demo case
server. Each page gets a slow zoom (Ken Burns) and pages crossfade into each
other, with a caption bar explaining what you're looking at.

Usage: py -3.12 tools/make_ui_demo.py
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / ".pytest_cache" / "ui"
OUT = ROOT / "docs" / "demo-ui.gif"

W, H = 640, 418
CAPTION_H = 36
ZOOM_FRAMES = 8
FADE_FRAMES = 6
HOLD_FIRST = 6

PAGES = [
    ("overview", "Overview - one case at a glance"),
    ("timeline", "Timeline - every record, masked"),
    ("anomalies", "Anomalies - explained leads to review"),
    ("secrets", "Secret leads - where masking fired"),
    ("coverage", "Coverage - what was parsed, what wasn't"),
    ("export", "Export - shareable case pack"),
    ("cases", "Cases & intake - watch mode"),
]

BG = (10, 15, 26)
CAP_BG = (16, 23, 38)
FG = (214, 226, 240)
TEAL = (45, 212, 191)


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    for name in ("seguisb.ttf", "segoeui.ttf"):
        path = Path("C:/Windows/Fonts") / name
        if path.exists():
            return ImageFont.truetype(str(path), size)
    return ImageFont.truetype("C:/Windows/Fonts/consola.ttf", size)


def load(page: str) -> Image.Image:
    return Image.open(SRC / f"{page}.png").convert("RGB")


def ken_burns(img: Image.Image, t: float) -> Image.Image:
    """Crop a slowly zooming window from the 1440x900 capture."""
    zoom = 1.0 + 0.10 * t
    cw, ch = 1440 / zoom, 900 / zoom
    # drift focus from the center-left toward center as t grows
    cx, cy = 660 + 60 * t, 450
    left = max(0, min(1440 - cw, cx - cw / 2))
    top = max(0, min(900 - ch, cy - ch / 2))
    crop = img.crop((int(left), int(top), int(left + cw), int(top + ch)))
    return crop.resize((W, H), Image.LANCZOS)


def caption(text: str) -> Image.Image:
    bar = Image.new("RGB", (W, CAPTION_H), CAP_BG)
    draw = ImageDraw.Draw(bar)
    draw.rectangle([0, 0, 4, CAPTION_H], fill=TEAL)
    draw.text((14, 9), text, font=font(15, True), fill=FG)
    return bar


def compose(body: Image.Image, text: str) -> Image.Image:
    img = Image.new("RGB", (W, H + CAPTION_H), BG)
    img.paste(body, (0, 0))
    img.paste(caption(text), (0, H))
    return img


def blend(a: Image.Image, b: Image.Image, t: float) -> Image.Image:
    return Image.blend(a, b, t)


def main() -> None:
    frames: list[Image.Image] = []
    images = [(name, load(name)) for name, _ in PAGES]

    first_name, first_img = images[0]
    for i in range(HOLD_FIRST):
        frames.append(compose(ken_burns(first_img, i / (HOLD_FIRST + ZOOM_FRAMES)), PAGES[0][1]))

    for idx in range(len(images) - 1):
        name_a, img_a = images[idx]
        name_b, img_b = images[idx + 1]
        # zoom through the rest of page A
        for i in range(ZOOM_FRAMES):
            t = (HOLD_FIRST + idx * ZOOM_FRAMES + i) / 60
            t = min(1.0, t)
            frames.append(compose(ken_burns(img_a, min(1.0, t + 0.1)), PAGES[idx][1]))
        # crossfade A -> B
        for i in range(FADE_FRAMES):
            t = (i + 1) / FADE_FRAMES
            body = blend(ken_burns(img_a, 1.0), ken_burns(img_b, 0.0), t)
            frames.append(compose(body, PAGES[idx + 1][1]))

    # hold the last page
    last_name, last_img = images[-1]
    for i in range(12):
        frames.append(compose(ken_burns(last_img, min(1.0, i / 48)), PAGES[-1][1]))

    OUT.parent.mkdir(exist_ok=True)
    frames[0].save(
        OUT,
        save_all=True,
        append_images=frames[1:],
        duration=110,
        loop=0,
        optimize=True,
    )
    print(f"wrote {OUT} with {len(frames)} frames")


if __name__ == "__main__":
    main()

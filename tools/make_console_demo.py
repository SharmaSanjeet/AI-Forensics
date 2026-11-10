"""Render docs/demo-console.gif: an animated terminal session of the real CLI.

Usage: py -3.12 tools/make_console_demo.py
The command outputs below were captured from a real case run; edit SCRIPT
if the app output changes.
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "demo-console.gif"

BG = (13, 17, 23)
BAR = (22, 27, 34)
FG = (230, 237, 243)
MUTED = (139, 148, 158)
GREEN = (63, 185, 80)
TEAL = (45, 212, 191)
AMBER = (245, 181, 68)

W, H = 880, 470
TITLE_H = 34
PAD = 18
LINE_H = 24

SCRIPT = [
    ("cmd", "$ ai-forensics list"),
    ("out", "20261110-130442-this-machine   2026-11-10   cases/20261110-130442-this-machine"),
    ("out", "20261110-124449-this-machine   2026-11-10   cases/20261110-124449-this-machine"),
    ("pause", ""),
    ("cmd", "$ ai-forensics detect --case 20261110-130442-this-machine"),
    ("out", '11 leads in 1108 rows: {"medium": 9, "low": 2}'),
    ("pause", ""),
    ("cmd", "$ ai-forensics analyze --provider ollama --model llama3.1:8b"),
    ("out", "provider=ollama model=llama3.1:8b"),
    ("out", "generated=0 cached=11 fallback=0 errors=0"),
    ("out", "brief[llm]: Local AI assistant activity on one machine shows"),
    ("out", "possible generic_secret exposure and high tool call rates."),
    ("pause", ""),
    ("cmd", "$ ai-forensics serve"),
    ("out", "-> web UI on http://127.0.0.1:8000   (local only; secrets stay masked)"),
]

FILL = {"cmd": FG, "out": MUTED}


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    name = "consolab.ttf" if bold else "consola.ttf"
    path = Path("C:/Windows/Fonts") / name
    if not path.exists():
        path = Path("C:/Windows/Fonts/cour.ttf")
    return ImageFont.truetype(str(path), size)


def base_frame() -> Image.Image:
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, W, TITLE_H], fill=BAR)
    for i, color in enumerate([(242, 99, 95), (245, 189, 79), (92, 200, 99)]):
        draw.ellipse([16 + i * 22, 12, 26 + i * 22, 22], fill=color)
    draw.text((86, 8), "AI-Forensics - working console", font=font(13, True), fill=MUTED)
    return img


def frame_for(lines: list[tuple[str, str]], cursor: tuple[int, int] | None) -> Image.Image:
    img = base_frame()
    draw = ImageDraw.Draw(img)
    y = TITLE_H + PAD
    for kind, text in lines:
        if kind == "cmd":
            dollar, _, rest = text.partition(" ")
            draw.text((PAD, y), dollar, font=font(17), fill=GREEN)
            draw.text((PAD + 34, y), rest, font=font(17), fill=FG)
        else:
            color = TEAL if text.startswith("->") else FILL.get(kind, MUTED)
            if text.startswith("->"):
                text = text.replace("->", "\u2192")
            draw.text((PAD, y), text, font=font(17), fill=color)
        y += LINE_H
    if cursor is not None:
        kind, text = lines[-1]
        if kind == "cmd":
            dollar, _, rest = text.partition(" ")
            x = PAD + 34 + draw.textlength(rest, font=font(17))
        else:
            x = PAD + draw.textlength(text, font=font(17))
        draw.rectangle([x + 3, y - LINE_H + 3, x + 13, y - LINE_H + 19], fill=TEAL)
    return img


def main() -> None:
    frames: list[Image.Image] = []
    lines: list[tuple[str, str]] = []

    def emit(img: Image.Image, ms: int) -> None:
        frames.append(img.copy())

    # empty terminal hold
    emit(base_frame(), 0)

    for kind, text in SCRIPT:
        if kind == "pause":
            for _ in range(4):
                emit(frame_for(lines, None), 90)
            continue
        if kind == "cmd":
            shown = ""
            step = 3
            for i in range(0, len(text), step):
                lines.append(("cmd", text[: min(i + step, len(text))]))
                emit(frame_for(lines, (len(text[: min(i + step, len(text))]),)), 45)
                lines.pop()
            lines.append(("cmd", text))
            emit(frame_for(lines, None), 120)
        else:
            lines.append(("out", text))
            emit(frame_for(lines, None), 140)
            emit(frame_for(lines, None), 140)

    # hold the finished terminal
    for _ in range(45):
        emit(frame_for(lines, None), 90)

    OUT.parent.mkdir(exist_ok=True)
    frames[0].save(
        OUT,
        save_all=True,
        append_images=frames[1:],
        duration=60,
        loop=0,
        optimize=True,
    )
    print(f"wrote {OUT} with {len(frames)} frames")


if __name__ == "__main__":
    main()

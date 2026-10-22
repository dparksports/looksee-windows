"""Generate LookSee app-icon candidates (gradient tile + eye glyph).

The brand: "take a look-see" — an eye that doubles as a magnifying glass,
on a tile that gradients from deep indigo (the unknown) to bright cyan
(seen clearly). Three candidates are rendered to Assets/icons/ with a
comparison sheet; the chosen one is copied to app_icon.ico in the repo
root (referenced by LookSee.csproj).

Usage:  <python with Pillow+numpy> Assets/generate_icon.py
"""
import os
import numpy as np
from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "icons")
os.makedirs(OUT, exist_ok=True)

S = 1024                    # master canvas
INDIGO = (23, 33, 105)      # deep indigo — the unknown
CYAN = (34, 211, 238)       # bright cyan — seen clearly
SKY = (14, 165, 233)        # pupil accent
LIGHT = (240, 247, 252)     # near-white tile
WHITE = (255, 255, 255)
INK = (23, 33, 105)

STROKE = 84                 # eye outline weight
EYE_L, EYE_R = 218, 806     # eye corners
EYE_CY = 512
EYE_H = 176                 # half-height of the lens
IRIS_R = 118
PUPIL_R = 52


def gradient_tile(top=INDIGO, bottom=CYAN, inset=56, radius=210):
    """Full-canvas image: rounded tile filled with a diagonal gradient."""
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    yy, xx = np.mgrid[0:S, 0:S]
    t = ((xx + yy) / (2 * S))[..., None]
    top_a, bot_a = np.array(top, float), np.array(bottom, float)
    grad = (top_a * (1 - t) + bot_a * t).astype(np.uint8)
    grad_img = Image.fromarray(grad, "RGB").convert("RGBA")

    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle([inset, inset, S - inset, S - inset],
                                           radius=radius, fill=255)
    img.paste(grad_img, (0, 0), mask)
    return img


def draw_eye(img, color=WHITE, pupil=SKY, handle=None):
    """Almond eye: two elliptical arcs; solid iris with a pupil dot.
    handle: None | (x0,y0,x1,y1) — magnifier grip from the lower corner."""
    d = ImageDraw.Draw(img)
    lens = [EYE_L, EYE_CY - EYE_H, EYE_R, EYE_CY + EYE_H]
    d.arc(lens, 180, 360, fill=color, width=STROKE)   # upper lid
    d.arc(lens, 0, 180, fill=color, width=STROKE)     # lower lid
    cx = (EYE_L + EYE_R) // 2
    # solid iris + accent pupil — solid shapes keep it readable at 16 px
    d.ellipse([cx - IRIS_R, EYE_CY - IRIS_R, cx + IRIS_R, EYE_CY + IRIS_R], fill=color)
    d.ellipse([cx - PUPIL_R, EYE_CY - PUPIL_R, cx + PUPIL_R, EYE_CY + PUPIL_R], fill=pupil)
    if handle:
        x0, y0, x1, y1 = handle
        d.line([(x0, y0), (x1, y1)], fill=color, width=STROKE)
        r = STROKE // 2
        d.ellipse([x1 - r, y1 - r, x1 + r, y1 + r], fill=color)
    return img


def candidate_a():
    """Recommendation: indigo→cyan tile, white eye, magnifier handle."""
    img = gradient_tile()
    return draw_eye(img, handle=(EYE_R - 6, EYE_CY + 88, EYE_R + 128, EYE_CY + 222))


def candidate_b():
    """Eye alone — the purest mark, best legibility at 16 px."""
    img = gradient_tile()
    return draw_eye(img)


def candidate_c():
    """Corporate light tile, indigo eye — matches a light-first theme."""
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([56, 56, S - 56, S - 56], radius=210,
                        fill=LIGHT, outline=(209, 226, 238), width=10)
    draw_eye(img, color=INK, pupil=CYAN)
    return img


def downscales(img):
    return {size: img.resize((size, size), Image.LANCZOS) for size in (256, 48, 32, 16)}


def save_all(name, img):
    sizes = downscales(img)
    sizes[256].save(os.path.join(OUT, f"candidate_{name}_256.png"))
    master = sizes[256].copy()
    master.save(os.path.join(OUT, f"candidate_{name}.ico"),
                sizes=[(256, 256), (48, 48), (32, 32), (24, 24), (16, 16)])
    return sizes


def sheet(cands):
    rows, cols = 2, 3  # dark row, light row
    cell_w, cell_h = 256 + 130, 256 + 40
    W, H = cols * cell_w + 80, rows * (cell_h + 70) + 60
    board = Image.new("RGB", (W, H), (250, 251, 253))
    d = ImageDraw.Draw(board)
    for ci, (name, sizes) in enumerate(cands.items()):
        x0 = 40 + ci * cell_w
        d.text((x0, 20), f"candidate {name}", fill=(60, 60, 70))
        # dark row
        d.rounded_rectangle([x0 - 10, 50, x0 + 256 + 10, 50 + 256 + 20], 12, fill=(24, 28, 36))
        board.paste(sizes[256], (x0, 60), sizes[256])
        for i, size in enumerate((48, 32, 16)):
            board.paste(sizes[size], (x0 + 270 + i * (size + 14), 60 + 256 - size), sizes[size])
        # light row
        oy = 50 + 256 + 70
        d.rounded_rectangle([x0 - 10, oy, x0 + 256 + 10, oy + 256 + 20], 12, fill=(255, 255, 255),
                            outline=(220, 224, 230))
        board.paste(sizes[256], (x0, oy + 10), sizes[256])
        for i, size in enumerate((48, 32, 16)):
            board.paste(sizes[size], (x0 + 270 + i * (size + 14), oy + 10 + 256 - size), sizes[size])
    board.save(os.path.join(OUT, "icon_sheet.png"))


cands = {"a": candidate_a(), "b": candidate_b(), "c": candidate_c()}
all_sizes = {name: save_all(name, img) for name, img in cands.items()}
sheet(all_sizes)
print("written to", OUT)

"""Generate LookSee's README infographics in an Apple-HIG-inspired theme.

Soft off-white canvas, floating white cards with hairline borders, one
accent per idea, generous whitespace, short declarative headlines. Text
is Segoe UI (the closest shipping cousin to SF Pro on Windows); tile
glyphs are color emoji.

Usage:  python Assets/generate_infographics.py
Writes: Assets/why_looksee.png, Assets/app_map.png,
        Assets/first_five_minutes.png, Assets/row_anatomy.png
"""
import os
from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
FONTS = "C:/Windows/Fonts"

# ── Apple-ish palette ─────────────────────────────────────────────────
BG      = (245, 245, 247)   # #F5F5F7 canvas
CARD    = (255, 255, 255)
BORDER  = (227, 227, 232)   # hairline
INK     = (29, 29, 31)      # #1D1D1F
SUB     = (110, 110, 115)   # #6E6E73
BLUE    = (0, 122, 255)     # #007AFF
GREEN   = (52, 199, 89)     # #34C759
TEAL    = (48, 176, 199)    # #30B0C7
ORANGE  = (255, 149, 0)     # #FF9500
PURPLE  = (175, 82, 222)    # #AF52DE
RED     = (255, 59, 48)     # #FF3B30
PILL_BG = (232, 241, 255)   # pale blue pill

W = 1680                    # canvas width for every infographic

def font(kind, size):
    files = {"reg": "segoeui.ttf", "semi": "seguisb.ttf",
             "bold": "segoeuib.ttf", "emoji": "seguiemj.ttf", "mono": "consola.ttf"}
    return ImageFont.truetype(os.path.join(FONTS, files[kind]), size)

EMOJI_OK = True
try:
    font("emoji", 40).getbbox("\U0001F44B")  # probe: color-emoji capable?
except Exception:
    EMOJI_OK = False

def text(d, xy, s, f, fill=INK, anchor="la", spacing=10):
    d.multiline_text(xy, s, font=f, fill=fill, anchor=anchor, spacing=spacing)

def text_w(d, s, f):
    return d.multiline_textbbox((0, 0), s, font=f)[2]

def wrap(s, f, max_w, d):
    words, lines, cur = s.split(), [], ""
    for w in words:
        t = (cur + " " + w).strip()
        if text_w(d, t, f) <= max_w or not cur:
            cur = t
        else:
            lines.append(cur); cur = w
    if cur: lines.append(cur)
    return "\n".join(lines)

def card(d, box, fill=CARD, radius=40, outline=BORDER, width=2):
    d.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)

def pill(d, cx, y, s, f, fg, bg, pad_x=26, pad_y=13):
    w = text_w(d, s, f)
    asc, desc = f.getmetrics()
    h = asc + desc
    box = [cx - w / 2 - pad_x, y, cx + w / 2 + pad_x, y + h + 2 * pad_y]
    d.rounded_rectangle(box, radius=(h + 2 * pad_y) / 2, fill=bg)
    d.text((cx, y + pad_y), s, font=f, fill=fg)
    return box[3]

def emoji(d, xy, ch, size):
    if EMOJI_OK:
        d.text(xy, ch, font=font("emoji", size), embedded_color=True)
    else:
        d.text(xy, ch, font=font("reg", size), fill=SUB)

def header(d, y, kicker, title_lines, title_size=68, accent=BLUE):
    pill(d, W // 2, y, kicker, font("semi", 25), accent, PILL_BG)
    y += 118
    f = font("semi", title_size)
    for i, line in enumerate(title_lines):
        col = accent if i == len(title_lines) - 1 and len(title_lines) > 1 else INK
        text(d, (W // 2, y + i * (title_size + 14)), line, f, col, anchor="ma")
    return y + len(title_lines) * (title_size + 14) + 8

def new_canvas(h):
    img = Image.new("RGB", (W, h), BG)
    return img, ImageDraw.Draw(img)

def save(img, name):
    img.save(os.path.join(HERE, name), optimize=True)
    print("wrote", name)


# ══════════════════════════════════════════════════════════════════════
# 1. Why LookSee exists — the antivirus-can't-do-this graphic
# ══════════════════════════════════════════════════════════════════════
def why_looksee():
    img, d = new_canvas(990)
    y = header(d, 64, "WHY LOOKSEE EXISTS",
               ["Antivirus answers: is this file bad?",
                "LookSee answers: what is this PC doing?"])

    # two comparison cards
    top, ch = y + 36, 470
    gap, mx = 40, 90
    cw = (W - 2 * mx - gap) // 2

    # left — antivirus
    card(d, [mx, top, mx + cw, top + ch])
    emoji(d, (mx + 44, top + 40), "\U0001F9EA", 62)          # test tube
    text(d, (mx + 130, top + 44), "Every antivirus", font("semi", 40))
    text(d, (mx + 130, top + 100), "matches files against a list of known bad ones",
         font("reg", 24), SUB)
    bullets_left = [
        "Sees files — not behavior",
        "A \u201cclean\u201d program phoning home? Invisible",
        "Verdicts are clean / threat, nothing between",
        "\u201cNo threats found\u201d — and the weirdness continues",
    ]
    by = top + 190
    for b in bullets_left:
        d.ellipse([mx + 48, by + 15, mx + 60, by + 27], fill=BORDER)
        text(d, (mx + 88, by), wrap(b, font("reg", 29), cw - 140, d), font("reg", 29))
        by += 30 + 26

    # right — LookSee (accent card)
    rx = mx + cw + gap
    card(d, [rx, top, rx + cw, top + ch], fill=(245, 250, 255),
         outline=(150, 190, 255), width=3)
    emoji(d, (rx + 44, top + 40), "\U0001F441", 62)          # eye
    text(d, (rx + 130, top + 44), "LookSee", font("semi", 40), BLUE)
    text(d, (rx + 130, top + 100), "watches what the machine actually does",
         font("reg", 24), SUB)
    bullets_right = [
        "Every internet conversation — live, and named",
        "Who started it, what arrived, what was sent",
        "Remembers, so yesterday stays solvable",
        "Looks only: nothing to un-break, ever",
    ]
    by = top + 190
    for b in bullets_right:
        d.text((rx + 46, by + 2), "\u2713", font=font("bold", 30), fill=GREEN)
        text(d, (rx + 88, by), wrap(b, font("reg", 29), cw - 140, d), font("reg", 29))
        by += 30 + 26

    # dark summary pill
    pill(d, W // 2, top + ch + 56,
         "Keep your antivirus. This is the piece it never gives you — visibility.",
         font("semi", 31), (255, 255, 255), INK)
    save(img, "why_looksee.png")


# ══════════════════════════════════════════════════════════════════════
# 2. App map — nine tabs, three shelves
# ══════════════════════════════════════════════════════════════════════
def app_map():
    img, d = new_canvas(1380)
    y = header(d, 60, "WHERE EVERYTHING LIVES", ["Nine tabs. Three shelves."])

    shelves = [
        ("LOOK", "feeds that show what's happening", [
            ("\U0001F4AC", "Who's Talking", "what is this PC sending, right now", (234, 243, 255)),
            ("\U0001F9FE", "Phone Bill", "who talks to whom, and how much", (231, 249, 240)),
            ("\U0001F9EC", "Who Started It", "why did this program run", (245, 235, 255)),
            ("\U0001F4E6", "Deliveries", "what Windows brought in overnight", (255, 242, 230)),
        ]),
        ("QUIET", "tools that make the machine quieter", [
            ("\U0001F6AB", "Black Hole", "proof the opt-outs actually stopped", (255, 233, 231)),
            ("\U0001F9A0", "Defender", "is the antivirus itself healthy", (228, 247, 250)),
        ]),
        ("SYSTEM", "the plumbing", [
            ("\U0001F510", "Privacy", "every data switch, one honest list", (235, 238, 255)),
            ("\U0001F504", "Windows Check-Ins", "how often Windows fetches its config", (234, 243, 255)),
            ("\u23FA", "Recorder", "will tomorrow answer yesterday", (237, 237, 241)),
        ]),
    ]

    mx, gap, th = 90, 28, 236
    for label, blurb, tiles in shelves:
        # shelf header: label + hairline + blurb
        d.text((mx, y), label, font=font("bold", 26), fill=SUB)
        lw = text_w(d, label, font("bold", 26))
        d.text((mx + lw + 24, y + 3), blurb, font="reg" and font("reg", 24), fill=BORDER)
        y += 48
        tw = (W - 2 * mx - gap * (len(tiles) - 1)) // len(tiles)
        for i, (gl, name, sub, tint) in enumerate(tiles):
            x0 = mx + i * (tw + gap)
            card(d, [x0, y, x0 + tw, y + th], radius=34)
            d.rounded_rectangle([x0 + 22, y + 22, x0 + 106, y + 106], radius=24, fill=tint)
            emoji(d, (x0 + 38, y + 38), gl, 46)
            text(d, (x0 + 22, y + 128), name, font("semi", 30))
            text(d, (x0 + 22, y + 172), wrap(sub, font("reg", 22), tw - 44, d),
                 font("reg", 22), SUB)
        y += th + 44

    pill(d, W // 2, y + 4, "Feeds keep recording while you look elsewhere — a feed runs until you stop it.",
         font("semi", 27), (255, 255, 255), INK)
    save(img, "app_map.png")


# ══════════════════════════════════════════════════════════════════════
# 3. First five minutes
# ══════════════════════════════════════════════════════════════════════
def first_five_minutes():
    img, d = new_canvas(910)
    y = header(d, 60, "GETTING STARTED", ["Five minutes, start to finish."])

    steps = [
        ("\U0001F4E5", "Download & unzip",
         "Grab the zip from Releases and unzip it anywhere. No installer, no account, no subscription."),
        ("\U0001F6E1", "Run as administrator",
         "Right-click LookSee.exe. It's the same permission Task Manager asks for — that's how it sees the whole machine."),
        ("\U0001F440", "Look around",
         "Every program talking to the internet is on screen, in plain English. Clicking a row changes nothing."),
    ]
    mx, gap, ch = 90, 28, 420
    cw = (W - 2 * mx - 2 * gap) // 3
    top = y + 36
    for i, (gl, title, body) in enumerate(steps):
        x0 = mx + i * (cw + gap)
        card(d, [x0, top, x0 + cw, top + ch])
        d.ellipse([x0 + 36, top + 36, x0 + 100, top + 100], fill=BLUE)
        n = font("bold", 36)
        d.text((x0 + 68, top + 68), str(i + 1), font=n, fill=(255, 255, 255), anchor="mm")
        emoji(d, (x0 + cw - 108, top + 40), gl, 56)
        text(d, (x0 + 36, top + 140), title, font("semi", 35))
        text(d, (x0 + 36, top + 200), wrap(body, font("reg", 27), cw - 72, d),
             font("reg", 27), SUB, spacing=14)

    pill(d, W // 2, top + ch + 52, "Done? Delete the folder — that's the whole uninstall.",
         font("semi", 29), (255, 255, 255), INK)
    save(img, "first_five_minutes.png")


# ══════════════════════════════════════════════════════════════════════
# 4. Row anatomy — reading one row of Who's Talking
# ══════════════════════════════════════════════════════════════════════
def row_anatomy():
    img, d = new_canvas(810)
    y = header(d, 60, "READING THE SCREEN", ["One row = one conversation."])

    # column callout labels over a mock row card
    cols = [  # (label, value, width-share)
        ("PROGRAM", "chrome.exe", 0.20, None),
        ("DESTINATION", "api.example.com", 0.24, None),
        ("DATA", "\u2191 2.1 MB   \u2193 14 MB", 0.22, None),
        ("SINCE", "09:41", 0.13, None),
        ("CONTENTS (OPT-IN)", "\U0001F50D view", 0.21, None),
    ]
    mx, cardw = 110, W - 220
    top = y + 96                     # leave room for callout labels
    ch = 130
    # callout labels + hairline connectors
    x = mx
    for label, val, share, _ in cols:
        cw = cardw * share
        f = font("bold", 21)
        d.text((x + cw / 2, top - 66), label, font=f, fill=SUB, anchor="ma")
        d.line([x + cw / 2, top - 38, x + cw / 2, top - 12], fill=BORDER, width=2)
        x += cw
    # the mock row card
    card(d, [mx, top, mx + cardw, top + ch], radius=30)
    x = mx
    for i, (label, val, share, _) in enumerate(cols):
        cw = cardw * share
        mono = label == "DATA" or label == "SINCE"
        f = font("mono" if mono else "reg", 29)
        col = BLUE if i == 0 else INK
        d.text((x + cw / 2, top + ch / 2), val, font=f, fill=col, anchor="mm")
        if i:  # column separators
            d.line([x, top + 26, x, top + ch - 26], fill=BORDER, width=2)
        x += cw

    # caption bullets
    by = top + ch + 64
    notes = [
        "Every row answers: who's talking, to whom, how much, for how long.",
        "The contents column appears only for programs you opted in — their words, readable.",
        "A row that surprises you is exactly the moment to click it — not before.",
    ]
    for n in notes:
        d.ellipse([W // 2 - 330, by + 13, W // 2 - 318, by + 25], fill=BLUE)
        d.text((W // 2 - 292, by), n, font=font("reg", 28), fill=SUB)
        by += 52
    save(img, "row_anatomy.png")


if __name__ == "__main__":
    why_looksee()
    app_map()
    first_five_minutes()
    row_anatomy()
    print("emoji rendering:", "color" if EMOJI_OK else "fallback")

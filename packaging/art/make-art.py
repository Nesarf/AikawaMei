#!/usr/bin/env python3
"""Installer art for AikawaMei, cut from the character image.

WHY THIS FILE EXISTS
--------------------
The three assets it writes were made once, by hand, and nothing recorded how. That is the shape of
artefact this project refuses everywhere else: unreproducible, and impossible to redo when the art
changes or a dimension turns out to be wrong -- which is exactly what happened the first time, when
the dialog's left panel was a square crop resized into a 493x312 frame and came out 48% narrower
than the drawing. Nobody could regenerate it correctly because there was nothing to regenerate it
from.

The generated files ARE committed. This script is not a build step and not a runtime dependency:
building a package never runs it. It needs Pillow, and it is run deliberately, when the art changes.

LAYOUT RULES, each of which cost something to learn
---------------------------------------------------
  * The dialog keeps its RIGHT side plain. Art bled across the full width made the wizard's own text
    unreadable, which is the one failure an installer dialog cannot have.
  * The banner keeps its LEFT side plain, because that is where the installer puts the page title.
  * Nothing is squashed. Every panel is cropped to the target aspect ratio FIRST and scaled
    uniformly afterwards. The script asserts the two ratios agree before it writes anything, so a
    wrong crop fails here rather than in a dialog nobody looks at until release.
  * The fill colour is SAMPLED from the source rather than declared. Both sources sit on near-white,
    so taking the corner pixel makes the seam between the art and the plain area invisible, and it
    survives the art being replaced with a differently-lit drawing.

USAGE
-----
    python3 packaging/art/make-art.py --source <portrait.png> --icon <icon.png> --out packaging/wix

Both sources are expected to be RGBA or RGB PNGs. The script prints what it wrote and the aspect
ratios it checked.
"""

import argparse
import os
import sys

try:
    from PIL import Image
except ImportError:  # pragma: no cover - the message is the point
    sys.exit("This tool needs Pillow (pip install Pillow). It is packaging-time only; the assets it "
             "writes are committed, so building a package does not need it.")

# WiX fixes these. They are not preferences.
BANNER = (493, 58)
DIALOG = (493, 312)
DIALOG_ART_WIDTH = 150
ICON_SIZES = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]


def sample_fill(image, fallback=(250, 246, 244)):
    """The source's own background colour, so the plain area matches the art beside it."""
    rgb = image.convert("RGB")
    corners = [rgb.getpixel((0, 0)), rgb.getpixel((rgb.width - 1, 0)),
               rgb.getpixel((0, rgb.height - 1)), rgb.getpixel((rgb.width - 1, rgb.height - 1))]
    # Only accept it if it is actually light: a dark corner means the art reaches the edge, and a
    # wizard drawn on that would be unreadable.
    light = [c for c in corners if sum(c) / 3 >= 200]
    if not light:
        return fallback
    return tuple(sum(c[i] for c in light) // len(light) for i in range(3))


def crop_to_aspect(image, target_w, target_h):
    """Crop to the target aspect ratio, centred, WITHOUT scaling. Orientation follows the source."""
    want = target_w / target_h
    have = image.width / image.height
    if abs(have - want) < 1e-9:
        return image
    if have > want:
        # Source is wider than the target: take a centred slice of the width.
        new_w = int(round(image.height * want))
        left = (image.width - new_w) // 2
        return image.crop((left, 0, left + new_w, image.height))
    # Source is taller: take a slice of the height, from the top, because a portrait's subject is
    # at the top far more often than at the middle.
    new_h = int(round(image.width / want))
    return image.crop((0, 0, image.width, new_h))


def scaled(image, size):
    return image.resize(size, Image.LANCZOS)


def compose_dialog(portrait):
    """Art on the left in a panel of its own, plain to the right for the wizard's text."""
    fill = sample_fill(portrait)
    canvas = Image.new("RGB", DIALOG, fill)
    art = crop_to_aspect(portrait, DIALOG_ART_WIDTH, DIALOG[1])
    # The assertion the first version needed: what was cropped must already have the panel's shape
    # before anything is resized, or the resize is a squash.
    assert abs((art.width / art.height) - (DIALOG_ART_WIDTH / DIALOG[1])) < 1e-3, "crop is not the panel's shape"
    canvas.paste(scaled(art.convert("RGB"), (DIALOG_ART_WIDTH, DIALOG[1])), (0, 0))
    return canvas


def face_box(portrait, size):
    """A square around the head, centred horizontally and starting in the upper third.

    The default is a guess about a particular drawing, which is why it is a parameter. A banner is
    58px tall: what lands there has to be the face, and where the face is is a decision a person
    makes about the artwork rather than something to derive.
    """
    size = min(size, portrait.width, portrait.height)
    left = (portrait.width - size) // 2
    top = max(0, int(portrait.height * 0.04))
    return (left, top, left + size, top + size)


def fade_left_edge(image, fade=14):
    """Alpha-fade the left edge of a crop.

    A square crop pasted onto a flat fill reads as a pasted rectangle the moment the drawing reaches
    its own border -- which a head with hair and ornaments does on every side. At 58px tall the
    rectangle is more noticeable than the face, so the edge is faded into the fill instead.
    """
    mask = Image.new("L", image.size, 255)
    px = mask.load()
    span = max(1, min(fade, image.width))
    for x in range(span):
        v = int(255 * (x / span))
        for y in range(image.height):
            px[x, y] = v
    out = image.convert("RGBA")
    out.putalpha(mask)
    return out


def compose_banner(portrait, face):
    """The face small on the right, plain on the left where the page title goes.

    Cut from the SAME source as the dialog panel, so both share one background colour and the
    pasted square leaves no edge. An earlier version pasted the icon here, whose background is a
    slightly different white -- visible as a faint rectangle around the face, which is the kind of
    thing only looking at the output catches.
    """
    fill = sample_fill(portrait)
    canvas = Image.new("RGB", BANNER, fill)
    side = BANNER[1]
    crop = portrait.crop(face) if face else portrait
    face_img = scaled(crop_to_aspect(crop, 1, 1).convert("RGB"), (side, side))
    canvas.paste(fade_left_edge(face_img), (BANNER[0] - side - 6, 0), fade_left_edge(face_img))
    return canvas


def main():
    ap = argparse.ArgumentParser(description="Regenerate the installer art from a character image.")
    ap.add_argument("--source", required=True, help="full-body portrait PNG")
    ap.add_argument("--icon", required=True, help="square face PNG, used for the banner and the icon")
    ap.add_argument("--out", required=True, help="directory to write into (packaging/wix)")
    ap.add_argument("--face-size", type=int, default=760,
                    help="side of the square cropped around the head for the banner, in source pixels")
    ap.add_argument("--face-top", type=float, default=0.04,
                    help="where that square starts, as a fraction of the source height")
    args = ap.parse_args()

    portrait = Image.open(args.source)
    icon = Image.open(args.icon)
    os.makedirs(args.out, exist_ok=True)

    box = face_box(portrait, args.face_size)
    box = (box[0], max(0, int(portrait.height * args.face_top)), box[2],
           max(0, int(portrait.height * args.face_top)) + (box[3] - box[1]))
    banner = compose_banner(portrait, box)
    assert banner.size == BANNER, banner.size
    banner_path = os.path.join(args.out, "wix-banner.bmp")
    banner.save(banner_path, "BMP")
    print("  %-22s %s  face box %s  fill=%s"
          % (os.path.basename(banner_path), banner.size, box, sample_fill(portrait)))

    dialog = compose_dialog(portrait)
    assert dialog.size == DIALOG, dialog.size
    dialog_path = os.path.join(args.out, "wix-dialog.bmp")
    dialog.save(dialog_path, "BMP")
    print("  %-22s %s  art panel %dpx wide, fill=%s"
          % (os.path.basename(dialog_path), dialog.size, DIALOG_ART_WIDTH, sample_fill(portrait)))

    ico_path = os.path.join(args.out, "aikawamei.ico")
    icon.convert("RGBA").save(ico_path, sizes=ICON_SIZES)
    written = Image.open(ico_path)
    print("  %-22s %s" % (os.path.basename(ico_path), sorted(written.info.get("sizes", []))))
    if len(written.info.get("sizes", [])) < len(ICON_SIZES):
        sys.exit("the icon did not keep every size asked for")
    for path in (banner_path, dialog_path, ico_path):
        print("  wrote %s (%d bytes)" % (path, os.path.getsize(path)))


if __name__ == "__main__":
    main()

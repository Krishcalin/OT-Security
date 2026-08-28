#!/usr/bin/env python3
"""
Derive the console's brand assets from the supplied master artwork.

    python tools/build_brand_assets.py            # rebuild
    python tools/build_brand_assets.py --check    # fail if committed assets drift

`docs/brand/otsec-master.png` is the supplied artwork. Everything under
`console/public/otsec-*.png` is generated from it and committed, so a deployment
needs nothing but the repository. Pillow is required to RUN this and is
deliberately not in `requirements.txt`: the container never builds assets.

WHY THE FIELD IS KEPT
─────────────────────
The master is ink on a flat blue field, not ink on transparency, and the field
is NOT incidental packaging. Read this before adding a `key_out` step.

Un-mixing a pixel against a target ink projects it onto that ink's axis, so any
ink LIGHTER than the field yields a negative coefficient, clamps to zero, and is
written fully transparent. This artwork has three such regions: the shield's
silver bevel, the pale blue circuit traces, and the PLC/RTU/SCADA glyphs around
the shield, all of which are lighter than #82c2e5. Keying the field out erases
them and leaves a floating navy blob.

MonitorRisk shipped exactly that mistake — its build keyed a cream field out
from under a white "Risk" and the console rendered the product as "Monitor",
with a valid RGBA PNG, correct dimensions and a green suite, because the only
assertion checked the file's colour type.

And there is no page colour that would fix it. The lockup carries dark navy ink
AND a silver bevel; navy needs a light ground and silver needs a dark one. So
the lockup KEEPS ITS FIELD and is a self-contained brand panel, and the panel
behind it (`.login-brand-side`) is painted the same value — `--brand-field` in
console.css. A test asserts the asset and the stylesheet still agree.

WHAT THE BUILD ACTUALLY DOES
────────────────────────────
1. Detects the field colour from the border ring, which is field by construction.
2. Flattens every near-field pixel to exactly that value. The master is a lossy
   render whose "flat" background is ±14 levels of noise across ~71% of the
   image; collapsing it costs nothing visually and most of the file size.
3. Emits the lockup for the sign-in panel, and a square shield-only mark for the
   26px header slot and the favicon, where a wordmark is a smudge and the
   peripheral glyphs are noise.

The geometry is DETECTED, then checked against the measurements below. A master
that lands outside them stops the build rather than silently shipping a crop
through the middle of the wordmark.
"""
from __future__ import annotations

import argparse
import io
import os
import sys

try:
    from PIL import Image
except ImportError:                                          # pragma: no cover
    sys.exit("This needs Pillow: python -m pip install Pillow")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MASTER = os.path.join(ROOT, "docs", "brand", "otsec-master.png")
PUBLIC = os.path.join(ROOT, "console", "public")

LOGO = os.path.join(PUBLIC, "otsec-logo.png")
MARK = os.path.join(PUBLIC, "otsec-mark.png")

#: The lockup renders 352 CSS px wide (22rem). This is ~3x, which covers a 2x
#: display with room to spare and still compresses small.
LOGO_WIDTH = 1000
#: The mark renders at 26px in the header and 16px in a tab. 256 is ample and
#: keeps the file trivial.
MARK_SIZE = 256

#: Both assets ship as 256-colour PNGs. Measured on this master: the palette
#: costs an RMS error of 2.88/255 against truecolour and takes the lockup from
#: 457 KB to 152 KB. Downscaling instead is strictly worse on both counts --
#: 800px truecolour is 303 KB at RMS 5.16 -- because the cost here is the
#: render's gradient noise, not its resolution. Dithering is off: it changes
#: neither size nor error on this image, and NONE is deterministic.
PALETTE_COLOURS = 256

#: Pixels within this distance of the detected field are flattened onto it.
#: Measured: at 14 this covers 71% of the master and leaves every real edge.
FIELD_TOLERANCE = 14

#: A pixel this much darker than the field is ink, not noise. Separates the
#: shield from the pale peripheral glyphs.
INK_GATE = 60

#: Measured on the supplied master (1200x896). The build DETECTS geometry and
#: asserts it lands near these; a master that does not is a different image and
#: must be re-measured rather than silently cropped.
EXPECT = {
    "size": (1200, 896),
    "field": (130, 194, 229),
    "shield_x": (370, 833),
    "shield_y": (74, 654),
}
TOLERANCE_PX = 40


def _luminance(colour) -> float:
    return 0.2126 * colour[0] + 0.7152 * colour[1] + 0.0722 * colour[2]


def detect_field(image: Image.Image):
    """The modal colour of the border ring, which is field by construction."""
    from collections import Counter
    width, height = image.size
    pixels = image.load()
    ring = []
    for x in range(0, width, 3):
        ring.append(pixels[x, 2])
        ring.append(pixels[x, height - 3])
    for y in range(0, height, 3):
        ring.append(pixels[2, y])
        ring.append(pixels[width - 3, y])
    return Counter(ring).most_common(1)[0][0]


def flatten_field(image: Image.Image, field, tolerance=FIELD_TOLERANCE):
    """Collapse the master's compression noise onto exactly the field colour.

    Purely a size win — the difference is invisible — but this file is loaded on
    every visit to the sign-in page.
    """
    out = image.copy()
    pixels = out.load()
    width, height = out.size
    for y in range(height):
        for x in range(width):
            colour = pixels[x, y]
            if all(abs(a - b) <= tolerance for a, b in zip(colour, field)):
                pixels[x, y] = field
    return out


def detect_shield(image: Image.Image, field):
    """The shield's bounding box, separated from the peripheral device glyphs.

    The glyphs are short spikes in the column profile; the shield is a sustained
    run. A gate on sustained height is what tells them apart.
    """
    width, height = image.size
    pixels = image.load()
    gate = _luminance(field) - INK_GATE

    rows = [sum(1 for x in range(0, width, 4)
                if _luminance(pixels[x, y]) < gate) for y in range(height)]
    bands, start = [], None
    for y, count in enumerate(rows):
        if count > 2 and start is None:
            start = y
        elif count <= 2 and start is not None:
            bands.append((start, y - 1))
            start = None
    if start is not None:
        bands.append((start, height - 1))
    if not bands:
        raise SystemExit("no ink found in the master — is it the right file?")
    top, bottom = max(bands, key=lambda b: b[1] - b[0])

    tall = bottom - top + 1
    columns = [sum(1 for y in range(top, bottom + 1)
                   if _luminance(pixels[x, y]) < gate) for x in range(width)]
    threshold = tall // 4
    runs, start = [], None
    for x, count in enumerate(columns):
        if count >= threshold and start is None:
            start = x
        elif count < threshold and start is not None:
            runs.append((start, x - 1))
            start = None
    if start is not None:
        runs.append((start, width - 1))
    runs = [r for r in runs if r[1] - r[0] > 20]
    if not runs:
        raise SystemExit("could not find the shield in the master")
    return runs[0][0], top, runs[-1][1], bottom


def _check_geometry(size, field, shield):
    """A master outside the measured envelope stops the build."""
    left, top, right, bottom = shield
    problems = []
    if size != EXPECT["size"]:
        problems.append("size %s, expected %s" % (size, EXPECT["size"]))
    if not all(abs(a - b) <= 12 for a, b in zip(field, EXPECT["field"])):
        problems.append("field %s, expected near %s" % (field, EXPECT["field"]))
    for name, got, want in (("shield left", left, EXPECT["shield_x"][0]),
                            ("shield right", right, EXPECT["shield_x"][1]),
                            ("shield top", top, EXPECT["shield_y"][0]),
                            ("shield bottom", bottom, EXPECT["shield_y"][1])):
        if abs(got - want) > TOLERANCE_PX:
            problems.append("%s %d, expected near %d" % (name, got, want))
    if problems:
        raise SystemExit(
            "the master does not match the measurements in this script:\n  "
            + "\n  ".join(problems)
            + "\n\nThis is a different image. Re-measure it and update EXPECT "
              "rather than loosening the check — the point of this gate is that "
              "a silent mis-crop through the wordmark passes every other test.")


def build():
    """Return {path: PIL image} without touching the filesystem.

    Images, not encoded bytes. PNG output differs between Pillow and zlib
    versions, and the CI matrix spans four Python legs that do not resolve to
    the same Pillow — so a byte comparison would report drift every time a
    runner upgraded, which trains people to ignore it. What actually matters is
    whether rebuilding would change the PICTURE.
    """
    master = Image.open(MASTER).convert("RGB")
    field = detect_field(master)
    shield = detect_shield(master, field)
    _check_geometry(master.size, field, shield)

    flat = flatten_field(master, field)

    logo = flat.resize(
        (LOGO_WIDTH, round(flat.height * LOGO_WIDTH / flat.width)),
        Image.LANCZOS)

    # The mark is the shield ALONE — cropped tight, then centred on a square of
    # field. Cropping to a square directly would drag the peripheral glyphs in,
    # and at 16px they are indistinguishable from dirt.
    left, top, right, bottom = shield
    cut = flat.crop((left, top, right + 1, bottom + 1))
    side = round(max(cut.size) * 1.12)               # 6% breathing room a side
    square = Image.new("RGB", (side, side), field)
    square.paste(cut, ((side - cut.width) // 2, (side - cut.height) // 2))
    mark = square.resize((MARK_SIZE, MARK_SIZE), Image.LANCZOS)

    out = {}
    for path, image in ((LOGO, logo), (MARK, mark)):
        # Quantise AFTER resizing, so the palette is chosen for the pixels that
        # actually ship. The field survives as exactly its own value, which is
        # what lets console.css name the same colour and match.
        out[path] = image.quantize(colors=PALETTE_COLOURS,
                                   method=Image.MEDIANCUT, dither=Image.NONE)
    return out, field


def encode(image) -> bytes:
    buffer = io.BytesIO()
    image.save(buffer, "PNG", optimize=True)
    return buffer.getvalue()


def differs(path, image) -> bool:
    """Whether the committed file is a different PICTURE from this image."""
    if not os.path.isfile(path):
        return True
    with Image.open(path) as committed:
        if committed.size != image.size:
            return True
        return committed.convert("RGB").tobytes() !=             image.convert("RGB").tobytes()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--check", action="store_true",
                        help="fail if the committed assets differ from a fresh "
                             "build, instead of writing them")
    args = parser.parse_args(argv)

    if not os.path.isfile(MASTER):
        raise SystemExit(
            "no master artwork at %s\nSee docs/brand/README.md."
            % os.path.relpath(MASTER, ROOT))

    assets, field = build()
    print("field #%02x%02x%02x" % field)

    drifted = []
    for path, image in assets.items():
        rel = os.path.relpath(path, ROOT)
        if args.check:
            bad = differs(path, image)
            if bad:
                drifted.append(rel)
            print("  %-34s %s" % (rel, "DRIFTED" if bad else "ok"))
        else:
            data = encode(image)
            with open(path, "wb") as handle:
                handle.write(data)
            print("  %-34s %d KB" % (rel, len(data) // 1024))

    if drifted:
        raise SystemExit(
            "committed brand assets differ from a fresh build: %s\n"
            "Run `python tools/build_brand_assets.py` and commit the result."
            % ", ".join(drifted))
    return 0


if __name__ == "__main__":
    sys.exit(main())

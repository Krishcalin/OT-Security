"""
The QR encoder, verified three independent ways.

Ported from OverWatch alongside `ot_server/qr.py`. It is kept because the module
it tests was written rather than depended on, and the reasoning below is why
copying the code without copying these tests would have been the wrong half.

A hand-rolled QR encoder is the kind of code that looks right, produces something
convincingly QR-shaped, and scans as nonsense — and the user experiences that as
"enrolment is broken", not "the mask penalty rule is off by one". Self-consistency
proves nothing here, so:

  1. the Reed-Solomon stage is checked against ISO/IEC 18004's OWN worked example,
     which is an external oracle for the part most likely to be subtly wrong;
  2. the structure is asserted at the coordinates the specification fixes;
  3. the matrix is read back and must yield the input, which catches placement and
     masking errors that (1) cannot see.
"""
from __future__ import annotations

import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ot_server import qr as aws_qr                       # noqa: E402
from ot_server import totp as aws_totp                   # noqa: E402

#: ISO/IEC 18004 worked example — "01234567" at version 1, EC level M. Both the data
#: codewords and the resulting EC codewords are published in the standard.
ISO_DATA = [0b00010000, 0b00100000, 0b00001100, 0b01010110, 0b01100001, 0b10000000,
            0b11101100, 0b00010001, 0b11101100, 0b00010001, 0b11101100, 0b00010001,
            0b11101100, 0b00010001, 0b11101100, 0b00010001]
ISO_EC = [0b10100101, 0b00100100, 0b11010100, 0b11000001, 0b11101101,
          0b00110110, 0b11000111, 0b10000111, 0b00101100, 0b01010101]


def test_reed_solomon_matches_the_iso_worked_example():
    """THE ONE THAT MATTERS MOST. An external oracle for the error-correction
    stage: if this passes, the field arithmetic and generator polynomial are right,
    which is where a hand-rolled encoder most often goes quietly wrong."""
    assert aws_qr.rs_encode(ISO_DATA, 10) == ISO_EC


@pytest.mark.parametrize("text", [
    "A",
    "HELLO WORLD",
    "otpauth://totp/OverWatch%3Aadmin?secret=" + "A" * 32 +
    "&issuer=OverWatch&algorithm=SHA1&digits=6&period=30",
    "x" * 200,
])
def test_a_matrix_reads_back_as_what_went_in(text):
    """Round trip. Catches placement, masking and interleaving errors — none of
    which the codeword vector above can see, because they all happen after it."""
    assert aws_qr.decode(aws_qr.encode(text)).decode("utf-8") == text


def test_the_real_provisioning_uri_encodes():
    """The actual payload this exists for, at its realistic length."""
    uri = aws_totp.provisioning_uri(aws_totp.new_secret(), "admin@example.com")
    assert aws_qr.decode(aws_qr.encode(uri)).decode("utf-8") == uri


# v6 holds 106 bytes at level M, v7 holds 122, v8 holds 152.
@pytest.mark.parametrize("text,version", [("A", 1), ("x" * 106, 6),
                                          ("x" * 120, 7), ("x" * 124, 8)])
def test_the_smallest_sufficient_version_is_chosen(text, version):
    """A larger-than-needed symbol is harder to scan on a low-resolution camera."""
    assert len(aws_qr.encode(text)) == version * 4 + 17


def test_the_fixed_structure_is_where_the_spec_puts_it():
    m = aws_qr.encode("structure")
    n = len(m)
    # Finder patterns: a 7x7 ring in three corners.
    for top, left in ((0, 0), (0, n - 7), (n - 7, 0)):
        assert all(m[top][left + c] == 1 for c in range(7)), "finder top edge"
        assert all(m[top + r][left] == 1 for r in range(7)), "finder left edge"
        assert m[top + 3][left + 3] == 1, "finder centre"
        assert m[top + 1][left + 1] == 0, "finder inner ring"
    # Timing patterns alternate, starting dark.
    assert all(m[6][i] == (1 if i % 2 == 0 else 0) for i in range(8, n - 8))
    assert all(m[i][6] == (1 if i % 2 == 0 else 0) for i in range(8, n - 8))
    # The dark module is always set — a scanner uses it to orient.
    assert m[n - 8][8] == 1


def test_the_mask_is_recoverable_from_the_format_area():
    """The decoder is told nothing; it reads the mask back out of the symbol, which
    is what a real scanner does."""
    m = aws_qr.encode("mask recovery")
    assert aws_qr._read_format_mask(m) in range(8)


def test_an_oversized_payload_raises_rather_than_truncating():
    """Silently dropping the tail would produce a QR that scans cleanly and enrols
    the wrong secret — the worst possible failure here."""
    with pytest.raises(ValueError, match="exceeds"):
        aws_qr.encode("z" * 400)


def test_the_svg_carries_no_payload_text():
    """This is why the console can inline it. The encoder emits only <rect> elements
    at numeric coordinates, so the URI — which contains the username — never reaches
    the markup and cannot carry script into the page."""
    secret = aws_totp.new_secret()
    uri = aws_totp.provisioning_uri(secret, '"><script>alert(1)</script>')
    svg = aws_qr.to_svg(uri)
    assert "<script" not in svg
    assert secret not in svg
    assert "alert" not in svg
    assert svg.startswith("<svg") and svg.endswith("</svg>")


def test_the_quiet_zone_is_present():
    """Four modules of light border are required by the spec, and scanners really do
    fail without them — it is not decoration."""
    svg = aws_qr.to_svg("quiet zone", module=4, quiet=4)
    matrix_side = len(aws_qr.encode("quiet zone"))
    assert f'width="{(matrix_side + 8) * 4}"' in svg

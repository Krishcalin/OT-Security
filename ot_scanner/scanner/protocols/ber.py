"""
A deliberately small BER/ASN.1 reader, shared by the protocols that need one.

SNMP and MMS both encode BER, and both are read here for the same purpose:
pulling a vendor, a model and a version out of a device's own answer about
itself. Two readers would drift, and the failure mode of a drifted ASN.1 parser
is not a crash — it is a subtly wrong string written into an inventory.

It is small on purpose. This reads definite-length, single-byte-tag elements,
which is all either protocol uses in the messages that carry identification.
Indefinite length and multi-byte tags raise rather than being half-supported,
because a parser that guesses at a length it does not understand produces
attacker-controlled garbage in an operator's asset list.

Every function here raises ValueError on malformed input. Callers on the capture
path are expected to catch it: a malformed frame is normal on a live network.
"""
from __future__ import annotations

from typing import Iterator, Tuple

TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30

#: Context-specific primitive tags [0]..[3], as used for IMPLICIT fields.
CONTEXT_0 = 0x80
CONTEXT_1 = 0x81
CONTEXT_2 = 0x82
CONTEXT_3 = 0x83

#: A single element longer than this is not identification data.
MAX_ELEMENT = 65535


def read_length(data: bytes, index: int) -> Tuple[int, int]:
    """BER length at `index` -> (length, index after it)."""
    if index >= len(data):
        raise ValueError("truncated BER length")
    first = data[index]
    index += 1
    if first < 0x80:
        return first, index
    if first == 0x80:
        # Indefinite length. Legal BER, but it requires scanning for an
        # end-of-contents marker, and neither protocol read here uses it.
        raise ValueError("indefinite BER length is not supported")
    count = first & 0x7F
    if count > 4 or index + count > len(data):
        raise ValueError("unsupported BER length")
    value = int.from_bytes(data[index:index + count], "big")
    if value > MAX_ELEMENT:
        raise ValueError("BER element implausibly long")
    return value, index + count


def read_tlv(data: bytes, index: int = 0) -> Tuple[int, bytes, int]:
    """One element -> (tag, value, index after it)."""
    if index + 2 > len(data):
        raise ValueError("truncated BER element")
    tag = data[index]
    length, index = read_length(data, index + 1)
    if index + length > len(data):
        raise ValueError("BER element longer than the buffer")
    return tag, data[index:index + length], index + length


def elements(data: bytes) -> Iterator[Tuple[int, bytes]]:
    """Walk a constructed value's children, stopping at the first bad one.

    Stopping rather than raising: a message whose tail is unreadable has often
    already yielded the fields worth having, and discarding those would lose
    identification that was correctly parsed.
    """
    index = 0
    while index < len(data):
        try:
            tag, value, index = read_tlv(data, index)
        except ValueError:
            return
        yield tag, value


def read_integer(raw: bytes) -> int:
    return int.from_bytes(raw, "big", signed=True) if raw else 0


def read_oid(raw: bytes) -> str:
    """BER OBJECT IDENTIFIER to dotted decimal."""
    if not raw:
        return ""
    parts = [str(raw[0] // 40), str(raw[0] % 40)]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def read_string(raw: bytes) -> str:
    """A VisibleString / OCTET STRING as text, without its padding.

    `replace` rather than `strict`: a device that puts a stray byte in its own
    model name should still appear in the inventory, with the rest of the name
    readable.
    """
    return raw.split(b"\x00")[0].decode("utf-8", "replace").strip()

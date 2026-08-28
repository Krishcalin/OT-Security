"""
Whether a device is still supported (Dragos ledger #5).

Platform 3.1 added "OT Asset Lifecycle Management", surfacing whether a device
remains supported or has reached end of life. The estate already fingerprints
vendor, model and firmware, which are the keys such an answer needs.

WHY NO LIFECYCLE DATA SHIPS WITH THIS
─────────────────────────────────────
The CVE corpus ships because CISA publishes it and it can be checked. Vendor
end-of-support dates cannot: they live in advisories, in contracts, and in
whatever a utility negotiated. Writing a plausible-looking table of them into
this repository would produce a screen that says a Siemens S7-300 is out of
support on a date nobody verified — and somebody may schedule a replacement
against it.

So this ships the mechanism and no data. Lifecycle records arrive as a
server-side content pack (D10), the same lane the CVE corpus uses and for the
same reason: they are volatile facts about the outside world, they never touch a
collector, and refreshing them re-answers the whole estate without contacting a
Pi. An operator loads what their vendor told them, and the source travels with
every record so a person reading the screen knows whose claim it is.

THE DEFAULT IS NOT "SUPPORTED"
──────────────────────────────
This is the whole of it. A device with no lifecycle record is `unknown`, and a
device this estate could not identify well enough to look up is `unidentified` —
two different gaps, and neither of them is a statement that the device is fine.

Rendering an absent record as "supported" is the same failure as reporting an
unassessed asset as clean, or a switched-off collector as a healthy one. This
system has made that mistake twice already in code that was tested; here it is
refused by construction, and `unknown` carries the loudest badge on the row.

WHAT END OF SUPPORT MEANS FOR A FINDING
───────────────────────────────────────
It is not a maintenance note. A CVE on a device past end of support will never
be patched — not this quarter, not next year, not ever — so containment (D11)
stops being the pragmatic option and becomes the only one. `bearing_on_findings`
says that in the terms an operator acts on.
"""
# NOTE: no `from __future__ import annotations` — imported by api.py's route
# factory, where postponed evaluation breaks FastAPI's annotation resolution.

import datetime
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

#: Still sold and still fixed.
SUPPORTED = "supported"
#: No longer sold, still fixed. Worth planning around, not worth alarming on.
END_OF_SALE = "end_of_sale"
#: Past the date. No fix is coming for anything found on it, ever.
END_OF_SUPPORT = "end_of_support"
#: A record exists and says the device is retired entirely.
END_OF_LIFE = "end_of_life"
#: No lifecycle record covers this vendor and model. NOT "supported".
UNKNOWN = "unknown"
#: The estate could not identify the device well enough to look one up.
UNIDENTIFIED = "unidentified"

#: The states that mean no fix is coming.
UNSUPPORTED = (END_OF_SUPPORT, END_OF_LIFE)


@dataclass
class Record:
    """One vendor's claim about one product family."""

    vendor: str = ""
    product_pattern: str = ""
    status: str = SUPPORTED
    end_of_sale: str = ""
    end_of_support: str = ""
    #: Whose claim this is. Travels to the screen: an operator reading "end of
    #: support" should know whether that came from the vendor or from a
    #: spreadsheet somebody maintained.
    source: str = ""
    note: str = ""


@dataclass
class AssetLifecycle:
    estate_id: str = ""
    vendor: str = ""
    model: str = ""
    status: str = UNIDENTIFIED
    end_of_sale: str = ""
    end_of_support: str = ""
    source: str = ""
    reason: str = ""
    #: What this means for the findings on this device, when it means anything.
    bearing_on_findings: str = ""

    @property
    def fixes_are_coming(self) -> Optional[bool]:
        """True, False, or None for "we do not know" — never a bare bool."""
        if self.status in UNSUPPORTED:
            return False
        if self.status in (SUPPORTED, END_OF_SALE):
            return True
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {"estate_id": self.estate_id, "vendor": self.vendor,
                "model": self.model, "status": self.status,
                "end_of_sale": self.end_of_sale,
                "end_of_support": self.end_of_support, "source": self.source,
                "reason": self.reason,
                "fixes_are_coming": self.fixes_are_coming,
                "bearing_on_findings": self.bearing_on_findings}


def load_records(payload: Optional[Dict[str, Any]]) -> List[Record]:
    """Lifecycle records from a `lifecycle` content pack payload.

    An absent or malformed pack yields no records, which makes every asset
    `unknown` — the honest consequence, and visibly not a clean estate.
    """
    out: List[Record] = []
    for raw in ((payload or {}).get("lifecycle") or []):
        if not isinstance(raw, dict):
            continue
        vendor = str(raw.get("vendor") or "").strip()
        pattern = str(raw.get("product_pattern") or "").strip()
        if not vendor or not pattern:
            # A record that names no product cannot be matched to one, and a
            # record matched to everything would be worse than none.
            continue
        out.append(Record(
            vendor=vendor, product_pattern=pattern,
            status=str(raw.get("status") or SUPPORTED),
            end_of_sale=str(raw.get("end_of_sale") or ""),
            end_of_support=str(raw.get("end_of_support") or ""),
            source=str(raw.get("source") or "unattributed"),
            note=str(raw.get("note") or "")))
    return out


def _matches(record: Record, vendor: str, model: str) -> bool:
    if record.vendor.lower() not in vendor.lower():
        return False
    try:
        return bool(re.search(record.product_pattern, model, re.IGNORECASE))
    except re.error:
        # A record whose pattern will not compile matches nothing rather than
        # everything. A broken record must not quietly become a wildcard.
        return False


def _past(date_text: str, today: datetime.date) -> Optional[bool]:
    if not date_text:
        return None
    try:
        return datetime.date.fromisoformat(date_text[:10]) <= today
    except ValueError:
        return None


def assess(asset: Dict[str, Any], records: List[Record],
           today: Optional[datetime.date] = None) -> AssetLifecycle:
    """One device's lifecycle position, or an honest account of why not."""
    today = today or datetime.date.today()
    attrs = asset.get("attributes") or {}
    vendor = str(attrs.get("vendor") or "").strip()
    model = str(attrs.get("model") or "").strip()

    result = AssetLifecycle(
        estate_id=str(asset.get("estate_id") or ""), vendor=vendor, model=model)

    if not vendor or not model:
        result.status = UNIDENTIFIED
        result.reason = (
            "this device has no %s in the inventory, so no lifecycle record "
            "could be looked up. That is a gap in what was observed, not a "
            "statement about the device."
            % ("vendor or model" if not vendor and not model
               else "vendor" if not vendor else "model"))
        return result

    match = next((r for r in records if _matches(r, vendor, model)), None)
    if match is None:
        result.status = UNKNOWN
        result.reason = (
            "no lifecycle record covers %s %s. This is NOT a statement that it "
            "is supported — nobody has told this server either way."
            % (vendor, model))
        return result

    result.end_of_sale = match.end_of_sale
    result.end_of_support = match.end_of_support
    result.source = match.source

    # Dates decide, where there are dates; the record's own status is the
    # fallback so a vendor can say "retired" without picking a day.
    if _past(match.end_of_support, today):
        result.status = END_OF_SUPPORT
    elif match.status in UNSUPPORTED:
        result.status = match.status
    elif _past(match.end_of_sale, today):
        result.status = END_OF_SALE
    else:
        result.status = SUPPORTED

    result.reason = _reason(result, match)
    result.bearing_on_findings = _bearing(result)
    return result


def _reason(result: AssetLifecycle, record: Record) -> str:
    if result.status == END_OF_SUPPORT:
        return ("support ended %s according to %s"
                % (record.end_of_support or "on a date not recorded",
                   record.source))
    if result.status == END_OF_LIFE:
        return "recorded as retired by %s" % record.source
    if result.status == END_OF_SALE:
        return ("no longer sold as of %s, still supported until %s (%s)"
                % (record.end_of_sale, record.end_of_support or "a date not "
                   "recorded", record.source))
    return ("supported%s, according to %s"
            % (" until " + record.end_of_support if record.end_of_support
               else "", record.source))


def _bearing(result: AssetLifecycle) -> str:
    """What the lifecycle state means for the findings on this device."""
    if result.status in UNSUPPORTED:
        return ("no fix is coming for anything found on this device, so "
                "containment is not the pragmatic option here — it is the only "
                "one")
    if result.status == END_OF_SALE:
        return ("fixes still arrive, but a replacement cannot be bought; plan "
                "the migration before support ends rather than after")
    return ""


def assess_estate(assets: List[Dict[str, Any]], records: List[Record],
                  today: Optional[datetime.date] = None
                  ) -> Dict[str, AssetLifecycle]:
    return {str(a.get("estate_id") or ""): assess(a, records, today)
            for a in assets or []}


def summarise(results: Dict[str, AssetLifecycle],
              records_loaded: int) -> Dict[str, Any]:
    values = list(results.values())
    counts: Dict[str, int] = {}
    for item in values:
        counts[item.status] = counts.get(item.status, 0) + 1

    unsupported = [i.estate_id for i in values if i.status in UNSUPPORTED]
    return {
        "records_loaded": records_loaded,
        "assessed": len(values),
        "counts": counts,
        "unsupported": sorted(unsupported),
        "explain": _explain(len(values), counts, records_loaded),
    }


def _explain(total: int, counts: Dict[str, int], records_loaded: int) -> str:
    if records_loaded == 0:
        return ("no lifecycle records are loaded, so every device is unknown. "
                "That is not a supported estate — it is an unassessed one. "
                "Publish a `lifecycle` content pack to answer this.")
    if not total:
        return "no devices to assess"

    unsupported = counts.get(END_OF_SUPPORT, 0) + counts.get(END_OF_LIFE, 0)
    unknown = counts.get(UNKNOWN, 0)
    unidentified = counts.get(UNIDENTIFIED, 0)

    parts = ["%d device(s)" % total]
    if unsupported:
        parts.append("%d past end of support, where no fix is coming for "
                     "anything found on them" % unsupported)
    if counts.get(END_OF_SALE):
        parts.append("%d no longer sold" % counts[END_OF_SALE])
    if unknown:
        parts.append("%d with no lifecycle record, which is unassessed rather "
                     "than supported" % unknown)
    if unidentified:
        parts.append("%d the estate could not identify well enough to look up"
                     % unidentified)
    return "; ".join(parts)

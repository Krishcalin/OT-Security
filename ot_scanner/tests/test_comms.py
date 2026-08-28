"""
Who talks to whom (Dragos ledger #6).

The load-bearing test is `test_a_direction_is_not_stated_over_a_guessed_level`.

Direction is the analytic here: a list sorted by packet count is a network graph
and an operator already has one. What they do not have is "is anything reaching
down into the control layer from above", which is what segmentation exists to
prevent. But calling a flow a segmentation concern when one of its two Purdue
levels came from the topology engine's fallback would be the same error D6, D11
and D12 all refuse — a confident statement resting on a guess.
"""
from __future__ import annotations

import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ot_server import comms                                 # noqa: E402


class _Zone:
    def __init__(self, zone_id, level):
        self.zone_id = zone_id
        self.purdue_level = level


def _lookup(mapping):
    """`ip -> (zone, basis)`, in the shape containment.zone_of returns."""
    def for_site(_site):
        def resolve(ip):
            return mapping.get(ip, (None, "unknown"))
        return resolve
    return for_site


def _flow(src, dst, protocol="modbus", port=502, packets=100,
          collector="pi-a"):
    return {"flow_key": src + dst, "collector_id": collector,
            "observation_count": packets,
            "attributes": {"src_ip": src, "dst_ip": dst,
                           "protocol": protocol, "dst_port": str(port),
                           "packet_count": packets}}


def _asset(ip, site="Alderley", vendor="Siemens", model="S7-1500",
           role="plc"):
    return {"estate_id": "site:%s/ip:%s" % (site, ip), "ip": ip, "site": site,
            "coverage": "complete",
            "attributes": {"ip": ip, "vendor": vendor, "model": model,
                           "role": role}}


CONTROL = _Zone("zone_l1", 1)
SUPERVISORY = _Zone("zone_l2", 2)
GUESSED = _Zone("zone_x", 1)


# ── direction ──────────────────────────────────────────────────────────────

def test_a_higher_level_reaching_a_lower_one_runs_downstream():
    """Toward the process. Named for the direction of consequence rather than
    the direction of the number."""
    src = comms.Endpoint(purdue_level=2, zone_basis="role")
    dst = comms.Endpoint(purdue_level=1, zone_basis="role")
    assert comms.direction_of(src, dst) == comms.DOWNSTREAM


def test_a_controller_reporting_upward_is_ordinary():
    src = comms.Endpoint(purdue_level=1, zone_basis="role")
    dst = comms.Endpoint(purdue_level=3, zone_basis="role")
    assert comms.direction_of(src, dst) == comms.UPSTREAM


def test_within_one_level_is_lateral():
    src = comms.Endpoint(purdue_level=1, zone_basis="role")
    dst = comms.Endpoint(purdue_level=1, zone_basis="protocol")
    assert comms.direction_of(src, dst) == comms.LATERAL


@pytest.mark.parametrize("src_basis,dst_basis,src_level,dst_level", [
    ("defaulted", "role", 2, 1),
    ("role", "defaulted", 2, 1),
    ("role", "role", -1, 1),
    ("role", "role", 2, -1),
])
def test_a_direction_is_not_stated_over_a_guessed_level(src_basis, dst_basis,
                                                        src_level, dst_level):
    """THE test. A level that came from the fallback, or that was never derived
    at all, cannot support a claim about which way a conversation runs."""
    src = comms.Endpoint(purdue_level=src_level, zone_basis=src_basis)
    dst = comms.Endpoint(purdue_level=dst_level, zone_basis=dst_basis)
    assert comms.direction_of(src, dst) == comms.UNDETERMINED


def test_undetermined_is_not_lateral():
    """They would look the same on a screen and mean opposite things: one says
    the levels are equal, the other says we do not know them."""
    assert comms.UNDETERMINED != comms.LATERAL


# ── resolving the endpoints ────────────────────────────────────────────────

def test_both_endpoints_are_resolved_to_devices():
    items = comms.conversations(
        [_flow("10.0.2.60", "10.0.1.11")],
        [_asset("10.0.2.60", vendor="Advantech", model="", role="hmi"),
         _asset("10.0.1.11")],
        {"pi-a": "Alderley"},
        _lookup({"10.0.2.60": (SUPERVISORY, "role"),
                 "10.0.1.11": (CONTROL, "role")}))
    assert len(items) == 1
    conversation = items[0]
    assert conversation.src.label == "Advantech (hmi)"
    assert conversation.dst.label == "Siemens S7-1500 (plc)"
    assert conversation.direction == comms.DOWNSTREAM
    assert conversation.crosses_zone is True


def test_an_address_with_no_device_is_reported_not_dropped():
    """Same family as an orphaned detection: the estate has evidence of a
    device it cannot show."""
    items = comms.conversations(
        [_flow("10.0.9.9", "10.0.1.11")],
        [_asset("10.0.1.11")],
        {"pi-a": "Alderley"},
        _lookup({"10.0.1.11": (CONTROL, "role")}))
    assert items[0].src.unknown_device is True
    assert items[0].src.label == "10.0.9.9"
    assert "inventory holds no device" in items[0].note


def test_a_device_is_labelled_the_way_a_person_recognises_it():
    items = comms.conversations(
        [_flow("10.0.1.11", "10.0.1.12")],
        [_asset("10.0.1.11", vendor="ABB", model="RTU560", role="rtu"),
         _asset("10.0.1.12")],
        {"pi-a": "Alderley"}, _lookup({}))
    assert items[0].src.label == "ABB RTU560 (rtu)"


def test_addresses_are_resolved_within_their_own_site():
    """Both plants use 10.0.1.11. Resolving across sites would label one
    plant's conversation with the other plant's device."""
    items = comms.conversations(
        [_flow("10.0.1.40", "10.0.1.11", collector="pi-b")],
        [_asset("10.0.1.11", site="Alderley", vendor="Siemens"),
         _asset("10.0.1.11", site="Marchwood", vendor="Schneider"),
         _asset("10.0.1.40", site="Marchwood", vendor="Schneider",
                model="", role="rtu")],
        {"pi-b": "Marchwood"}, _lookup({}))
    assert "Schneider" in items[0].dst.label
    assert "Siemens" not in items[0].dst.label


def test_a_flow_missing_an_endpoint_is_skipped_rather_than_half_drawn():
    broken = _flow("10.0.1.11", "")
    assert comms.conversations([broken], [], {}, _lookup({})) == []


# ── ordering ───────────────────────────────────────────────────────────────

def test_downstream_conversations_come_first():
    """The ones segmentation exists to prevent should not be below a chatty
    lateral flow with a bigger packet count."""
    items = comms.conversations(
        [_flow("10.0.1.11", "10.0.1.12", packets=99999),
         _flow("10.0.2.60", "10.0.1.11", packets=5)],
        [_asset("10.0.1.11"), _asset("10.0.1.12"), _asset("10.0.2.60")],
        {"pi-a": "Alderley"},
        _lookup({"10.0.1.11": (CONTROL, "role"),
                 "10.0.1.12": (CONTROL, "role"),
                 "10.0.2.60": (SUPERVISORY, "role")}))
    assert items[0].direction == comms.DOWNSTREAM


# ── the summary ────────────────────────────────────────────────────────────

def test_an_empty_list_is_not_a_quiet_plant():
    summary = comms.summarise([], "complete", True)
    assert "not a statement that the plant is quiet" in summary["explain"]


def test_a_degraded_estate_makes_the_count_a_floor():
    items = comms.conversations(
        [_flow("10.0.1.11", "10.0.1.12")],
        [_asset("10.0.1.11"), _asset("10.0.1.12")],
        {"pi-a": "Alderley"}, _lookup({}))
    summary = comms.summarise(items, "1 collector dropped frames", False)
    assert "floor rather than a total" in summary["explain"]
    assert summary["trustworthy"] is False


def test_a_trustworthy_estate_gets_no_floor_caveat():
    items = comms.conversations(
        [_flow("10.0.1.11", "10.0.1.12")],
        [_asset("10.0.1.11"), _asset("10.0.1.12")],
        {"pi-a": "Alderley"}, _lookup({}))
    assert "floor rather than a total" not in \
        comms.summarise(items, "all complete", True)["explain"]


def test_the_summary_counts_undetermined_separately():
    """"We cannot state the direction" is not "the direction is fine"."""
    items = comms.conversations(
        [_flow("10.0.2.60", "10.0.1.11"), _flow("10.0.9.9", "10.0.1.12")],
        [_asset("10.0.1.11"), _asset("10.0.1.12"), _asset("10.0.2.60")],
        {"pi-a": "Alderley"},
        _lookup({"10.0.2.60": (SUPERVISORY, "role"),
                 "10.0.1.11": (CONTROL, "role")}))
    summary = comms.summarise(items, "complete", True)
    assert summary["downstream"] == 1
    assert summary["undetermined"] == 1
    assert "cannot be stated" in summary["explain"]
    assert summary["unknown_endpoints"] == ["10.0.9.9"]


# ── the route ──────────────────────────────────────────────────────────────

def test_the_communications_route_is_fail_closed():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from ot_server.api import create_app

    class _Store:
        def collector_sites(self):
            return {}

        def all_assets(self, limit=5000):
            return []

        def all_flows(self, limit=20000):
            return []

        def collector_ids(self):
            return []

    client = TestClient(create_app(_Store(), console_dir=""))
    assert client.get("/api/v1/estate/communications").status_code == 503

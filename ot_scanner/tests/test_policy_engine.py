"""Tests for PolicyEngine — rule generation and export."""

from scanner.models import OTDevice, CommFlow, NetworkZone, TopologyEdge
from scanner.policy.engine import PolicyEngine
from datetime import datetime


class TestRuleGeneration:
    def test_generates_rules_from_flows(self, sample_device, sample_hmi, sample_zones, sample_flows, sample_edges):
        engine = PolicyEngine(
            devices=[sample_device, sample_hmi],
            flows=sample_flows, zones=sample_zones,
            violations=[], edges=sample_edges,
        )
        ruleset = engine.generate()
        assert ruleset.total_rules > 0
        assert ruleset.rules  # not empty

    def test_implicit_deny_per_zone(self, sample_device, sample_hmi, sample_zones, sample_flows, sample_edges):
        engine = PolicyEngine(
            devices=[sample_device, sample_hmi],
            flows=sample_flows, zones=sample_zones,
            violations=[], edges=sample_edges,
        )
        ruleset = engine.generate()
        deny_rules = [r for r in ruleset.rules if r.action == "deny" and r.priority == 9999]
        assert len(deny_rules) > 0  # at least one deny-all per zone

    def test_rules_sorted_by_priority(self, sample_device, sample_hmi, sample_zones, sample_flows, sample_edges):
        engine = PolicyEngine(
            devices=[sample_device, sample_hmi],
            flows=sample_flows, zones=sample_zones,
            violations=[], edges=sample_edges,
        )
        ruleset = engine.generate()
        priorities = [r.priority for r in ruleset.rules]
        assert priorities == sorted(priorities)

    def test_sequential_rule_ids(self, sample_device, sample_hmi, sample_zones, sample_flows, sample_edges):
        engine = PolicyEngine(
            devices=[sample_device, sample_hmi],
            flows=sample_flows, zones=sample_zones,
            violations=[], edges=sample_edges,
        )
        ruleset = engine.generate()
        ids = [r.rule_id for r in ruleset.rules]
        assert ids[0] == "PR-001"
        assert ids[-1] == f"PR-{len(ids):03d}"

    def test_safety_system_isolation(self, safety_device, sample_zones, sample_flows, sample_edges):
        engine = PolicyEngine(
            devices=[safety_device],
            flows=sample_flows, zones=sample_zones,
            violations=[], edges=sample_edges,
        )
        ruleset = engine.generate()
        safety_deny = [r for r in ruleset.rules
                       if r.action == "deny" and "safety" in r.description.lower()]
        assert safety_deny

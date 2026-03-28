"""Tests for ConfigSnapshotEngine — capture, save, load, diff."""

import tempfile
import os
from scanner.models import OTDevice, ProtocolStats
from scanner.config.engine import ConfigSnapshotEngine


class TestSnapshotCapture:
    def test_capture_produces_configs(self, sample_device):
        engine = ConfigSnapshotEngine(tempfile.mkdtemp())
        configs = engine.capture([sample_device])
        assert len(configs) == 1
        assert configs[0].device_ip == "10.1.1.10"
        assert configs[0].firmware == "V4.5"
        assert "S7comm" in configs[0].protocol_list

    def test_capture_extracts_function_codes(self, sample_device):
        engine = ConfigSnapshotEngine(tempfile.mkdtemp())
        configs = engine.capture([sample_device])
        fc_profile = configs[0].function_code_profile
        assert "S7comm" in fc_profile
        assert "0x04 Read Var" in fc_profile["S7comm"]


class TestSnapshotPersistence:
    def test_save_and_load(self, sample_device):
        tmpdir = tempfile.mkdtemp()
        engine = ConfigSnapshotEngine(tmpdir)
        configs = engine.capture([sample_device])
        path = engine.save_snapshot(configs, "test.pcap")
        assert os.path.exists(path)

        loaded = engine.load_snapshot(path)
        assert len(loaded) == 1
        assert loaded[0].device_ip == "10.1.1.10"
        assert loaded[0].firmware == "V4.5"

    def test_index_maintained(self, sample_device):
        tmpdir = tempfile.mkdtemp()
        engine = ConfigSnapshotEngine(tmpdir)
        configs = engine.capture([sample_device])
        engine.save_snapshot(configs, "scan1.pcap")
        engine.save_snapshot(configs, "scan2.pcap")

        index = engine._load_index()
        assert len(index["snapshots"]) == 2

    def test_set_baseline(self, sample_device):
        tmpdir = tempfile.mkdtemp()
        engine = ConfigSnapshotEngine(tmpdir)
        configs = engine.capture([sample_device])
        path = engine.save_snapshot(configs, "baseline.pcap")
        engine.set_baseline(path)

        baseline = engine.load_latest()
        assert baseline is not None
        assert len(baseline) == 1


class TestDriftDetection:
    def test_firmware_change_detected(self, sample_device):
        tmpdir = tempfile.mkdtemp()
        engine = ConfigSnapshotEngine(tmpdir)

        old_configs = engine.capture([sample_device])
        sample_device.firmware = "V4.6"
        new_configs = engine.capture([sample_device])

        drift = engine.diff(old_configs, new_configs)
        assert sample_device.ip in drift
        types = {a.drift_type for a in drift[sample_device.ip]}
        assert "firmware_change" in types

    def test_program_event_detected(self, sample_device):
        tmpdir = tempfile.mkdtemp()
        engine = ConfigSnapshotEngine(tmpdir)

        old_configs = engine.capture([sample_device])
        sample_device.protocol_stats[0].has_program_download = True
        new_configs = engine.capture([sample_device])

        drift = engine.diff(old_configs, new_configs)
        assert sample_device.ip in drift
        types = {a.drift_type for a in drift[sample_device.ip]}
        assert "program_event" in types
        # Program events should be critical
        crit = [a for a in drift[sample_device.ip] if a.severity == "critical"]
        assert crit

    def test_no_drift_when_unchanged(self, sample_device):
        tmpdir = tempfile.mkdtemp()
        engine = ConfigSnapshotEngine(tmpdir)
        configs = engine.capture([sample_device])
        drift = engine.diff(configs, configs)
        assert len(drift) == 0

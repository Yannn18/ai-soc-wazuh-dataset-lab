#!/usr/bin/env python3
"""Unit tests for normalize_wazuh_alert.py"""
import json
import sys
from pathlib import Path

# Add scripts to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from normalize_wazuh_alert import (
    normalize,
    is_custom_ai_soc_alert,
    is_builtin_ssh_alert,
    extract_ssh_fields,
    extract_custom_fields,
    map_builtin_rule_to_attack,
    make_event_id,
    get_nested,
)


class TestGetNested:
    def test_get_nested_simple(self):
        obj = {"a": {"b": "value"}}
        assert get_nested(obj, "a.b") == "value"

    def test_get_nested_missing(self):
        obj = {"a": {}}
        assert get_nested(obj, "a.b", "default") == "default"

    def test_get_nested_not_dict(self):
        obj = {"a": "string"}
        assert get_nested(obj, "a.b", "default") == "default"


class TestMakeEventId:
    def test_deterministic(self):
        record = {
            "timestamp": "2026-10-28T07:06:05.246+0000",
            "agent_name": "Debian_VM",
            "rule_id": "5710",
            "raw_event": "test event"
        }
        id1 = make_event_id(record)
        id2 = make_event_id(record)
        assert id1 == id2
        assert id1.startswith("evt-")
        assert len(id1) == 20  # "evt-" + 16 chars

    def test_different_records_different_ids(self):
        record1 = {"timestamp": "2026-10-28T07:06:05", "agent_name": "A", "rule_id": "1", "raw_event": "x"}
        record2 = {"timestamp": "2026-10-28T07:06:05", "agent_name": "B", "rule_id": "1", "raw_event": "x"}
        assert make_event_id(record1) != make_event_id(record2)


class TestIsCustomAiSocAlert:
    def test_custom_decoded_as(self):
        alert = {"rule": {"decoded_as": "ai-soc-pentest"}}
        assert is_custom_ai_soc_alert(alert) is True

    def test_custom_program_name(self):
        alert = {"data": {"program_name": "ai-soc-pentest"}}
        assert is_custom_ai_soc_alert(alert) is True

    def test_not_custom(self):
        alert = {"rule": {"decoded_as": "syslog"}, "data": {"program_name": "sshd"}}
        assert is_custom_ai_soc_alert(alert) is False


class TestIsBuiltinSshAlert:
    def test_ssh_rule_range(self):
        alert = {"rule": {"id": 5715, "groups": ["syslog"]}}
        assert is_builtin_ssh_alert(alert) is True

    def test_ssh_group(self):
        alert = {"rule": {"id": 9999, "groups": ["sshd", "authentication_failed"]}}
        assert is_builtin_ssh_alert(alert) is True

    def test_not_ssh(self):
        alert = {"rule": {"id": 100, "groups": ["web", "attack"]}}
        assert is_builtin_ssh_alert(alert) is False


class TestExtractSshFields:
    def test_all_fields(self):
        alert = {"data": {"srcip": "192.168.1.1", "dstip": "10.0.0.1", "user": "admin", "srcport": "22", "dstport": "22", "protocol": "ssh2"}}
        fields = extract_ssh_fields(alert)
        assert fields["srcip"] == "192.168.1.1"
        assert fields["dstip"] == "10.0.0.1"
        assert fields["user"] == "admin"

    def test_alternative_field_names(self):
        alert = {"data": {"src_ip": "192.168.1.1", "dst_ip": "10.0.0.1", "username": "admin"}}
        fields = extract_ssh_fields(alert)
        assert fields["srcip"] == "192.168.1.1"
        assert fields["dstip"] == "10.0.0.1"
        assert fields["user"] == "admin"


class TestExtractCustomFields:
    def test_all_fields(self):
        alert = {"data": {"scenario_id": "ssh_brute_force_001", "attack_type": "ssh_brute_force", "mitre_tactic": "Credential Access", "mitre_technique": "T1110.001", "payload_id": "ssh_spray_1", "tool": "sshpass+ssh", "intensity": "low"}}
        fields = extract_custom_fields(alert)
        assert fields["scenario_id"] == "ssh_brute_force_001"
        assert fields["attack_type"] == "ssh_brute_force"
        assert fields["mitre_technique"] == "T1110.001"


class TestMapBuiltinRuleToAttack:
    def test_brute_force_rules(self):
        for rule_id in [5710, 5712, 5716]:
            result = map_builtin_rule_to_attack(rule_id, [])
            assert result["attack_type"] == "ssh_brute_force"
            assert result["mitre_technique"] == "T1110.001"

    def test_auth_success(self):
        result = map_builtin_rule_to_attack(5715, [])
        assert result["attack_type"] == "ssh_auth_success"
        assert result["mitre_technique"] == "T1021.004"

    def test_priv_esc(self):
        for rule_id in [5718, 5760]:
            result = map_builtin_rule_to_attack(rule_id, [])
            assert result["attack_type"] == "ssh_priv_esc"
            assert result["mitre_technique"] == "T1548.003"

    def test_group_based(self):
        result = map_builtin_rule_to_attack(9999, ["authentication_failed"])
        assert result["attack_type"] == "ssh_brute_force"

    def test_unknown_fallback(self):
        result = map_builtin_rule_to_attack(9999, ["other"])
        assert result["attack_type"] == "ssh_unknown"
        assert result["mitre_technique"] == "unknown"


class TestNormalize:
    def test_custom_alert(self):
        alert = {
            "timestamp": "2026-10-28T07:06:05.246+0000",
            "rule": {"id": "100001", "level": 7, "description": "Custom pentest alert", "decoded_as": "ai-soc-pentest", "groups": ["custom"]},
            "agent": {"name": "test-agent", "ip": "192.168.1.10"},
            "data": {"scenario_id": "ssh_brute_force_001", "attack_type": "ssh_brute_force", "mitre_tactic": "Credential Access", "mitre_technique": "T1110.001", "payload_id": "ssh_spray_1", "tool": "sshpass+ssh", "intensity": "low"},
            "full_log": '{"scenario_id": "ssh_brute_force_001", ...}'
        }
        record = normalize(alert)
        assert record["alert_source"] == "custom_ai_soc"
        assert record["scenario_id"] == "ssh_brute_force_001"
        assert record["attack_type"] == "ssh_brute_force"
        assert record["mitre_technique"] == "T1110.001"
        assert record["agent_name"] == "test-agent"
        assert record["event_id"].startswith("evt-")

    def test_builtin_ssh_alert(self):
        alert = {
            "timestamp": "2026-10-28T07:06:05.246+0000",
            "rule": {"id": "5715", "level": 3, "description": "sshd: authentication success", "groups": ["sshd", "authentication_success"]},
            "agent": {"name": "Debian_VM", "ip": "192.168.0.7"},
            "data": {"srcip": "192.168.56.1", "srcport": "56574", "dstuser": "admin1"},
            "full_log": "Oct 28 07:06:47 10 sshd-session[1779]: Accepted publickey for admin1 from 192.168.56.1 port 56574 ssh2"
        }
        record = normalize(alert)
        assert record["alert_source"] == "builtin_ssh"
        assert record["attack_type"] == "ssh_auth_success"
        assert record["mitre_technique"] == "T1021.004"
        assert record["agent_name"] == "Debian_VM"
        assert record["source_ip"] == "192.168.56.1"
        assert record["ssh_user"] == "admin1"

    def test_other_alert(self):
        alert = {
            "timestamp": "2026-10-22T02:16:50.008+0000",
            "rule": {"id": "503", "level": 3, "description": "Wazuh agent started", "groups": ["ossec"]},
            "agent": {"name": "owasp_juice_server", "ip": "10.0.2.15"},
            "full_log": "ossec: Agent started: 'owasp_juice_server->any'."
        }
        record = normalize(alert)
        assert record["alert_source"] == "other"
        assert record["attack_type"] == "unknown"
        assert record["scenario_id"] == "unmatched"
        assert record["agent_name"] == "owasp_juice_server"


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
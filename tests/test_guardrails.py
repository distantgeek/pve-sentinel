"""Tests for guardrails module."""

import pytest

from src.guardrails import get_system_prompt, list_presets, PRESETS


class TestGuardrails:
    def test_list_presets_returns_all(self):
        presets = list_presets()
        assert "cis-ubuntu-l1" in presets
        assert "cis-ai" in presets
        assert "nist-cyber-ai" in presets
        assert "general" in presets

    def test_get_default_returns_general(self):
        prompt = get_system_prompt()
        assert "Proxmox VE security advisor" in prompt

    def test_get_preset_by_name(self):
        prompt = get_system_prompt(preset="cis-ubuntu-l1")
        assert "CIS Ubuntu Linux Benchmark Level 1" in prompt

    def test_get_preset_case_sensitive(self):
        with pytest.raises(ValueError, match="Unknown guardrail preset"):
            get_system_prompt(preset="CIS-UBUNTU-L1")

    def test_custom_overrides_preset(self):
        prompt = get_system_prompt(preset="cis-ubuntu-l1", custom="Custom rules here.")
        assert prompt == "Custom rules here."

    def test_custom_bypasses_presets(self):
        prompt = get_system_prompt(custom="Strict NIST 800-53 compliance required.")
        assert "NIST 800-53" in prompt

    def test_unknown_preset_raises(self):
        with pytest.raises(ValueError, match="Unknown guardrail preset"):
            get_system_prompt(preset="nonexistent")

    def test_all_presets_are_strings(self):
        for name, prompt in PRESETS.items():
            assert isinstance(prompt, str), f"Preset {name} is not a string"
            assert len(prompt) > 100, f"Preset {name} is too short"

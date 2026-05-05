"""Tests for guardrails module."""

import pytest

from src.guardrails import (
    get_system_prompt, list_presets, PRESETS, VALIDATION_DIRECTIVE,
)


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


class TestValidationDirective:
    def test_directive_is_nonempty_string(self):
        assert isinstance(VALIDATION_DIRECTIVE, str)
        assert len(VALIDATION_DIRECTIVE) > 50

    def test_directive_prepended_to_default(self):
        prompt = get_system_prompt()
        assert VALIDATION_DIRECTIVE in prompt
        assert prompt.startswith(VALIDATION_DIRECTIVE.strip())

    def test_directive_prepended_to_preset(self):
        prompt = get_system_prompt(preset="cis-ubuntu-l1")
        assert VALIDATION_DIRECTIVE in prompt
        assert prompt.startswith(VALIDATION_DIRECTIVE.strip())

    def test_directive_prepended_to_custom(self):
        prompt = get_system_prompt(custom="Custom rules.")
        assert VALIDATION_DIRECTIVE in prompt
        assert "Custom rules." in prompt

    def test_directive_contains_key_principles(self):
        assert "Never make definitive claims" in VALIDATION_DIRECTIVE
        assert "Pending Verification" in VALIDATION_DIRECTIVE
        assert "already configured" in VALIDATION_DIRECTIVE
        assert "data source" in VALIDATION_DIRECTIVE

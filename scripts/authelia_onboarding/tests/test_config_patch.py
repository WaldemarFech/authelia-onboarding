from __future__ import annotations

import copy
import unittest
import os
import tempfile
from pathlib import Path

import yaml
from unittest.mock import patch
import scripts.authelia_onboarding.config_patch as acl_module

from scripts.authelia_onboarding.config_patch import (
    ConfigurationPatchError,
    RESOURCE_PATTERNS,
    apply_file,
    patch_configuration,
    restore_file,
)


BASE = """authentication_backend:
  file:
    path: /opt/authelia/config/users_database.yml
    watch: false # watch edits made by the onboarding service
access_control:
  default_policy: two_factor
  rules:
    - domain:
        - gew.h1.example.invalid
      subject:
        - user:LabUser
      policy: one_factor
    - domain:
        - gew.h1.example.invalid
      policy: deny
    - domain:
        - jellyfin.example.invalid
      subject:
        - group:jellyfin-users
      policy: two_factor # preserve the browser policy
    - domain:
        - jellyfin-app.example.invalid
      subject:
        - group:jellyfin-users
      policy: one_factor # preserve the existing client policy
    - domain:
        - auth.example.invalid
      policy: bypass
session:
  cookies:
    - domain: example.invalid
"""


class AutheliaConfigurationPatchTests(unittest.TestCase):
    def setUp(self):
        self.domain_patch = patch.object(acl_module, "PORTAL_DOMAIN", "auth.example.invalid")
        self.admin_patch = patch.object(acl_module, "ADMIN_SUBJECTS", ["user:labowner", "user:jarvis"])
        self.domain_patch.start()
        self.admin_patch.start()
        self.addCleanup(self.admin_patch.stop)
        self.addCleanup(self.domain_patch.stop)

    def test_patch_preserves_existing_text_and_inserts_both_admins_before_bypass(self) -> None:
        result = patch_configuration(BASE)
        parsed = yaml.safe_load(result.text)
        rules = parsed["access_control"]["rules"]

        self.assertTrue(result.changed)
        self.assertIn("watch: true # watch edits made by the onboarding service", result.text)
        self.assertIn("policy: one_factor", result.text)
        self.assertEqual(parsed["authentication_backend"]["file"]["watch"], True)
        original_rules = yaml.safe_load(BASE)["access_control"]["rules"]
        bypass_index = next(index for index, rule in enumerate(original_rules) if rule["policy"] == "bypass")
        self.assertEqual(rules[:bypass_index], original_rules[:bypass_index])
        self.assertEqual(rules[bypass_index]["subject"], ["user:labowner", "user:jarvis"])
        self.assertEqual(rules[bypass_index]["resources"], RESOURCE_PATTERNS)
        self.assertEqual(rules[bypass_index]["policy"], "two_factor")
        self.assertEqual(rules[bypass_index + 1]["policy"], "deny")
        self.assertEqual(rules[bypass_index + 1]["resources"], RESOURCE_PATTERNS)
        self.assertEqual(rules[bypass_index + 2:], original_rules[bypass_index:])
        self.assertIn("policy: two_factor # preserve the browser policy", result.text)
        self.assertIn("policy: one_factor # preserve the existing client policy", result.text)
        self.assertEqual(parsed["session"], yaml.safe_load(BASE)["session"])

    def test_missing_watch_is_added_and_patch_is_idempotent(self) -> None:
        fixture = BASE.replace("    watch: false # watch edits made by the onboarding service\n", "")
        first = patch_configuration(fixture)
        second = patch_configuration(first.text)

        self.assertTrue(first.changed)
        self.assertFalse(second.changed)
        parsed = yaml.safe_load(first.text)
        self.assertTrue(parsed["authentication_backend"]["file"]["watch"])
        self.assertEqual(parsed["session"], yaml.safe_load(fixture)["session"])

    def test_partial_or_duplicate_onboarding_rules_fail_closed(self) -> None:
        partial = BASE.replace("      policy: bypass\n", "      resources:\n        - '^/onboarding/admin$'\n      policy: two_factor\n")
        with self.assertRaisesRegex(ConfigurationPatchError, "partial onboarding"):
            patch_configuration(partial)
        duplicate = BASE.replace("  default_policy: two_factor\n", "  default_policy: two_factor\n  default_policy: deny\n")
        with self.assertRaises(ConfigurationPatchError):
            patch_configuration(duplicate)





    def test_singleton_or_flow_admin_policies_fail_closed(self) -> None:
        canonical = patch_configuration(BASE).text
        block = "      subject:\n        - 'user:labowner'\n        - 'user:jarvis'\n"
        for replacement in ("      subject:\n        - 'user:labowner'\n", "      subject: ['user:labowner']\n"):
            fixture = canonical.replace(block, replacement, 1)
            self.assertNotEqual(fixture, canonical)
            with self.assertRaises(ConfigurationPatchError):
                patch_configuration(fixture)

    def test_subject_alias_outside_admin_span_fails_closed(self) -> None:
        canonical = patch_configuration(BASE).text
        fixture = "saved_subject: &saved ['user:labowner']\n" + canonical.replace(
            "      subject:\n        - 'user:labowner'\n        - 'user:jarvis'\n", "      subject: *saved\n", 1)
        with self.assertRaises(ConfigurationPatchError):
            patch_configuration(fixture)

    def test_existing_pairs_reject_partial_altered_separated_or_reordered_rules(self) -> None:
        current = yaml.safe_load(patch_configuration(BASE).text)
        for principal in ("labowner", "LabUser", "labowner+jarvis"):
            with self.subTest(principal=principal):
                fixture = copy.deepcopy(current)
                rules = fixture["access_control"]["rules"]
                admin_index = next(index for index, rule in enumerate(rules) if rule.get("subject") == ["user:labowner", "user:jarvis"])
                rules[admin_index]["subject"] = (["user:labowner", "user:jarvis"] if principal == "labowner+jarvis" else ["user:" + principal])
                variants = {}
                altered = copy.deepcopy(rules)
                altered[admin_index]["subject"] = ["user:other"]
                variants["subject"] = altered
                for label, subjects in {
                    "jarvis_only": ["user:jarvis"],
                    "subject_reversed": ["user:jarvis", "user:labowner"],
                    "extra_subject": ["user:labowner", "user:jarvis", "user:other"],
                    "duplicate_subject": ["user:labowner", "user:jarvis", "user:jarvis"],
                    "case_variant": ["user:labowner", "user:Jarvis"],
                }.items():
                    changed_subject = copy.deepcopy(rules)
                    changed_subject[admin_index]["subject"] = subjects
                    variants[label] = changed_subject
                altered = copy.deepcopy(rules)
                altered[admin_index]["policy"] = "one_factor"
                variants["policy"] = altered
                altered = copy.deepcopy(rules)
                altered[admin_index]["resources"][0] += "altered"
                variants["resources"] = altered
                altered = copy.deepcopy(rules)
                altered[admin_index]["networks"] = ["192.0.2.0/24"]
                variants["extra_selector"] = altered
                partial = copy.deepcopy(rules)
                del partial[admin_index + 1]
                variants["partial"] = partial
                separated = copy.deepcopy(rules)
                separated.insert(admin_index + 1, copy.deepcopy(rules[0]))
                variants["separated"] = separated
                reversed_pair = copy.deepcopy(rules)
                reversed_pair[admin_index:admin_index + 2] = reversed_pair[admin_index:admin_index + 2][::-1]
                variants["reversed"] = reversed_pair
                after_bypass = copy.deepcopy(rules)
                bypass = after_bypass.pop(admin_index + 2)
                after_bypass.insert(admin_index, bypass)
                variants["after_bypass"] = after_bypass
                duplicate_bypass = copy.deepcopy(rules)
                duplicate_bypass.append(copy.deepcopy(rules[admin_index + 2]))
                variants["duplicate_bypass"] = duplicate_bypass
                for name, altered_rules in variants.items():
                    with self.subTest(principal=principal, variant=name):
                        altered_fixture = copy.deepcopy(fixture)
                        altered_fixture["access_control"]["rules"] = altered_rules
                        with self.assertRaises(ConfigurationPatchError):
                            patch_configuration(yaml.safe_dump(altered_fixture, sort_keys=False))

    @unittest.skipIf(os.name == "nt", "Linux filesystem semantics required")
    def test_apply_file_keeps_verified_same_host_backup_and_exact_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "configuration.yml"
            target.write_text(BASE, encoding="utf-8")
            os.chmod(target, 0o600)

            receipt = apply_file(target)

            backup = Path(receipt["backup"])
            self.assertTrue(receipt["changed"])
            self.assertEqual(backup.read_text(encoding="utf-8"), BASE)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertTrue(yaml.safe_load(target.read_text(encoding="utf-8"))["authentication_backend"]["file"]["watch"])
            self.assertFalse(apply_file(target)["changed"])

    @unittest.skipIf(os.name == "nt", "Linux filesystem semantics required")
    def test_apply_file_rejects_symlink_without_touching_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "configuration.yml"
            actual = Path(directory) / "actual.yml"
            actual.write_text(BASE, encoding="utf-8")
            target.symlink_to(actual)

            with self.assertRaisesRegex(ConfigurationPatchError, "regular file"):
                apply_file(target)
            self.assertEqual(actual.read_text(encoding="utf-8"), BASE)

    @unittest.skipIf(os.name == "nt", "Linux filesystem semantics required")
    def test_restore_accepts_only_same_directory_onboarding_backup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "configuration.yml"
            target.write_text(BASE, encoding="utf-8")
            receipt = apply_file(target)
            backup = Path(receipt["backup"])
            target.write_text("broken: true\n", encoding="utf-8")

            restored = restore_file(target, backup)

            self.assertTrue(restored["restored"])
            self.assertEqual(target.read_text(encoding="utf-8"), BASE)
            with tempfile.TemporaryDirectory() as other:
                wrong_dir = Path(other) / backup.name
                wrong_dir.write_bytes(backup.read_bytes())
                with self.assertRaisesRegex(ConfigurationPatchError, "trusted onboarding backup"):
                    restore_file(target, wrong_dir)


if __name__ == "__main__":
    unittest.main()

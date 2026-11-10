import ast
import ipaddress
import os
from pathlib import Path
import re
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.parse

from scripts.authelia_onboarding import config_patch as acl

BASE = """authentication_backend:
  file:
    path: /tmp/users.yml
    watch: false
access_control:
  default_policy: deny
  rules:
    - domain:
        - auth.example.invalid
      policy: bypass
"""

class AclTests(unittest.TestCase):
    def test_no_implicit_admin_policy(self):
        with patch.object(acl, "PORTAL_DOMAIN", ""), patch.object(acl, "ADMIN_SUBJECTS", []):
            with self.assertRaises(acl.ConfigurationPatchError):
                acl.patch_configuration(BASE)

    def test_explicit_admin_pair_and_deny_before_bypass(self):
        with patch.object(acl, "PORTAL_DOMAIN", "auth.example.invalid"), patch.object(acl, "ADMIN_SUBJECTS", ["user:alice"]):
            result = acl.patch_configuration(BASE)
            import yaml
            rules = yaml.safe_load(result.text)["access_control"]["rules"]
            self.assertEqual([r["policy"] for r in rules], ["two_factor", "deny", "bypass"])
            self.assertEqual(rules[0]["subject"], ["user:alice"])
            self.assertFalse(acl.patch_configuration(result.text).changed)

    def test_earlier_overlapping_or_unknown_rules_are_rejected(self):
        import yaml
        earlier_rules = [
            {"domain": "*.example.invalid", "policy": "bypass"},
            {"domain_regex": ".*example[.]invalid", "policy": "bypass"},
            {"domain": "auth.example.invalid", "policy": "one_factor"},
            {"domain": "AUTH.EXAMPLE.INVALID.", "policy": "bypass"},
            {"policy": "bypass"},
            {"domain": ["other.example.invalid", "*.example.invalid"], "policy": "bypass"},
        ]
        with patch.object(acl, "PORTAL_DOMAIN", "auth.example.invalid"), patch.object(acl, "ADMIN_SUBJECTS", ["user:alice"]):
            for rule in earlier_rules:
                for protected in (False, True):
                    with self.subTest(rule=rule, protected=protected):
                        config = yaml.safe_load(acl.patch_configuration(BASE).text if protected else BASE)
                        config["access_control"]["rules"].insert(0, rule)
                        with self.assertRaises(acl.ConfigurationPatchError):
                            acl.patch_configuration(yaml.safe_dump(config, sort_keys=False))

    def test_earlier_distinct_literal_domain_is_allowed(self):
        import yaml
        with patch.object(acl, "PORTAL_DOMAIN", "auth.example.invalid"), patch.object(acl, "ADMIN_SUBJECTS", ["user:alice"]):
            config = yaml.safe_load(BASE)
            config["access_control"]["rules"].insert(0, {"domain": "other.example.invalid", "policy": "bypass"})
            result = acl.patch_configuration(yaml.safe_dump(config, sort_keys=False))
            self.assertFalse(acl.patch_configuration(result.text).changed)

    def test_existing_different_admin_policy_is_rejected(self):
        with patch.object(acl, "PORTAL_DOMAIN", "auth.example.invalid"), patch.object(acl, "ADMIN_SUBJECTS", ["user:alice"]):
            old = acl.patch_configuration(BASE).text
            acl.ADMIN_SUBJECTS = ["user:bob"]
            with self.assertRaises(acl.ConfigurationPatchError):
                acl.patch_configuration(old)

class StartupTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parents[1] / "scripts/authelia_onboarding/onboarding_service.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        func = next(x for x in tree.body if isinstance(x, ast.FunctionDef) and x.name == "configure_from_environment")
        module = ast.fix_missing_locations(ast.Module(body=[func], type_ignores=[]))
        self.notification = SimpleNamespace(ADMIN_USERNAMES=())
        self.ns = {"os":os, "ipaddress":ipaddress, "urllib":urllib, "re":re,
                   "USERNAME_RE":re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$"), "_notifications_module":self.notification}
        exec(compile(module, str(path), "exec"), self.ns)
        self.run_config = self.ns["configure_from_environment"]
        self.valid = {"ONBOARDING_ADMINS":"alice,bob", "ONBOARDING_TRUSTED_PROXY":"10.77.0.10",
                      "ONBOARDING_ORIGIN":"https://auth.example.invalid", "ONBOARDING_BIND_IP":"10.77.0.11",
                      "ONBOARDING_BIND_PORT":"9945"}

    def test_no_defaults(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(RuntimeError):
            self.run_config()

    def test_explicit_values_configure_same_admins(self):
        with patch.dict(os.environ, self.valid, clear=True):
            self.assertEqual(self.run_config(), ("10.77.0.11", 9945))
        self.assertEqual(self.notification.ADMIN_USERNAMES, ("alice", "bob"))
        self.assertEqual(self.ns["ALLOWED_GROUPS"], set())

    def test_rejects_invalid_configuration(self):
        for key, value in [("ONBOARDING_BIND_IP", "0.0.0.0"), ("ONBOARDING_ORIGIN", "http://example.invalid"),
                           ("ONBOARDING_ADMINS", "Alice"), ("ONBOARDING_TRUSTED_PROXY", "0.0.0.0/0"),
                           ("ONBOARDING_TRUSTED_PROXY", "0.0.0.0"), ("ONBOARDING_TRUSTED_PROXY", "224.0.0.1"),
                           ("ONBOARDING_BIND_IP", "224.0.0.1")]:
            with self.subTest(key=key), patch.dict(os.environ, {**self.valid, key:value}, clear=True):
                with self.assertRaises(RuntimeError):
                    self.run_config()

class DisabledFeaturesTests(unittest.TestCase):
    def test_http_handlers_do_not_read_notification_archive_or_account_context(self):
        path = Path(__file__).resolve().parents[1] / "scripts/authelia_onboarding/onboarding_service.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        handler = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Handler")
        for method_name in ("do_GET", "do_POST"):
            method = next(node for node in handler.body if isinstance(node, ast.FunctionDef) and node.name == method_name)
            for node in ast.walk(method):
                if isinstance(node, ast.Name):
                    self.assertNotEqual(node.id, "AccountContext")
                if isinstance(node, ast.Attribute):
                    self.assertNotIn(node.attr, {"legacy_notifications", "read_for_admin", "purge_expired_for_admin"})

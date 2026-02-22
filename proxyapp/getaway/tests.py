from django.test import TestCase
from unittest.mock import patch

from .views import (
    allow_insecure_tls_fallback,
    get_tls_verify_setting,
    is_allowed_host,
    normalize_allowed_rule,
)


class AllowedHostRulesTests(TestCase):
    def test_normalize_allowed_rule_accepts_full_url(self):
        self.assertEqual(
            normalize_allowed_rule("https://www.example.com/some/path?x=1"),
            "example.com",
        )

    def test_normalize_allowed_rule_keeps_wildcard(self):
        self.assertEqual(
            normalize_allowed_rule("*.api.example.com"),
            "*.api.example.com",
        )

    def test_is_allowed_host_with_url_based_rule(self):
        allowed = {normalize_allowed_rule("https://www.youtube.com/watch?v=1")}
        self.assertTrue(is_allowed_host("youtube.com", allowed))


class TlsVerifySettingTests(TestCase):
    @patch.dict("os.environ", {}, clear=True)
    def test_default_tls_verify_is_true(self):
        self.assertTrue(get_tls_verify_setting())

    @patch.dict("os.environ", {"EZPROXY_TLS_VERIFY": "false"}, clear=True)
    def test_tls_verify_can_be_disabled_with_env(self):
        self.assertFalse(get_tls_verify_setting())

    @patch.dict("os.environ", {"EZPROXY_CA_BUNDLE": "/etc/ssl/custom-ca.pem"}, clear=True)
    def test_ca_bundle_takes_precedence(self):
        self.assertEqual(get_tls_verify_setting(), "/etc/ssl/custom-ca.pem")


class InsecureTlsFallbackTests(TestCase):
    @patch("getaway.views.settings.DEBUG", True)
    @patch.dict("os.environ", {}, clear=True)
    def test_fallback_defaults_to_true_in_debug(self):
        self.assertTrue(allow_insecure_tls_fallback())

    @patch("getaway.views.settings.DEBUG", True)
    @patch.dict("os.environ", {"EZPROXY_ALLOW_INSECURE_FALLBACK": "false"}, clear=True)
    def test_fallback_can_be_forced_off(self):
        self.assertFalse(allow_insecure_tls_fallback())

"""Offline coverage for the opt-in, session-local Codex reference profile."""
import unittest
from unittest.mock import Mock, patch

from config import browser as cfg
from core import session as session_module
from core.session import BrowserSession


REFERENCE = "chrome149_reference"
REFERENCE_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
)


class CodexReferenceProfileTests(unittest.TestCase):
    def build(self, **kwargs):
        return cfg.build_browser_environment(
            base_profile=cfg.HAR_CAPTURE_BASE_PROFILE,
            browser_family=REFERENCE,
            **kwargs,
        )

    def test_reference_identity_matches_pinned_upstream(self):
        profile = self.build()
        self.assertEqual(profile["profile_name"], REFERENCE)
        self.assertEqual(profile["browser_family"], "chrome")
        self.assertEqual(profile["impersonate"], "chrome146")
        self.assertEqual(profile["chrome_major"], "149")
        self.assertEqual(profile["chrome_full_version"], "149.0.0.0")
        self.assertEqual(profile["user_agent"], REFERENCE_UA)
        self.assertEqual(profile["sec_ch_ua"], '"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"')
        self.assertEqual(profile["sec_ch_ua_full_version_list"], '"Google Chrome";v="149.0.0.0", "Chromium";v="149.0.0.0", "Not)A;Brand";v="24.0.0.0"')
        self.assertTrue(profile["send_client_hints"])
        self.assertEqual(profile["navigator_vendor"], "Google Inc.")
        self.assertEqual(profile["navigator_platform"], "MacIntel")
        self.assertEqual(profile["navigator_languages"], [profile["navigator_language"]])

    def test_known_upstream_tls_version_mismatch_is_not_hidden(self):
        self.assertEqual(
            cfg.validate_browser_profile(self.build()),
            ["TLS impersonate 与 Chrome 主版本不一致"],
        )

    def test_sentinel_payload_and_runner_args_use_same_reference_profile(self):
        from core.sentinel import generate_fingerprint_data
        from core.sentinel_runner import _runner_context_args

        profile = self.build()
        payload = generate_fingerprint_data("offline-device", profile=profile)
        self.assertEqual(payload[4], REFERENCE_UA)
        # Only build argument strings: do not launch Node or a browser.
        args, timezone_iana = _runner_context_args(
            flow="authorize_continue", device_id="offline-device", sdk_path="offline-sdk.js",
            sdk_url="https://sentinel.example.test/sdk.js", browser_profile=profile,
        )
        values = dict(zip(args[::2], args[1::2]))
        self.assertEqual(values["--browser-family"], "chrome")
        self.assertEqual(values["--user-agent"], REFERENCE_UA)
        self.assertEqual(values["--chrome-major"], "149")
        self.assertEqual(values["--chrome-full-version"], "149.0.0.0")
        self.assertEqual(values["--sec-ch-ua"], profile["sec_ch_ua"])
        self.assertEqual(values["--languages"], profile["navigator_language"])
        self.assertEqual(values["--time-zone"], profile["timezone_iana"])
        self.assertEqual(timezone_iana, profile["timezone_iana"])

    def test_reference_geo_does_not_change_global_locale_policy(self):
        geo = {"country": "US", "timezone": "America/New_York"}
        with patch.object(cfg, "AUTO_BROWSER_LOCALE_FROM_IP", False), \
             patch.object(cfg, "BROWSER_LOCALE_PROFILE", "jp"):
            reference = self.build(geo=geo)
            default = cfg.build_browser_environment(geo)
            firefox = cfg.build_browser_environment(geo, browser_family="firefox")
            self.assertFalse(cfg.AUTO_BROWSER_LOCALE_FROM_IP)
        self.assertEqual(reference["navigator_languages"], ["en-US"])
        self.assertEqual(reference["timezone_iana"], "America/New_York")
        for profile in (default, firefox):
            self.assertEqual(profile["navigator_language"], "ja-JP")
            self.assertEqual(profile["timezone_iana"], "Asia/Tokyo")

    def test_reference_does_not_guess_country_from_proxy_username(self):
        with patch.object(cfg, "BROWSER_LOCALE_PROFILE", "jp"):
            reference = self.build(region="US")
        self.assertEqual(reference["navigator_languages"], ["ja-JP"])

    def test_profile_mutations_do_not_leak_to_other_sessions(self):
        reference = self.build()
        reference["navigator_languages"].append("test-only")
        reference["window_key_samples"].append("test-only")
        reference["sec_ch_ua"] = "test-only"
        second = self.build()
        default = cfg.build_browser_environment()
        firefox = cfg.build_browser_environment(browser_family="firefox")
        self.assertNotIn("test-only", second["navigator_languages"])
        self.assertNotIn("test-only", default["window_key_samples"])
        self.assertIn('v="149"', second["sec_ch_ua"])
        self.assertEqual(default["chrome_major"], "146")
        self.assertIn("Chrome/146.0.0.0", default["user_agent"])
        self.assertEqual(cfg.validate_browser_profile(default), [])
        self.assertEqual(firefox["impersonate"], "firefox147")
        self.assertFalse(firefox["send_client_hints"])
        self.assertEqual(cfg.validate_browser_profile(firefox), [])

    def test_http_and_profile_share_reference_identity_without_network(self):
        with patch.object(session_module, "Session") as transport, \
             patch.object(BrowserSession, "_detect_exit_geo") as geo:
            session = BrowserSession(proxy="", detect_exit_geo=False, browser_family=REFERENCE)
            transport.assert_called_once_with(impersonate="chrome146")
            geo.assert_not_called()
            self.assertEqual(session.browser_family, "chrome")
            for headers in (
                session._get_common_headers(),
                session.get_auth_headers(),
                session.get_auth_navigate_headers(),
                session.get_sentinel_frame_headers(),
            ):
                self.assertEqual(headers["User-Agent"], REFERENCE_UA)
                self.assertIn('v="149"', headers["sec-ch-ua"])
            transport.return_value.get.assert_not_called()
            transport.return_value.post.assert_not_called()

    def test_high_entropy_hints_do_not_fall_back_to_global_chrome146(self):
        with patch.object(session_module, "Session"), \
             patch.object(session_module, "SEND_HIGH_ENTROPY_CLIENT_HINTS", True):
            session = BrowserSession(proxy="", detect_exit_geo=False, browser_family=REFERENCE)
            headers = session._get_common_headers()
        self.assertEqual(headers["sec-ch-ua-full-version-list"], session.browser_profile["sec_ch_ua_full_version_list"])
        self.assertNotIn("146.0.0.0", headers["sec-ch-ua-full-version-list"])

    def test_only_reference_session_forces_geo_lookup(self):
        for family, expected in ((REFERENCE, {"force": True}), ("chrome", {}), ("firefox", {})):
            with self.subTest(family=family), \
                 patch.object(session_module, "Session"), \
                 patch.object(BrowserSession, "_detect_exit_geo", return_value={}) as geo:
                BrowserSession(proxy="", browser_family=family)
                geo.assert_called_once_with(**expected)

    def test_unknown_profile_is_rejected_before_creating_transport(self):
        with patch.object(session_module, "Session") as transport:
            with self.assertRaises(ValueError):
                BrowserSession(proxy="", detect_exit_geo=False, browser_family="unknown")
            transport.assert_not_called()

    def test_both_codex_entrypoints_use_selected_profile(self):
        from core import codex_oauth, codex_password_totp, db, progress_events

        with patch.object(codex_oauth._cfg, "CODEX_BROWSER_FAMILY", "chrome"), \
             patch.object(codex_oauth, "_check_codex_flow_stop"), \
             patch.object(progress_events, "phase"), \
             patch.object(db, "get_account_by_email", return_value={}), \
             patch.object(codex_password_totp, "login_material", return_value=("test-password", "test-secret")):
            for entrypoint in (codex_oauth._run_codex_oauth_once, codex_password_totp.run_once):
                with self.subTest(entrypoint=entrypoint.__name__), \
                     patch.object(codex_oauth, "BrowserSession", side_effect=RuntimeError("offline stop")) as constructor:
                    result = entrypoint(
                        "test@example.com", otp_provider=Mock(), proxy="", force=True, auth_source="local",
                    )
                    constructor.assert_called_once_with(proxy="", browser_family=REFERENCE)
                    self.assertEqual(result["status"], "failed")

    def test_codex_profile_selection_preserves_firefox_and_original_chrome(self):
        from core import codex_oauth

        for selected, expected in (("chrome", REFERENCE), ("firefox", "firefox"), ("chrome146", "chrome")):
            with self.subTest(selected=selected), patch.object(codex_oauth._cfg, "CODEX_BROWSER_FAMILY", selected):
                self.assertEqual(codex_oauth._codex_browser_profile_key(), expected)


if __name__ == "__main__":
    unittest.main()

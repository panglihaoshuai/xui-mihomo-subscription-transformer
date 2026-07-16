import importlib.util
import http.client
import json
import pathlib
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock


ROOT = pathlib.Path(__file__).parents[1]
MODULE_PATH = ROOT / "xui_mihomo_subscription.py"
SPEC = importlib.util.spec_from_file_location("xui_mihomo_subscription", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class TransformProfileTest(unittest.TestCase):
    def setUp(self):
        self.source = {
            "proxies": [
                {"name": "US VLESS", "type": "vless"},
                {"name": "US Hysteria2", "type": "hysteria2"},
                {"name": "JP VMess", "type": "vmess"},
            ],
            "proxy-groups": [{"name": "old", "type": "select"}],
            "rules": ["MATCH,old"],
        }

    def test_builds_smart_groups_from_dynamic_node_names(self):
        result = MODULE.transform_profile(self.source)
        names = [node["name"] for node in self.source["proxies"]]

        self.assertEqual("rule", result["mode"])
        self.assertTrue(result["tun"]["enable"])
        self.assertEqual(["any:53", "tcp://any:53"], result["tun"]["dns-hijack"])
        self.assertEqual(names, result["proxy-groups"][0]["proxies"])
        self.assertEqual("url-test", result["proxy-groups"][0]["type"])
        self.assertEqual(names + ["DIRECT"], result["proxy-groups"][1]["proxies"])
        self.assertEqual(["AUTO", "MANUAL", "DIRECT"], result["proxy-groups"][2]["proxies"])
        self.assertEqual("MATCH,PROXY", result["rules"][-1])

    def test_supports_filter_and_fallback_policy(self):
        result = MODULE.transform_profile(
            self.source,
            {"node_include": "US", "node_exclude": "Hysteria", "group_type": "fallback"},
        )
        auto = result["proxy-groups"][0]
        self.assertEqual("fallback", auto["type"])
        self.assertEqual(["US VLESS"], auto["proxies"])
        self.assertNotIn("tolerance", auto)

    def test_builds_domain_specific_service_group_without_direct_fallback(self):
        result = MODULE.transform_profile(
            self.source,
            {
                "service_groups": [
                    {
                        "name": "OPENAI",
                        "group_type": "url-test",
                        "domains": ["chatgpt.com", "openai.com"],
                        "node_exclude": "VLESS",
                        "health_check": {
                            "url": "https://chatgpt.com/cdn-cgi/trace",
                            "interval": 60,
                            "expected_status": 200,
                        },
                    }
                ]
            },
        )

        groups = {group["name"]: group for group in result["proxy-groups"]}
        openai = groups["OPENAI"]
        self.assertEqual("url-test", openai["type"])
        self.assertEqual(["US Hysteria2", "JP VMess"], openai["proxies"])
        self.assertNotIn("DIRECT", openai["proxies"])
        self.assertEqual("https://chatgpt.com/cdn-cgi/trace", openai["url"])
        self.assertEqual(200, openai["expected-status"])
        self.assertEqual(
            ["DOMAIN-SUFFIX,chatgpt.com,OPENAI", "DOMAIN-SUFFIX,openai.com,OPENAI"],
            result["rules"][:2],
        )

    def test_overseas_dns_uses_non_direct_auto_group(self):
        result = MODULE.transform_profile(
            self.source,
            {"group_names": {"auto": "FAST", "manual": "PICK", "proxy": "OUTBOUND"}},
        )

        self.assertEqual(
            [
                "https://1.1.1.1/dns-query#FAST",
                "https://8.8.8.8/dns-query#FAST",
            ],
            result["dns"]["nameserver"],
        )
        self.assertEqual("MATCH,OUTBOUND", result["rules"][-1])

    def test_builds_simple_auto_manual_layout(self):
        result = MODULE.transform_profile(
            self.source,
            {
                "group_layout": "simple",
                "health_check": {
                    "url": "https://chatgpt.com/cdn-cgi/trace",
                    "expected_status": 200,
                },
            },
        )

        self.assertEqual(["AUTO", "MANUAL"], [group["name"] for group in result["proxy-groups"]])
        auto, manual = result["proxy-groups"]
        self.assertEqual("https://chatgpt.com/cdn-cgi/trace", auto["url"])
        self.assertEqual(200, auto["expected-status"])
        self.assertEqual(
            ["AUTO", "US VLESS", "US Hysteria2", "JP VMess"],
            manual["proxies"],
        )
        self.assertNotIn("DIRECT", manual["proxies"])
        self.assertEqual("MATCH,MANUAL", result["rules"][-1])

    def test_rejects_service_groups_in_simple_layout(self):
        with self.assertRaisesRegex(ValueError, "simple group_layout"):
            MODULE.transform_profile(
                self.source,
                {
                    "group_layout": "simple",
                    "service_groups": [{"name": "OPENAI", "domains": ["chatgpt.com"]}],
                },
            )

    def test_rejects_service_group_name_conflicts(self):
        with self.assertRaisesRegex(ValueError, "service group name"):
            MODULE.transform_profile(
                self.source,
                {"service_groups": [{"name": "AUTO", "domains": ["chatgpt.com"]}]},
            )

    def test_rejects_profiles_without_selected_nodes(self):
        with self.assertRaisesRegex(ValueError, "selected no proxies"):
            MODULE.transform_profile(self.source, {"node_include": "does-not-match"})


class ConfigTest(unittest.TestCase):
    def _load(self, config):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8") as handle:
            json.dump(config, handle)
            handle.flush()
            return MODULE.load_config(handle.name)

    def test_loads_route_policy_mapping(self):
        upstream, routes = self._load(
            {
                "upstream": "http://localhost:2096",
                "paths": {"/clash/example": {"upstream_path": "/clash/token", "policy": "smart"}},
                "policies": {"smart": {"group_type": "fallback"}},
            }
        )
        self.assertEqual("http://localhost:2096", upstream)
        self.assertEqual("fallback", routes["/clash/example"]["policy"]["group_type"])

    def test_applies_default_policy_to_legacy_string_routes(self):
        _, routes = self._load(
            {
                "upstream": "http://127.0.0.1:2096",
                "default_policy": "smart",
                "paths": {"/clash/example": "/clash/token"},
                "policies": {"smart": {"group_type": "url-test"}},
            }
        )
        self.assertEqual("url-test", routes["/clash/example"]["policy"]["group_type"])

    def test_rejects_non_loopback_upstream(self):
        with self.assertRaisesRegex(ValueError, "loopback"):
            self._load({"upstream": "http://198.51.100.1:2096", "paths": {"/clash/a": "/clash/a"}})


class HttpHandlerTest(unittest.TestCase):
    def test_serves_transformed_yaml_and_preserves_usage_header(self):
        class FakeResponse:
            headers = {"Subscription-Userinfo": "upload=1; download=2; total=3"}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return b"proxies:\n  - name: test-node\n    type: vmess\n"

        routes = {
            "/clash/example": {
                "upstream_path": "/clash/token",
                "policy": {
                    "service_groups": [
                        {
                            "name": "OPENAI",
                            "domains": ["chatgpt.com"],
                            "health_check": {
                                "url": "https://chatgpt.com/cdn-cgi/trace",
                                "expected_status": 200,
                            },
                        }
                    ]
                },
            }
        }
        server = ThreadingHTTPServer(
            ("127.0.0.1", 0), MODULE.create_handler("http://127.0.0.1:2096", routes)
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with mock.patch.object(MODULE.urllib.request, "urlopen", return_value=FakeResponse()):
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                connection.request("GET", "/clash/example")
                response = connection.getresponse()
                body = response.read().decode("utf-8")
                self.assertEqual(200, response.status)
                self.assertEqual(
                    "upload=1; download=2; total=3",
                    response.getheader("Subscription-Userinfo"),
                )
                self.assertIn("name: OPENAI", body)
                self.assertIn("DOMAIN-SUFFIX,chatgpt.com,OPENAI", body)
                connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()

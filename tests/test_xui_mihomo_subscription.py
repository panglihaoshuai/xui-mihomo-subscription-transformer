import importlib.util
import json
import pathlib
import tempfile
import unittest


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

    def test_rejects_non_loopback_upstream(self):
        with self.assertRaisesRegex(ValueError, "loopback"):
            self._load({"upstream": "http://198.51.100.1:2096", "paths": {"/clash/a": "/clash/a"}})


if __name__ == "__main__":
    unittest.main()

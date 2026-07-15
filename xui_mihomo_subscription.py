#!/usr/bin/env python3
"""Transform loopback-only 3X-UI Clash subscriptions into Mihomo profiles."""

import argparse
import copy
import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


LOGGER = logging.getLogger("xui-mihomo-subscription")
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
GROUP_TYPES = {"url-test", "fallback", "load-balance"}

DEFAULT_TUN = {
    "enable": True,
    "stack": "mixed",
    "auto-route": True,
    "auto-detect-interface": True,
    "strict-route": True,
    "dns-hijack": ["any:53", "tcp://any:53"],
}
DEFAULT_DNS = {
    "enable": True,
    "ipv6": False,
    "enhanced-mode": "fake-ip",
    "fake-ip-range": "198.18.0.1/16",
    "fake-ip-filter-mode": "blacklist",
    "fake-ip-filter": [
        "*.lan",
        "*.local",
        "localhost",
        "+.stun.*.*",
        "+.stun.*.*.*",
        "time.*.com",
        "ntp.*.com",
    ],
    "default-nameserver": ["1.1.1.1", "8.8.8.8"],
    "nameserver": [
        "https://1.1.1.1/dns-query#AUTO",
        "https://8.8.8.8/dns-query#AUTO",
    ],
    "nameserver-policy": {
        "geosite:cn": [
            "https://dns.alidns.com/dns-query",
            "https://doh.pub/dns-query",
        ]
    },
    "direct-nameserver": [
        "https://dns.alidns.com/dns-query",
        "https://doh.pub/dns-query",
    ],
    "direct-nameserver-follow-policy": True,
    "proxy-server-nameserver": [
        "https://1.1.1.1/dns-query",
        "https://8.8.8.8/dns-query",
    ],
}
DEFAULT_RULES = [
    "GEOSITE,private,DIRECT",
    "GEOIP,private,DIRECT,no-resolve",
    "GEOSITE,cn,DIRECT",
    "GEOIP,CN,DIRECT,no-resolve",
    "MATCH,PROXY",
]
DEFAULT_HEALTH_CHECK = {
    "url": "https://www.gstatic.com/generate_204",
    "interval": 10,
    "timeout": 5000,
    "tolerance": 100,
    "lazy": False,
    "expected_status": 204,
    "max_failed_times": 1,
}


def deep_merge(base, override):
    """Return a recursive merge without mutating configuration defaults."""
    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _replace_auto_dns_tag(value, auto_name):
    if isinstance(value, dict):
        return {key: _replace_auto_dns_tag(item, auto_name) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_auto_dns_tag(item, auto_name) for item in value]
    if isinstance(value, str) and value.endswith("#AUTO"):
        return value[:-5] + f"#{auto_name}"
    return copy.deepcopy(value)


def _selected_names(proxies, policy):
    include = policy.get("node_include")
    exclude = policy.get("node_exclude")
    include_re = re.compile(include) if include else None
    exclude_re = re.compile(exclude) if exclude else None

    names = []
    for proxy in proxies:
        name = proxy.get("name") if isinstance(proxy, dict) else None
        if not isinstance(name, str) or not name:
            raise ValueError("profile contains a proxy without a name")
        if include_re and not include_re.search(name):
            continue
        if exclude_re and exclude_re.search(name):
            continue
        names.append(name)

    if not names:
        raise ValueError("policy selected no proxies")
    if len(names) != len(set(names)):
        raise ValueError("profile contains duplicate proxy names")
    return names


def _health_group(name, proxy_names, policy):
    health = deep_merge(DEFAULT_HEALTH_CHECK, policy.get("health_check"))
    group_type = policy.get("group_type", "url-test")
    if group_type not in GROUP_TYPES:
        raise ValueError(f"unsupported group_type: {group_type}")

    group = {
        "name": name,
        "type": group_type,
        "proxies": proxy_names,
        "url": health["url"],
        "interval": health["interval"],
        "timeout": health["timeout"],
        "lazy": health["lazy"],
        "expected-status": health["expected_status"],
        "max-failed-times": health["max_failed_times"],
    }
    if group_type == "url-test":
        group["tolerance"] = health["tolerance"]
    if group_type == "load-balance":
        group["strategy"] = policy.get("load_balance_strategy", "round-robin")
    return group


def transform_profile(source, policy=None):
    """Build a Mihomo profile while preserving all upstream proxy definitions."""
    policy = policy or {}
    proxies = source.get("proxies") if isinstance(source, dict) else None
    if not isinstance(proxies, list) or not proxies:
        raise ValueError("profile contains no proxies")

    names = _selected_names(proxies, policy)
    group_names = deep_merge(
        {"auto": "AUTO", "manual": "MANUAL", "proxy": "PROXY"},
        policy.get("group_names"),
    )
    auto_name = group_names["auto"]
    manual_name = group_names["manual"]
    proxy_name = group_names["proxy"]
    if len({auto_name, manual_name, proxy_name}) != 3:
        raise ValueError("group_names must be unique")
    if any(name in {auto_name, manual_name, proxy_name} for name in names):
        raise ValueError("proxy name conflicts with generated group name")

    service_groups = policy.get("service_groups", [])
    if not isinstance(service_groups, list):
        raise ValueError("service_groups must be a list")
    reserved_group_names = {auto_name, manual_name, proxy_name}
    generated_service_groups = []
    service_rules = []
    for service in service_groups:
        if not isinstance(service, dict):
            raise ValueError("each service group must be an object")
        service_name = service.get("name")
        if not isinstance(service_name, str) or not service_name:
            raise ValueError("service group name must be a non-empty string")
        if service_name in reserved_group_names or service_name in names:
            raise ValueError("service group name conflicts with another group or proxy")
        reserved_group_names.add(service_name)

        domains = service.get("domains")
        if not isinstance(domains, list) or not domains:
            raise ValueError("service group domains must be a non-empty list")
        normalized_domains = []
        for domain in domains:
            if not isinstance(domain, str):
                raise ValueError("service group domains must contain strings")
            normalized = domain.removeprefix("+.").lower()
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", normalized):
                raise ValueError(f"invalid service group domain: {domain}")
            normalized_domains.append(normalized)

        service_names = _selected_names(proxies, service)
        generated_service_groups.append(
            _health_group(service_name, service_names, service)
        )
        service_rules.extend(
            f"DOMAIN-SUFFIX,{domain},{service_name}" for domain in normalized_domains
        )

    result = {
        "mode": "rule",
        "tun": deep_merge(DEFAULT_TUN, policy.get("tun")),
        "dns": deep_merge(
            _replace_auto_dns_tag(DEFAULT_DNS, auto_name), policy.get("dns")
        ),
    }
    for key, value in source.items():
        if key not in {"mode", "tun", "dns", "proxy-groups", "rules"}:
            result[key] = copy.deepcopy(value)

    result["proxy-groups"] = [
        _health_group(auto_name, names, policy),
        *generated_service_groups,
        {
            "name": manual_name,
            "type": "select",
            "proxies": names + (["DIRECT"] if policy.get("manual_direct", True) else []),
        },
        {
            "name": proxy_name,
            "type": "select",
            "proxies": [auto_name, manual_name, "DIRECT"],
        },
    ]

    rules = copy.deepcopy(policy.get("rules", DEFAULT_RULES))
    if not isinstance(rules, list) or not all(isinstance(rule, str) for rule in rules):
        raise ValueError("rules must be a list of strings")
    rules = service_rules + rules
    if not rules or rules[-1] != f"MATCH,{proxy_name}":
        rules = [rule for rule in rules if not rule.startswith("MATCH,")]
        rules.append(f"MATCH,{proxy_name}")
    result["rules"] = rules
    return result


def _validate_upstream(value):
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "http" or parsed.hostname not in LOOPBACK_HOSTS:
        raise ValueError("upstream must be an HTTP loopback URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("upstream must not contain credentials, query, or fragment")
    return value.rstrip("/")


def load_config(path):
    with open(path, "r", encoding="utf-8") as handle:
        config = json.load(handle)

    upstream = _validate_upstream(config.get("upstream", ""))
    paths = config.get("paths")
    policies = config.get("policies", {})
    default_policy_name = config.get("default_policy")
    if not isinstance(paths, dict) or not paths:
        raise ValueError("paths must be a non-empty object")
    if not isinstance(policies, dict):
        raise ValueError("policies must be an object")
    if default_policy_name is not None and (
        not isinstance(default_policy_name, str) or default_policy_name not in policies
    ):
        raise ValueError("default_policy must reference a configured policy")

    routes = {}
    for public_path, route in paths.items():
        if not isinstance(public_path, str) or not public_path.startswith("/clash/"):
            raise ValueError("all public paths must start with /clash/")
        if isinstance(route, str):
            upstream_path, policy_name = route, default_policy_name
        elif isinstance(route, dict):
            upstream_path = route.get("upstream_path")
            policy_name = route.get("policy")
        else:
            raise ValueError("each path must be a string or object")
        if not isinstance(upstream_path, str) or not upstream_path.startswith("/clash/"):
            raise ValueError("all upstream paths must start with /clash/")
        if "?" in upstream_path or "#" in upstream_path:
            raise ValueError("upstream paths must not contain query or fragment")
        if policy_name is not None and (not isinstance(policy_name, str) or policy_name not in policies):
            raise ValueError("each route policy must reference a configured policy")
        policy = policies.get(policy_name, {}) if policy_name else {}
        if not isinstance(policy, dict):
            raise ValueError("each policy must be an object")
        routes[public_path] = {"upstream_path": upstream_path, "policy": policy}
    return upstream, routes


def create_handler(upstream, routes):
    class SubscriptionHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            self._serve(send_body=True)

        def do_HEAD(self):
            self._serve(send_body=False)

        def _serve(self, send_body):
            public_path = urllib.parse.urlsplit(self.path).path
            route = routes.get(public_path)
            if route is None:
                self.send_error(404)
                return

            try:
                import yaml

                request = urllib.request.Request(
                    upstream + route["upstream_path"],
                    headers={"User-Agent": "xui-mihomo-subscription/1"},
                )
                with urllib.request.urlopen(request, timeout=15) as response:
                    source = yaml.safe_load(response.read())
                    transformed = transform_profile(source, route["policy"])
                    body = yaml.safe_dump(
                        transformed, allow_unicode=True, sort_keys=False
                    ).encode("utf-8")
                    upstream_headers = response.headers
            except urllib.error.HTTPError as error:
                self.send_error(error.code if error.code == 404 else 502)
                return
            except Exception:
                LOGGER.exception("subscription transformation failed")
                self.send_error(502)
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/yaml; charset=utf-8")
            for header in (
                "Profile-Update-Interval",
                "Profile-Web-Page-Url",
                "Routing-Enable",
                "Subscription-Userinfo",
            ):
                value = upstream_headers.get(header)
                if value is not None:
                    self.send_header(header, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if send_body:
                self.wfile.write(body)

        def log_message(self, format_string, *args):
            LOGGER.info(
                "request completed with status %s",
                args[1] if len(args) > 1 else "unknown",
            )

    return SubscriptionHandler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18082)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    upstream, routes = load_config(args.config)
    server = ThreadingHTTPServer(
        (args.listen, args.port), create_handler(upstream, routes)
    )
    server.serve_forever()


if __name__ == "__main__":
    main()

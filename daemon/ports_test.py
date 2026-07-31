"""Tests for ports.py (Spec 029: Path-Prefix Multi-Port)."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ports import (
    PortsMap,
    PortsConfigError,
    parse_path_prefix,
    load_ports_config,
    from_ports_legacy,
)


class TestParsePathPrefix(unittest.TestCase):
    """Spec 029 FR-003: /_p<port>/ parsing."""

    def test_no_prefix_uses_default(self):
        self.assertEqual(parse_path_prefix("/", 80), (80, "/"))
        self.assertEqual(parse_path_prefix("/foo", 80), (80, "/foo"))
        self.assertEqual(parse_path_prefix("/foo/bar", 80), (80, "/foo/bar"))
        self.assertEqual(parse_path_prefix("/api/users?id=1", 80), (80, "/api/users?id=1"))

    def test_explicit_port_with_path(self):
        self.assertEqual(parse_path_prefix("/_p9090/invoices", 80), (9090, "/invoices"))
        self.assertEqual(
            parse_path_prefix("/_p443/auth/login", 80), (443, "/auth/login")
        )
        self.assertEqual(
            parse_path_prefix("/_p1/a/b/c", 80), (1, "/a/b/c")
        )

    def test_explicit_port_root(self):
        self.assertEqual(parse_path_prefix("/_p9090/", 80), (9090, "/"))
        self.assertEqual(parse_path_prefix("/_p9090", 80), (9090, "/"))

    def test_port_1_minimum(self):
        self.assertEqual(parse_path_prefix("/_p1/", 80), (1, "/"))

    def test_port_65535_maximum(self):
        self.assertEqual(parse_path_prefix("/_p65535/", 80), (65535, "/"))

    def test_port_0_raises(self):
        with self.assertRaises(ValueError) as ctx:
            parse_path_prefix("/_p0/", 80)
        self.assertIn("out of range", str(ctx.exception))

    def test_port_too_large_raises(self):
        with self.assertRaises(ValueError) as ctx:
            parse_path_prefix("/_p99999/", 80)
        self.assertIn("out of range", str(ctx.exception))

    def test_port_70000_raises(self):
        with self.assertRaises(ValueError) as ctx:
            parse_path_prefix("/_p70000/", 80)
        self.assertIn("out of range", str(ctx.exception))

    def test_non_numeric_prefix_treated_as_normal_path(self):
        # /_pabc/ doesn't match the regex, falls through to default
        self.assertEqual(parse_path_prefix("/_pabc/", 80), (80, "/_pabc/"))
        self.assertEqual(parse_path_prefix("/_p/", 80), (80, "/_p/"))

    def test_p_without_underscore_treated_as_normal_path(self):
        # /p9090/ (no underscore) doesn't match
        self.assertEqual(parse_path_prefix("/p9090/", 80), (80, "/p9090/"))

    def test_p_in_middle_not_matched(self):
        # /foo/_p9090/ — prefix must be at start
        self.assertEqual(
            parse_path_prefix("/foo/_p9090/", 80), (80, "/foo/_p9090/")
        )

    def test_default_port_is_what_caller_says(self):
        # default_port is a parameter, not hardcoded 80
        self.assertEqual(parse_path_prefix("/", 9090), (9090, "/"))
        self.assertEqual(parse_path_prefix("/foo", 443), (443, "/foo"))

    def test_path_with_query_preserved(self):
        self.assertEqual(
            parse_path_prefix("/_p9090/invoices?status=paid", 80),
            (9090, "/invoices?status=paid"),
        )

    def test_empty_path_returns_default_root(self):
        self.assertEqual(parse_path_prefix("", 80), (80, "/"))

    def test_path_not_starting_with_slash_returns_default(self):
        # malformed but defensive
        self.assertEqual(parse_path_prefix("foo", 80), (80, "foo"))


class TestPortsMap(unittest.TestCase):
    """Spec 029 FR-001/FR-002: PortsMap dataclass."""

    def test_basic_construction(self):
        pm = PortsMap(ports={80: "http://a", 9090: "http://b"})
        self.assertEqual(pm.default_port, 80)  # default of default
        self.assertIn(80, pm)
        self.assertEqual(pm.get(80), "http://a")
        self.assertEqual(len(pm), 2)

    def test_default_port_must_be_in_ports(self):
        with self.assertRaises(PortsConfigError) as ctx:
            PortsMap(ports={80: "http://a"}, default_port=9090)
        self.assertIn("not in ports map", str(ctx.exception))

    def test_empty_ports_rejected(self):
        with self.assertRaises(PortsConfigError):
            PortsMap(ports={})

    def test_invalid_port_keys_rejected(self):
        with self.assertRaises(PortsConfigError):
            PortsMap(ports={0: "http://a"})
        with self.assertRaises(PortsConfigError):
            PortsMap(ports={70000: "http://a"})
        with self.assertRaises(PortsConfigError):
            PortsMap(ports={"abc": "http://a"})

    def test_invalid_backend_urls_rejected(self):
        with self.assertRaises(PortsConfigError):
            PortsMap(ports={80: ""})
        with self.assertRaises(PortsConfigError):
            PortsMap(ports={80: None})
        with self.assertRaises(PortsConfigError):
            PortsMap(ports={80: 123})

    def test_invalid_default_port_type(self):
        with self.assertRaises(PortsConfigError):
            PortsMap(ports={80: "http://a"}, default_port="abc")
        with self.assertRaises(PortsConfigError):
            PortsMap(ports={80: "http://a"}, default_port=0)
        with self.assertRaises(PortsConfigError):
            PortsMap(ports={80: "http://a"}, default_port=70000)

    def test_ports_must_be_dict(self):
        with self.assertRaises(PortsConfigError):
            PortsMap(ports=[("80", "http://a")])


class TestLoadPortsConfig(unittest.TestCase):
    """Spec 029 FR-010: config file loading."""

    def _write_yaml(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".yaml")
        with os.fdopen(fd, "w") as f:
            f.write(content)
        self.addCleanup(os.unlink, path)
        return path

    def _write_json(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            f.write(content)
        self.addCleanup(os.unlink, path)
        return path

    def test_yaml_minimal_with_default(self):
        path = self._write_yaml(
            "default_port: 9090\n"
            "ports:\n"
            "  80: http://10.0.0.1:8081\n"
            "  9090: http://10.0.0.2:9090\n"
        )
        pm = load_ports_config(path)
        self.assertEqual(pm.default_port, 9090)
        self.assertEqual(pm.get(80), "http://10.0.0.1:8081")
        self.assertEqual(pm.get(9090), "http://10.0.0.2:9090")

    def test_yaml_no_default_picks_first(self):
        path = self._write_yaml(
            "ports:\n"
            "  9090: http://10.0.0.2:9090\n"
            "  80: http://10.0.0.1:8081\n"
        )
        # No default_port → first key in dict order
        pm = load_ports_config(path)
        self.assertEqual(pm.default_port, 9090)

    def test_json_config(self):
        path = self._write_json(
            json.dumps({
                "default_port": 443,
                "ports": {"443": "http://a", "80": "http://b"},
            })
        )
        pm = load_ports_config(path)
        self.assertEqual(pm.default_port, 443)
        self.assertIn(443, pm.ports)
        self.assertEqual(pm.get(443), "http://a")

    def test_reload_picks_up_changes(self):
        path = self._write_yaml(
            "default_port: 80\n"
            "ports:\n"
            "  80: http://original\n"
        )
        pm = load_ports_config(path)
        self.assertEqual(pm.get(80), "http://original")

        # Rewrite file
        with open(path, "w") as f:
            f.write(
                "default_port: 80\n"
                "ports:\n"
                "  80: http://updated\n"
                "  9090: http://new\n"
            )

        pm2 = pm.reload()
        self.assertEqual(pm2.get(80), "http://updated")
        self.assertEqual(pm2.get(9090), "http://new")
        self.assertEqual(len(pm2), 2)

    def test_missing_ports_section_rejected(self):
        path = self._write_yaml("default_port: 80\n")
        with self.assertRaises(PortsConfigError) as ctx:
            load_ports_config(path)
        self.assertIn("missing 'ports:'", str(ctx.exception))

    def test_empty_ports_section_rejected(self):
        path = self._write_yaml("ports: {}\n")
        with self.assertRaises(PortsConfigError):
            load_ports_config(path)

    def test_default_port_not_in_ports_rejected(self):
        path = self._write_yaml(
            "default_port: 9090\n"
            "ports:\n"
            "  80: http://a\n"
        )
        with self.assertRaises(PortsConfigError) as ctx:
            load_ports_config(path)
        self.assertIn("not in ports map", str(ctx.exception))

    def test_invalid_yaml_rejected(self):
        path = self._write_yaml("this: is: not: valid: yaml: [[[")
        with self.assertRaises(PortsConfigError):
            load_ports_config(path)

    def test_invalid_json_rejected(self):
        path = self._write_json("{not valid json")
        with self.assertRaises(PortsConfigError):
            load_ports_config(path)

    def test_string_port_keys_coerced(self):
        # YAML with quoted "80" should be coerced to int
        path = self._write_yaml(
            'ports:\n'
            '  "80": http://a\n'
            '  "9090": http://b\n'
        )
        pm = load_ports_config(path)
        self.assertIn(80, pm.ports)
        self.assertIn(9090, pm.ports)


class TestFromPortsLegacy(unittest.TestCase):
    """Spec 029 FR-013: legacy --ports backwards compat."""

    def test_single_port(self):
        pm = from_ports_legacy({80: "http://localhost:8081"})
        self.assertEqual(pm.default_port, 80)
        self.assertEqual(pm.get(80), "http://localhost:8081")

    def test_first_port_becomes_default(self):
        pm = from_ports_legacy({9090: "http://a", 80: "http://b"})
        self.assertEqual(pm.default_port, 9090)

    def test_empty_rejected(self):
        with self.assertRaises(PortsConfigError):
            from_ports_legacy({})


if __name__ == "__main__":
    unittest.main()

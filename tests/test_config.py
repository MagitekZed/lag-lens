"""Tests for laglens.config: defaults, unknown keys, clamping, redaction, chmod."""
import copy
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens import config  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def strip(cfg):
    return {k: v for k, v in cfg.items() if not k.startswith("_")}


class ExportsTests(unittest.TestCase):
    def test_iter_keys_is_public(self):
        self.assertIn("iter_keys", config.__all__)
        self.assertEqual(sorted(config.iter_keys({"a": {"b": 1, "c": {"d": 2}}, "e": 3})), ["a.b", "a.c.d", "e"])


class DefaultsTests(unittest.TestCase):
    def test_defaults_without_file(self):
        cfg = config.load_config(None)
        self.assertEqual(strip(cfg), config.DEFAULTS)
        self.assertEqual(cfg["_warnings"], [])
        for removed in ("trains", "big_packets", "pmtu", "pulse", "peer_url"):
            self.assertNotIn(removed, cfg)
        self.assertNotIn("calibrate", cfg["path"])
        self.assertEqual(cfg["hop_rate_hz"], 2)
        self.assertEqual(cfg["docsis"]["pages"][0], "/network_setup.jst")
        self.assertEqual(cfg["docsis"]["login_paths"], ["/check.jst", "/check.jsp"])
        self.assertIn("stun", cfg["targets"])  # reserved key kept

    def test_example_file_matches_defaults(self):
        example = ROOT / "config.example.json"
        cfg = config.load_config(example)
        self.assertEqual(cfg["_warnings"], [])
        self.assertEqual(strip(cfg), config.DEFAULTS)
        with open(example) as fh:
            raw = json.load(fh)
        self.assertEqual(raw, config.DEFAULTS)

    def test_defaults_not_mutated(self):
        before = copy.deepcopy(config.DEFAULTS)
        cfg = config.load_config(None, {"targets.v4": ["9.9.9.9"], "docsis.pages": []})
        cfg["targets"]["v4"].append("x")
        cfg["cdn"]["urls"].append("y")
        self.assertEqual(config.DEFAULTS, before)


class LoadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="laglens-cfg-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, obj, name="config.json"):
        p = self.tmp / name
        p.write_text(json.dumps(obj) if not isinstance(obj, str) else obj)
        return p

    def test_file_merges_over_defaults(self):
        p = self.write({"port": 9000, "docsis": {"password": "hunter2"}, "targets": {"xbox_ip": "10.0.0.23"}})
        cfg = config.load_config(p)
        self.assertEqual(cfg["port"], 9000)
        self.assertEqual(cfg["docsis"]["password"], "hunter2")
        self.assertEqual(cfg["docsis"]["username"], "admin")
        self.assertEqual(cfg["targets"]["xbox_ip"], "10.0.0.23")
        self.assertEqual(cfg["targets"]["v4"], ["1.1.1.1", "8.8.8.8"])

    def test_unknown_keys_warn_and_are_dropped(self):
        p = self.write({"bogus": 1, "docsis": {"nope": 2, "interval_s": 30}, "trains": {"enabled": True}})
        with self.assertLogs("laglens.config", level="WARNING") as logs:
            cfg = config.load_config(p)
        text = "\n".join(logs.output)
        self.assertIn("'bogus'", text)
        self.assertIn("'docsis.nope'", text)
        self.assertIn("'trains'", text)
        self.assertNotIn("bogus", cfg)
        self.assertNotIn("nope", cfg["docsis"])
        self.assertEqual(cfg["docsis"]["interval_s"], 30)
        self.assertEqual(len(cfg["_warnings"]), 3)

    def test_clamping(self):
        p = self.write({"rate_hz": 9, "hop_rate_hz": 7})
        with self.assertLogs("laglens.config", level="WARNING"):
            cfg = config.load_config(p)
        self.assertEqual(cfg["rate_hz"], 5)
        self.assertEqual(cfg["hop_rate_hz"], 5)
        cfg = config.load_config(None, {"rate_hz": 0.2})
        self.assertEqual(cfg["rate_hz"], 1)
        cfg = config.load_config(None, {"rate_hz": 2.5})
        self.assertEqual(cfg["rate_hz"], 2.5)

    def test_invalid_values_revert_to_default(self):
        p = self.write({"port": "abc", "targets": "nope", "cdn": {"enabled": "yes"}, "wifi": {"enabled": "auto"}, "label": 5})
        with self.assertLogs("laglens.config", level="WARNING") as logs:
            cfg = config.load_config(p)
        self.assertEqual(cfg["port"], 8787)
        self.assertEqual(cfg["targets"], config.DEFAULTS["targets"])
        self.assertTrue(cfg["cdn"]["enabled"])
        self.assertEqual(cfg["wifi"]["enabled"], "auto")
        self.assertIsNone(cfg["label"])
        self.assertEqual(len(logs.output), 4)

    def test_bad_file_yields_defaults(self):
        p = self.write("{not json")
        with self.assertLogs("laglens.config", level="WARNING"):
            cfg = config.load_config(p)
        self.assertEqual(strip(cfg), config.DEFAULTS)
        p2 = self.write([1, 2])
        with self.assertLogs("laglens.config", level="WARNING"):
            cfg = config.load_config(p2)
        self.assertEqual(strip(cfg), config.DEFAULTS)
        self.assertEqual(strip(config.load_config(self.tmp / "missing.json")), config.DEFAULTS)

    def test_overrides_dotted_and_nested(self):
        p = self.write({"port": 9000})
        cfg = config.load_config(p, {"port": 9100, "targets.xbox_ip": "10.0.0.5", "docsis": {"password": "pw"}})
        self.assertEqual(cfg["port"], 9100)
        self.assertEqual(cfg["targets"]["xbox_ip"], "10.0.0.5")
        self.assertEqual(cfg["docsis"]["password"], "pw")
        self.assertEqual(config.expand_dotted({"a.b.c": 1, "a.d": 2}), {"a": {"b": {"c": 1}, "d": 2}})
        self.assertEqual(config.expand_dotted(None), {})

    def test_deep_merge(self):
        base = {"a": {"x": 1, "y": 2}, "b": [1]}
        out = config.deep_merge(base, {"a": {"y": 3}, "b": [2]})
        self.assertEqual(out, {"a": {"x": 1, "y": 3}, "b": [2]})
        self.assertEqual(base["a"]["y"], 2)


class RedactTests(unittest.TestCase):
    def test_redact_secrets_only(self):
        cfg = config.load_config(None, {"docsis.password": "hunter2", "notify.ntfy_topic": "topic"})
        red = config.redact(cfg)
        self.assertEqual(red["docsis"]["password"], "***")
        self.assertEqual(red["docsis"]["username"], "admin")
        self.assertEqual(red["notify"]["ntfy_topic"], "topic")
        self.assertEqual(cfg["docsis"]["password"], "hunter2")  # original untouched
        self.assertIsNone(config.redact(config.DEFAULTS)["docsis"]["password"])
        self.assertTrue(config.has_secret(cfg))
        self.assertFalse(config.has_secret(config.DEFAULTS))
        nested = config.redact({"x": [{"api_token": "abc"}], "secret_key": "s", "plain": "p"})
        self.assertEqual(nested, {"x": [{"api_token": "***"}], "secret_key": "***", "plain": "p"})

    def test_public_strips_internal_keys(self):
        cfg = config.load_config(None)
        self.assertNotIn("_warnings", config.public(cfg))
        self.assertEqual(sorted(config.iter_keys({"a": {"b": 1}, "c": 2})), ["a.b", "c"])


class EnsureFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="laglens-cfg-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_creates_from_example_next_to_it(self):
        example = self.tmp / "config.example.json"
        example.write_text(json.dumps({"port": 1234}))
        p = config.ensure_config_file(self.tmp / "config.json")
        self.assertEqual(json.loads(p.read_text()), {"port": 1234})

    def test_creates_defaults_when_no_example(self):
        sub = self.tmp / "deep" / "dir"
        p = config.ensure_config_file(sub / "config.json")
        self.assertEqual(json.loads(p.read_text()), config.DEFAULTS)

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_chmod_600_when_password_present(self):
        p = self.tmp / "config.json"
        p.write_text(json.dumps({"docsis": {"password": "pw"}}))
        os.chmod(p, 0o644)
        config.ensure_config_file(p)
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        q = self.tmp / "nopw.json"
        q.write_text(json.dumps({"port": 1}))
        os.chmod(q, 0o644)
        config.ensure_config_file(q)
        self.assertEqual(stat.S_IMODE(q.stat().st_mode), 0o644)

    def test_existing_file_untouched(self):
        p = self.tmp / "config.json"
        p.write_text("{\"port\": 1}")
        config.ensure_config_file(p)
        self.assertEqual(p.read_text(), "{\"port\": 1}")


class SaveValuesTests(unittest.TestCase):
    """``save_values`` persists a dotted key atomically without touching the rest of the file."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="laglens-cfg-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_sets_dotted_key_and_keeps_user_values(self):
        p = self.tmp / "config.json"
        p.write_text(json.dumps({"port": 9999, "targets": {"v4": ["9.9.9.9"], "xbox_ip": None}, "label": "x"}, indent=2))
        self.assertTrue(config.save_values(p, {"targets.xbox_ip": "10.0.0.23"}))
        data = json.loads(p.read_text())
        self.assertEqual(data["targets"]["xbox_ip"], "10.0.0.23")
        self.assertEqual(data["targets"]["v4"], ["9.9.9.9"])  # siblings untouched
        self.assertEqual((data["port"], data["label"]), (9999, "x"))
        self.assertNotIn("rate_hz", data)  # the user's file, not the merged defaults
        self.assertFalse((self.tmp / "config.json.tmp").exists())
        # the value round-trips through load_config
        self.assertEqual(config.load_config(p)["targets"]["xbox_ip"], "10.0.0.23")
        # a missing intermediate object is created
        self.assertTrue(config.save_values(p, {"notify.ntfy_topic": "t"}))
        self.assertEqual(json.loads(p.read_text())["notify"], {"ntfy_topic": "t"})

    def test_missing_file_starts_from_defaults(self):
        p = self.tmp / "sub" / "config.json"
        self.assertTrue(config.save_values(p, {"targets.xbox_ip": "10.0.0.23"}))
        data = json.loads(p.read_text())
        self.assertEqual(data["targets"]["xbox_ip"], "10.0.0.23")
        self.assertEqual(data["port"], config.DEFAULTS["port"])

    def test_unreadable_file_is_left_alone(self):
        p = self.tmp / "config.json"
        p.write_text("{not json")
        with self.assertLogs("laglens.config", level="WARNING"):
            self.assertFalse(config.save_values(p, {"targets.xbox_ip": "10.0.0.23"}))
        self.assertEqual(p.read_text(), "{not json")
        q = self.tmp / "list.json"
        q.write_text("[1, 2]")
        with self.assertLogs("laglens.config", level="WARNING"):
            self.assertFalse(config.save_values(q, {"port": 1}))
        self.assertEqual(q.read_text(), "[1, 2]")

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_mode_600_kept_for_secrets_and_private_files(self):
        p = self.tmp / "config.json"
        p.write_text(json.dumps({"docsis": {"password": "pw"}}))
        os.chmod(p, 0o644)
        self.assertTrue(config.save_values(p, {"targets.xbox_ip": "10.0.0.23"}))
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)  # a secret is present
        q = self.tmp / "private.json"
        q.write_text(json.dumps({"port": 1}))
        os.chmod(q, 0o600)
        self.assertTrue(config.save_values(q, {"port": 2}))
        self.assertEqual(stat.S_IMODE(q.stat().st_mode), 0o600)  # was private: stays private
        r = self.tmp / "plain.json"
        r.write_text(json.dumps({"port": 1}))
        os.chmod(r, 0o644)
        self.assertTrue(config.save_values(r, {"port": 2}))
        self.assertEqual(stat.S_IMODE(r.stat().st_mode), 0o644)


if __name__ == "__main__":
    unittest.main()

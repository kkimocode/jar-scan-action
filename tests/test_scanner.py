"""
Tests for jar_scanner.py. Builds small fixture jars with javac (needs a JDK),
scans them, and checks the right rules fire. Fixture code is never executed.

Run:  python3 -m unittest discover -s tests -v
"""
import base64
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import jar_scanner  # noqa: E402

FAKE_PE = b"MZ" + b"\0" * 0x3A + struct.pack("<I", 0x40) + b"PE\0\0" + b"\0" * 64


def javac(workdir, sources):
    """Compile {path: source} and return {class path inside jar: bytes}."""
    src_dir = os.path.join(workdir, "src")
    out_dir = os.path.join(workdir, "out")
    shutil.rmtree(src_dir, ignore_errors=True)
    shutil.rmtree(out_dir, ignore_errors=True)
    files = []
    for rel, code in sources.items():
        p = os.path.join(src_dir, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(code)
        files.append(p)
    subprocess.run(["javac", "-nowarn", "-d", out_dir] + files, check=True, capture_output=True)
    classes = {}
    for root, _d, fs in os.walk(out_dir):
        for f in fs:
            full = os.path.join(root, f)
            with open(full, "rb") as fh:
                classes[os.path.relpath(full, out_dir).replace(os.sep, "/")] = fh.read()
    return classes


def make_jar(path, entries):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


def fabric_json(mod_id):
    return json.dumps({"schemaVersion": 1, "id": mod_id, "version": "1.0.0", "name": mod_id})


@unittest.skipUnless(shutil.which("javac"), "javac (JDK) required")
class ScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="jarscan-test-")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def scan(self, path):
        return jar_scanner.Scanner().scan_path(path)

    def rules(self, report, min_sev="info"):
        return {f.rule for f in report.findings if jar_scanner.RANK[f.severity] >= jar_scanner.RANK[min_sev]}

    # ---------------------------------------------------------------- clean
    def test_clean_mod_has_no_findings(self):
        classes = javac(self.tmp, {"com/example/cool/CoolMod.java": """
            package com.example.cool;
            import java.util.*;
            public class CoolMod {
                public static final String MOD_ID = "coolmod";
                private final Map<String, Integer> counts = new HashMap<>();
                public void onInitialize() { counts.put("hello", 1); System.out.println("Cool mod loaded"); }
            }"""})
        jar = make_jar(os.path.join(self.tmp, "clean.jar"), {**classes, "fabric.mod.json": fabric_json("coolmod")})
        rep = self.scan(jar)
        self.assertEqual(self.rules(rep, "low"), set())
        self.assertEqual(rep.mod.get("id"), "coolmod")
        self.assertEqual(rep.classes, 1)

    # ---------------------------------------------------------------- stealer
    def test_stealer_pattern(self):
        classes = javac(self.tmp, {"a/Evil.java": """
            package a;
            import java.net.*;
            public class Evil {
                static String P = "\\\\AppData\\\\Roaming\\\\discord\\\\Local Storage\\\\leveldb";
                static String H = "https://discord.com/api/webhooks/123/abc";
                void go() throws Exception { new URL(H).openConnection(); }
            }"""})
        rep = self.scan(make_jar(os.path.join(self.tmp, "stealer.jar"), classes))
        r = self.rules(rep)
        self.assertTrue({"CREDENTIAL_PATHS", "DISCORD_WEBHOOK", "NETWORK", "STEALER_PATTERN"} <= r, r)
        self.assertEqual(rep.worst(), "critical")

    # ---------------------------------------------------------------- dropper
    def test_dropper_with_disguised_exe(self):
        classes = javac(self.tmp, {"b/Drop.java": """
            package b;
            public class Drop {
                void go() throws Exception { Runtime.getRuntime().exec(new String[]{"cmd.exe", "/c", "start", "x.exe"}); }
            }"""})
        rep = self.scan(make_jar(os.path.join(self.tmp, "dropper.jar"),
                                 {**classes, "assets/b/icon.png": FAKE_PE}))
        r = self.rules(rep)
        self.assertTrue({"EXEC", "DISGUISED_EXECUTABLE", "SHELL_COMMAND", "DROPPER_PATTERN"} <= r, r)

    # ---------------------------------------------------------------- encoded payload
    def test_base64_hidden_class(self):
        inner = javac(self.tmp, {"x/Hidden.java": "package x; public class Hidden { int v = 42; }"})
        payload = base64.b64encode(inner["x/Hidden.class"]).decode()
        self.assertGreater(len(payload), 200)
        classes = javac(self.tmp, {"c/Carrier.java": f"""
            package c;
            public class Carrier {{ static final String DATA = "{payload}"; }}"""})
        rep = self.scan(make_jar(os.path.join(self.tmp, "encoded.jar"), classes))
        self.assertIn("ENCODED_PAYLOAD", self.rules(rep, "critical"))

    def test_skin_texture_base64_is_not_flagged(self):
        texture = base64.b64encode(json.dumps(
            {"textures": {"SKIN": {"url": "http://textures.minecraft.net/texture/" + "ab" * 60}}}).encode()).decode()
        classes = javac(self.tmp, {"d/Heads.java": f'package d; public class Heads {{ static String T = "{texture}"; }}'})
        rep = self.scan(make_jar(os.path.join(self.tmp, "heads.jar"), classes))
        self.assertNotIn("ENCODED_PAYLOAD", self.rules(rep))

    # ---------------------------------------------------------------- nested jar-in-jar
    def test_nested_jar_is_scanned(self):
        classes = javac(self.tmp, {"lib/Helper.java": """
            package lib;
            public class Helper { void go() throws Exception { new ProcessBuilder("powershell", "-c", "x").start(); } }"""})
        inner = os.path.join(self.tmp, "inner.jar")
        make_jar(inner, classes)
        with open(inner, "rb") as fh:
            inner_bytes = fh.read()
        rep = self.scan(make_jar(os.path.join(self.tmp, "outer.jar"),
                                 {"META-INF/jars/inner.jar": inner_bytes, "fabric.mod.json": fabric_json("outer")}))
        execs = [f for f in rep.findings if f.rule == "EXEC"]
        self.assertTrue(execs)
        self.assertIn("META-INF/jars/inner.jar!/lib/Helper.class", execs[0].location)
        self.assertEqual(rep.nested_archives, 1)

    # ---------------------------------------------------------------- encrypted loader
    def test_encrypted_loader(self):
        classes = javac(self.tmp, {"e/Loader.java": """
            package e;
            import javax.crypto.*; import javax.crypto.spec.*;
            public class Loader extends ClassLoader {
                Class<?> go(byte[] enc, byte[] key) throws Exception {
                    Cipher c = Cipher.getInstance("AES");
                    c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
                    byte[] b = c.doFinal(enc);
                    return defineClass(null, b, 0, b.length);
                }
            }"""})
        rep = self.scan(make_jar(os.path.join(self.tmp, "loader.jar"), classes))
        self.assertIn("ENCRYPTED_LOADER", self.rules(rep, "high"))

    # ---------------------------------------------------------------- broken input
    def test_malformed_and_fake_class(self):
        jar = make_jar(os.path.join(self.tmp, "broken.jar"), {
            "a/Fake.class": os.urandom(256),
            "a/Broken.class": b"\xca\xfe\xba\xbe\x00\x00\x00\x34\xff\xff\x07",
        })
        r = self.rules(self.scan(jar))
        self.assertIn("ENCRYPTED_CLASS", r)
        self.assertIn("MALFORMED_CLASS", r)

    def test_not_a_zip(self):
        p = os.path.join(self.tmp, "notazip.jar")
        with open(p, "wb") as fh:
            fh.write(b"hello")
        self.assertIn("BAD_ARCHIVE", self.rules(self.scan(p)))

    # ---------------------------------------------------------------- CLI + config
    def test_cli_exit_codes_and_ignore(self):
        classes = javac(self.tmp, {"f/Rpc.java": """
            package f;
            public class Rpc { static { System.loadLibrary("discord-rpc"); } }"""})
        folder = os.path.join(self.tmp, "mods")
        os.makedirs(folder, exist_ok=True)
        make_jar(os.path.join(folder, "rpc-mod.jar"), classes)

        self.assertEqual(jar_scanner.main([folder]), 1)               # NATIVE_LOAD is high
        self.assertEqual(jar_scanner.main([folder, "--fail-on", "critical"]), 0)

        cfg = os.path.join(self.tmp, "cfg.json")
        with open(cfg, "w") as fh:
            json.dump({"ignore": [{"rule": "NATIVE_LOAD", "jar": "rpc-*.jar"}]}, fh)
        out = os.path.join(self.tmp, "report.json")
        self.assertEqual(jar_scanner.main([folder, "--config", cfg, "--json", out]), 0)
        with open(out) as fh:
            data = json.load(fh)
        self.assertEqual(data["result"], "pass")
        self.assertEqual(data["jars"][0]["suppressed"], 1)

        self.assertEqual(jar_scanner.main([os.path.join(self.tmp, "does-not-exist")]), 2)


if __name__ == "__main__":
    unittest.main()

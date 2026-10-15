#!/usr/bin/env python3
"""
jar-scan: static scanner for malware-like behaviour in Java / Minecraft mod jars.

It reads class-file constant pools directly (nothing is decompiled or executed)
and flags things like process execution, native-code loading, credential-file
paths, Discord/Telegram exfiltration URLs, embedded executables and payloads
hidden in Base64 strings. Nested jars (Fabric jar-in-jar) are scanned too.

Zero dependencies: Python 3.8+ standard library only.

Usage:
    python3 jar_scanner.py build/libs
    python3 jar_scanner.py mods/ --fail-on medium --json report.json
"""
from __future__ import annotations

import argparse
import base64
import binascii
import fnmatch
import glob
import hashlib
import io
import json
import os
import re
import struct
import sys
import zipfile
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Set, Tuple

__version__ = "1.0.0"

SEVERITIES = ["info", "low", "medium", "high", "critical"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Safety limits so a hostile jar can't exhaust the runner.
MAX_ENTRY_BYTES = 64 * 1024 * 1024       # skip single entries bigger than this
MAX_TOTAL_BYTES = 1024 * 1024 * 1024     # stop reading a jar after this much data
MAX_NEST_DEPTH = 4                       # jar-in-jar-in-jar...
MAX_TEXT_BYTES = 2 * 1024 * 1024         # text files bigger than this aren't string-scanned
MAX_COMPRESSION_RATIO = 250              # zip-bomb guard

CLASS_MAGIC = b"\xca\xfe\xba\xbe"
TEXT_EXTS = {".json", ".json5", ".txt", ".properties", ".cfg", ".conf", ".toml", ".yml",
             ".yaml", ".mcmeta", ".js", ".sh", ".xml", ".ini", ".mf"}
ARCHIVE_EXTS = {".jar", ".zip", ".litemod"}
EXEC_EXTS = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".msi", ".hta",
             ".jse", ".wsf", ".lnk", ".pif"}
NATIVE_EXTS = {".dll", ".so", ".dylib", ".jnilib", ".sys"}

# --------------------------------------------------------------------------- rules
# Method references found in the constant pool: (rule, severity, message, [(owner, name)])
# "*" matches anything.
METHOD_RULES = [
    ("EXEC", "high", "Starts external processes",
     [("java/lang/Runtime", "exec"), ("java/lang/ProcessBuilder", "<init>"),
      ("java/lang/ProcessBuilder", "start"), ("java/lang/ProcessBuilder", "command")]),
    ("NATIVE_LOAD", "high", "Loads native code (DLL / .so / .dylib)",
     [("java/lang/System", "load"), ("java/lang/System", "loadLibrary"),
      ("java/lang/Runtime", "load"), ("java/lang/Runtime", "loadLibrary"),
      ("com/sun/jna/Native", "load"), ("com/sun/jna/Native", "loadLibrary"),
      ("com/sun/jna/NativeLibrary", "getInstance")]),
    ("DYNAMIC_CLASSLOAD", "medium", "Defines or loads classes at runtime",
     [("*", "defineClass"), ("*", "defineHiddenClass"),
      ("java/net/URLClassLoader", "<init>"), ("java/net/URLClassLoader", "newInstance")]),
    ("SCRIPT_EVAL", "medium", "Evaluates scripts at runtime",
     [("javax/script/ScriptEngineManager", "<init>"), ("javax/script/ScriptEngine", "eval")]),
    ("INSTRUMENTATION", "medium", "Uses the Java agent / attach API to modify other code",
     [("java/lang/instrument/Instrumentation", "*"),
      ("com/sun/tools/attach/VirtualMachine", "attach")]),
    ("UNSAFE", "low", "Uses sun.misc.Unsafe",
     [("sun/misc/Unsafe", "*"), ("jdk/internal/misc/Unsafe", "*")]),
    ("CRYPTO", "info", "Uses encryption",
     [("javax/crypto/Cipher", "getInstance"), ("javax/crypto/spec/SecretKeySpec", "<init>")]),
    ("NETWORK", "info", "Makes network connections",
     [("java/net/URL", "openConnection"), ("java/net/URL", "openStream"),
      ("java/net/http/HttpClient", "send"), ("java/net/http/HttpClient", "sendAsync"),
      ("java/net/Socket", "<init>"), ("java/nio/channels/SocketChannel", "open"),
      ("okhttp3/OkHttpClient", "newCall")]),
    ("SYSTEM_INFO", "info", "Reads environment / hardware identifiers",
     [("java/net/NetworkInterface", "getHardwareAddress"), ("java/lang/System", "getenv")]),
]

# Regexes run over string constants and text files.
STRING_RULES = [
    ("DISCORD_WEBHOOK", "high", "Contains a Discord webhook URL (common exfiltration channel)",
     r"discord(?:app)?\.com/api(?:/v\d+)?/webhooks/"),
    ("TELEGRAM_BOT", "high", "Contains a Telegram bot API URL (common exfiltration channel)",
     r"api\.telegram\.org/bot"),
    ("CREDENTIAL_PATHS", "high", "References browser, Discord or launcher credential files",
     r"Local Storage[\\/]+leveldb|Login Data|Network[\\/]+Cookies|Local State"
     r"|launcher_accounts(?:_microsoft_store)?\.json|microsoft_accounts\.json"
     r"|\.lunarclient[\\/]+settings|\.feather[\\/]+accounts|dQw4w9WgXcQ:"),
    ("DISCORD_TOKEN_REGEX", "high", "Contains a Discord-token-shaped regex",
     r"\[\\w-\]\{2[3-6]\}\\\.|mfa\\\.\["),
    ("SHELL_COMMAND", "high", "Contains shell / system-tool command strings",
     r"\bpowershell(?:\.exe)?\b|\bcmd\.exe\b|\bcmd\s+/[ck]\b|\bschtasks\b|\breg(?:\.exe)?\s+add\b"
     r"|\bmshta\b|\bcertutil\b|\bbitsadmin\b|\bwscript\b|\bcscript\b|\brundll32\b|\bregsvr32\b"),
    ("PERSISTENCE", "high", "References auto-start locations (survives reboots)",
     r"Start Menu[\\/]+Programs[\\/]+Startup|CurrentVersion[\\/]+Run(?:Once)?\b"
     r"|Library/LaunchAgents|/etc/systemd/system|\bcrontab\b"),
    ("DEFENDER_TAMPER", "critical", "Tries to disable or add exclusions to Windows Defender",
     r"Add-MpPreference|Set-MpPreference|ExclusionPath|DisableRealtimeMonitoring"),
    ("PAYLOAD_HOST", "medium", "References file-drop, paste or tunnel hosts",
     r"pastebin\.com/raw|hastebin\.com/raw|transfer\.sh|gofile\.io|anonfiles|catbox\.moe"
     r"|ngrok(?:-free)?\.(?:io|app)|webhook\.site|pipedream\.net|cdn\.discordapp\.com/attachments"),
    ("RAW_IP_URL", "medium", "Connects to a hard-coded IP address",
     r"https?://(?!127\.|0\.0\.0\.0|10\.|192\.168\.)\d{1,3}(?:\.\d{1,3}){3}"),
    ("SESSION_TOKEN", "medium", "Mentions Minecraft session / access tokens",
     r"\baccessToken\b|--accessToken|\bgetAccessToken\b|\bsessionId\b|\bgetSessionId\b"),
]
STRING_RULES = [(r, s, m, re.compile(p, re.IGNORECASE)) for r, s, m, p in STRING_RULES]

B64_FULL = re.compile(r"^[A-Za-z0-9+/_-]{200,}={0,2}$")
B64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{200,}={0,2}")

# --------------------------------------------------------------------------- data


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    jar: str
    location: str
    evidence: str = ""


@dataclass
class JarReport:
    path: str
    sha256: str = ""
    size: int = 0
    mod: Dict[str, str] = field(default_factory=dict)
    classes: int = 0
    nested_archives: int = 0
    findings: List[Finding] = field(default_factory=list)
    suppressed: int = 0
    error: str = ""

    def worst(self) -> Optional[str]:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=RANK.__getitem__)


class _Ctx:
    """Per-top-level-jar scan state."""

    def __init__(self, report: JarReport):
        self.report = report
        self.bytes_read = 0
        self.truncated = False
        self.class_names: List[str] = []
        self.rules_seen: Dict[str, List[str]] = {}

    def add(self, rule, severity, message, location, evidence=""):
        self.report.findings.append(
            Finding(rule, severity, message, self.report.path, location, evidence))
        self.rules_seen.setdefault(rule, []).append(location)


# --------------------------------------------------------------------------- class parsing


def parse_class(data: bytes) -> Tuple[str, List[Tuple[str, str]], List[str]]:
    """Return (this_class, method_refs[(owner, name)], string_constants)."""
    if len(data) < 10 or data[:4] != CLASS_MAGIC:
        raise ValueError("not a class file")
    count = struct.unpack_from(">H", data, 8)[0]
    pos, i = 10, 1
    cp: List[Optional[tuple]] = [None] * count
    while i < count:
        tag = data[pos]
        pos += 1
        if tag == 1:  # Utf8
            ln = struct.unpack_from(">H", data, pos)[0]
            pos += 2
            if pos + ln > len(data):
                raise ValueError("truncated utf8")
            cp[i] = (1, data[pos:pos + ln].decode("utf-8", "replace"))
            pos += ln
        elif tag in (3, 4):  # Integer, Float
            pos += 4
        elif tag in (5, 6):  # Long, Double take two slots
            pos += 8
            i += 1
        elif tag in (7, 8, 16, 19, 20):  # Class, String, MethodType, Module, Package
            cp[i] = (tag, struct.unpack_from(">H", data, pos)[0])
            pos += 2
        elif tag in (9, 10, 11, 12, 17, 18):  # refs, NameAndType, (Invoke)Dynamic
            cp[i] = (tag, struct.unpack_from(">HH", data, pos))
            pos += 4
        elif tag == 15:  # MethodHandle
            pos += 3
        else:
            raise ValueError(f"bad constant tag {tag}")
        i += 1

    def utf8(idx):
        e = cp[idx] if 0 < idx < count else None
        if not e or e[0] != 1:
            raise ValueError("bad utf8 index")
        return e[1]

    def class_name(idx):
        e = cp[idx] if 0 < idx < count else None
        if not e or e[0] != 7:
            raise ValueError("bad class index")
        return utf8(e[1])

    strings, methods = [], []
    for e in cp:
        if not e:
            continue
        if e[0] == 8:
            strings.append(utf8(e[1]))
        elif e[0] in (10, 11):
            owner_idx, nat_idx = e[1]
            nat = cp[nat_idx]
            if not nat or nat[0] != 12:
                raise ValueError("bad NameAndType")
            methods.append((class_name(owner_idx), utf8(nat[1][0])))
    this_idx = struct.unpack_from(">H", data, pos + 2)[0]
    return class_name(this_idx), methods, strings


# --------------------------------------------------------------------------- helpers


def _snippet(s: str, m: re.Match, width: int = 90) -> str:
    start = max(0, m.start() - 20)
    out = s[start:start + width].replace("\n", " ").replace("\r", " ")
    return ("…" if start else "") + out + ("…" if start + width < len(s) else "")


def _is_pe(b: bytes) -> bool:
    if len(b) < 0x40 or b[:2] != b"MZ":
        return False
    off = struct.unpack_from("<I", b, 0x3C)[0]
    return off + 4 <= len(b) and b[off:off + 4] == b"PE\0\0"


def _is_native_binary(b: bytes) -> bool:
    if _is_pe(b) or b[:4] == b"\x7fELF":
        return True
    if b[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        return True
    # Mach-O fat binary shares CAFEBABE with class files; class major version is >= 45.
    if b[:4] == CLASS_MAGIC and len(b) >= 8 and struct.unpack_from(">I", b, 4)[0] < 45:
        return True
    return False


def _is_class(b: bytes) -> bool:
    return b[:4] == CLASS_MAGIC and len(b) >= 8 and struct.unpack_from(">H", b, 6)[0] >= 45


def classify_b64(s: str) -> Optional[Tuple[str, str, str]]:
    """Decode a Base64-looking string and say what's hidden inside, if anything."""
    t = s.rstrip("=").replace("-", "+").replace("_", "/")
    try:
        raw = base64.b64decode(t + "=" * (-len(t) % 4))
    except (binascii.Error, ValueError):
        return None
    if _is_class(raw):
        return ("ENCODED_PAYLOAD", "critical", "Java class hidden inside a Base64 string")
    if _is_native_binary(raw):
        return ("ENCODED_PAYLOAD", "critical", "Native executable hidden inside a Base64 string")
    if raw[:4] == b"PK\x03\x04":
        return ("ENCODED_PAYLOAD", "critical", "Jar/zip archive hidden inside a Base64 string")
    if raw[:1] in (b"{", b"[") or raw[:8] == b"\x89PNG\r\n\x1a\n" or raw[:3] in (b"\xff\xd8\xff", b"GIF"):
        return None  # JSON (e.g. skin textures) or images: normal
    if len(s) >= 2000:
        return ("LARGE_ENCODED_BLOB", "low", "Large Base64 blob (could be a hidden payload or encrypted data)")
    return None


# --------------------------------------------------------------------------- scanner


class Scanner:
    def scan_path(self, path: str) -> JarReport:
        report = JarReport(path=path)
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as e:
            report.error = str(e)
            return report
        report.size = len(data)
        report.sha256 = hashlib.sha256(data).hexdigest()
        ctx = _Ctx(report)
        self._scan_archive(data, "", 0, ctx)
        self._obfuscation_check(ctx)
        self._combos(ctx)
        return report

    # -- archives
    def _scan_archive(self, data: bytes, chain: str, depth: int, ctx: _Ctx):
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError) as e:
            ctx.add("BAD_ARCHIVE", "medium", f"Archive could not be opened ({e})", chain or "(root)")
            return
        with zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                loc = f"{chain}!/{name}" if chain else name
                if info.flag_bits & 0x1:
                    ctx.add("ENCRYPTED_ENTRY", "medium", "Password-protected file inside the jar", loc)
                    continue
                if info.file_size > MAX_ENTRY_BYTES:
                    ctx.add("OVERSIZED_ENTRY", "low", f"Entry skipped, too large ({info.file_size} bytes)", loc)
                    continue
                if (info.compress_size and info.file_size > 10 * 1024 * 1024
                        and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO):
                    ctx.add("ZIP_BOMB", "high", "Entry has an extreme compression ratio (zip bomb?)", loc)
                    continue
                if ctx.bytes_read + info.file_size > MAX_TOTAL_BYTES:
                    if not ctx.truncated:
                        ctx.truncated = True
                        ctx.add("SCAN_TRUNCATED", "medium", "Jar too large, scan stopped early", loc)
                    return
                try:
                    blob = zf.read(info)
                except Exception as e:  # corrupt entries, bad CRCs, unsupported compression
                    ctx.add("UNREADABLE_ENTRY", "low", f"Entry could not be read ({e})", loc)
                    continue
                ctx.bytes_read += len(blob)
                self._scan_entry(name, blob, loc, depth, ctx)

    def _scan_entry(self, name: str, blob: bytes, loc: str, depth: int, ctx: _Ctx):
        lower = name.lower()
        ext = os.path.splitext(lower)[1]

        if ext == ".class" or _is_class(blob):
            if _is_class(blob):
                self._scan_class(blob, loc, depth, ctx)
            else:
                ctx.add("ENCRYPTED_CLASS", "medium", "'.class' file that isn't valid bytecode (encrypted?)", loc)
            return

        if ext in EXEC_EXTS:
            ctx.add("EMBEDDED_EXECUTABLE", "high", f"Bundles a Windows executable/script ({ext})", loc)
        elif ext in NATIVE_EXTS:
            sev = "high" if ext == ".sys" else "medium"
            ctx.add("EMBEDDED_NATIVE", sev, f"Bundles a native library ({ext})", loc)
        elif _is_native_binary(blob):
            ctx.add("DISGUISED_EXECUTABLE", "high",
                    f"Native executable disguised as '{ext or 'no extension'}'", loc)

        if blob[:4] == b"PK\x03\x04" or ext in ARCHIVE_EXTS:
            if depth >= MAX_NEST_DEPTH:
                ctx.add("NEST_TOO_DEEP", "medium", "Archives nested too deeply, not scanned", loc)
                return
            if ext not in ARCHIVE_EXTS:
                ctx.add("DISGUISED_ARCHIVE", "medium", f"Zip/jar archive disguised as '{ext or 'no extension'}'", loc)
            ctx.report.nested_archives += 1
            self._scan_archive(blob, loc, depth + 1, ctx)
            return

        if (ext in TEXT_EXTS or lower == "meta-inf/manifest.mf") and len(blob) <= MAX_TEXT_BYTES:
            text = blob.decode("utf-8", "replace")
            self._scan_strings([text], loc, ctx, from_class=False)
            if depth == 0:
                self._metadata(lower, text, loc, ctx)

    def _metadata(self, lower: str, text: str, loc: str, ctx: _Ctx):
        if lower in ("fabric.mod.json", "quilt.mod.json"):
            try:
                meta = json.loads(text)
                if lower == "quilt.mod.json":
                    meta = meta.get("quilt_loader", {})
                    meta = {**meta, **meta.get("metadata", {})}
                ctx.report.mod = {k: str(meta.get(k)) for k in ("id", "name", "version") if meta.get(k)}
                ctx.report.mod["loader"] = "fabric" if lower.startswith("fabric") else "quilt"
            except (ValueError, AttributeError):
                pass
        elif lower in ("meta-inf/mods.toml", "meta-inf/neoforge.mods.toml"):
            m = re.search(r'modId\s*=\s*"([^"]+)"', text)
            if m:
                ctx.report.mod = {"id": m.group(1), "loader": "forge" if "neoforge" not in lower else "neoforge"}
        elif lower == "meta-inf/manifest.mf":
            agent = re.search(r"^(Premain-Class|Agent-Class|Launcher-Agent-Class):\s*(\S+)", text, re.M)
            if agent:
                ctx.add("JAVA_AGENT", "medium", "Jar declares itself as a Java agent", loc,
                        f"{agent.group(1)}: {agent.group(2)}")

    def _scan_class(self, blob: bytes, loc: str, depth: int, ctx: _Ctx):
        try:
            this_class, methods, strings = parse_class(blob)
        except (ValueError, struct.error, IndexError) as e:
            ctx.add("MALFORMED_CLASS", "medium", f"Class could not be parsed, possibly crafted to break tools ({e})", loc)
            return
        ctx.report.classes += 1
        if depth == 0:
            ctx.class_names.append(this_class)

        hits: Dict[str, Set[str]] = {}
        for owner, mname in methods:
            for rule, _sev, _msg, pats in METHOD_RULES:
                for po, pn in pats:
                    if (po == "*" or po == owner) and (pn == "*" or pn == mname):
                        hits.setdefault(rule, set()).add(f"{owner.replace('/', '.')}.{mname}")
        for rule, sev, msg, _ in METHOD_RULES:
            if rule in hits:
                ctx.add(rule, sev, msg, loc, ", ".join(sorted(hits[rule])[:5]))
        if "CRYPTO" in hits and "DYNAMIC_CLASSLOAD" in hits:
            ctx.add("ENCRYPTED_LOADER", "high", "Decrypts data and defines classes in the same class (encrypted payload loader)", loc)

        self._scan_strings(strings, loc, ctx, from_class=True)

    def _scan_strings(self, strings: List[str], loc: str, ctx: _Ctx, from_class: bool):
        hits: Dict[str, Tuple[str, str, List[str]]] = {}
        for s in strings:
            if len(s) < 4:
                continue
            for rule, sev, msg, rx in STRING_RULES:
                m = rx.search(s)
                if m:
                    entry = hits.setdefault(rule, (sev, msg, []))
                    if len(entry[2]) < 3:
                        entry[2].append(_snippet(s, m))
            candidates = [s] if (from_class and B64_FULL.match(s)) else (
                B64_TOKEN.findall(s)[:50] if not from_class else [])
            for c in candidates:
                res = classify_b64(c)
                if res:
                    rule, sev, msg = res
                    entry = hits.setdefault(rule, (sev, msg, []))
                    if len(entry[2]) < 3:
                        entry[2].append(f"{len(c)} chars: {c[:40]}…")
        for rule, (sev, msg, ev) in hits.items():
            ctx.add(rule, sev, msg, loc, " | ".join(ev))

    # -- jar-level heuristics
    def _obfuscation_check(self, ctx: _Ctx):
        names = [n.rsplit("/", 1)[-1].split("$")[0] for n in ctx.class_names]
        if len(names) < 20:
            return
        weird = [n for n in names if not n.isascii() or re.fullmatch(r"[Il1]{5,}|[O0]{5,}", n)]
        short = [n for n in names if len(n) <= 2]
        if len(weird) >= 5:
            ctx.add("OBFUSCATED", "medium", f"{len(weird)} classes use confusing/non-ASCII names (heavy obfuscation)",
                    "(whole jar)", ", ".join(weird[:5]))
        elif len(short) / len(names) > 0.5:
            ctx.add("OBFUSCATED", "low", f"{len(short)}/{len(names)} classes have 1-2 letter names (obfuscated)",
                    "(whole jar)", ", ".join(short[:8]))

    def _combos(self, ctx: _Ctx):
        seen = ctx.rules_seen

        def first(*rules):
            for r in rules:
                if r in seen:
                    return f"{r} @ {seen[r][0]}"
            return ""

        exfil = ("DISCORD_WEBHOOK", "TELEGRAM_BOT", "PAYLOAD_HOST", "RAW_IP_URL")
        creds = first("CREDENTIAL_PATHS", "DISCORD_TOKEN_REGEX")
        if creds and first(*exfil, "NETWORK"):
            ctx.add("STEALER_PATTERN", "critical",
                    "Reads credential/token files AND can send data out: classic token/account stealer pattern",
                    "(whole jar)", f"{creds}; {first(*exfil, 'NETWORK')}")
        elif first("SESSION_TOKEN") and first(*exfil):
            ctx.add("STEALER_PATTERN", "critical",
                    "Touches Minecraft session tokens AND has an exfiltration endpoint",
                    "(whole jar)", f"{first('SESSION_TOKEN')}; {first(*exfil)}")

        payload = first("EMBEDDED_EXECUTABLE", "DISGUISED_EXECUTABLE", "ENCODED_PAYLOAD")
        runner = first("EXEC", "NATIVE_LOAD", "DYNAMIC_CLASSLOAD")
        if payload and runner:
            ctx.add("DROPPER_PATTERN", "critical",
                    "Carries a hidden/embedded payload AND has code to run it: dropper pattern",
                    "(whole jar)", f"{payload}; {runner}")
        if first("EXEC") and first("PAYLOAD_HOST", "RAW_IP_URL"):
            ctx.add("DOWNLOAD_EXECUTE", "high",
                    "Runs processes AND references payload hosts / raw IPs: download-and-execute pattern",
                    "(whole jar)", f"{first('EXEC')}; {first('PAYLOAD_HOST', 'RAW_IP_URL')}")


# --------------------------------------------------------------------------- config / filtering


def load_config(path: Optional[str], explicit: bool) -> dict:
    if not path or not os.path.isfile(path):
        if explicit and path:
            print(f"warning: config file '{path}' not found, using defaults", file=sys.stderr)
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
    if not isinstance(cfg, dict):
        raise ValueError("config must be a JSON object")
    return cfg


def apply_ignores(report: JarReport, ignores: List[dict]):
    if not ignores:
        return
    kept = []
    base = os.path.basename(report.path)
    for f in report.findings:
        hit = False
        for rule in ignores:
            if (fnmatch.fnmatch(f.rule, rule.get("rule", "*"))
                    and fnmatch.fnmatch(base, rule.get("jar", "*"))
                    and fnmatch.fnmatch(f.location, rule.get("location", "*"))):
                hit = True
                break
        if hit:
            report.suppressed += 1
        else:
            kept.append(f)
    report.findings = kept


def collect_jars(paths: List[str]) -> List[str]:
    out: List[str] = []
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for fn in sorted(files):
                    if os.path.splitext(fn.lower())[1] in (".jar", ".litemod"):
                        out.append(os.path.join(root, fn))
        elif os.path.isfile(p):
            out.append(p)
        else:
            matches = sorted(glob.glob(p, recursive=True))
            if not matches:
                print(f"warning: '{p}' matched nothing", file=sys.stderr)
            out.extend(m for m in matches if os.path.isfile(m))
    seen, uniq = set(), []
    for p in out:
        key = os.path.abspath(p)
        if key not in seen:
            seen.add(key)
            uniq.append(p)
    return uniq


# --------------------------------------------------------------------------- output

COLORS = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m",
          "low": "\033[36m", "info": "\033[2m"}
RESET = "\033[0m"


def _sorted(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (-RANK[f.severity], f.rule, f.location))


def print_console(reports: List[JarReport], fail_on: str, show_info: bool, failed: bool):
    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    c = (lambda sev, s: f"{COLORS[sev]}{s}{RESET}") if color else (lambda sev, s: s)
    print(f"jar-scan {__version__}: scanned {len(reports)} jar(s)\n")
    for r in reports:
        mod = " ".join(v for k, v in r.mod.items() if k in ("id", "version"))
        print(f"■ {r.path}" + (f"  [{mod}]" if mod else ""))
        print(f"  sha256 {r.sha256}  ·  {r.classes} classes" +
              (f"  ·  {r.nested_archives} nested" if r.nested_archives else ""))
        if r.error:
            print(f"  ERROR: {r.error}")
        shown = [f for f in _sorted(r.findings) if show_info or f.severity != "info"]
        hidden = len(r.findings) - len(shown)
        if not shown:
            print("  ✓ nothing suspicious")
        for f in shown:
            print(f"  {c(f.severity, f.severity.upper().ljust(8))}  {f.rule}: {f.message}")
            print(f"            at {f.location}")
            if f.evidence:
                print(f"            {f.evidence[:200]}")
        extra = []
        if hidden:
            extra.append(f"{hidden} info finding(s) hidden (--show-info)")
        if r.suppressed:
            extra.append(f"{r.suppressed} suppressed by config")
        if extra:
            print("  (" + "; ".join(extra) + ")")
        print()
    verdict = "FAIL" if failed else "PASS"
    print(f"Result: {verdict} (fail threshold: {fail_on})")


def _gh_escape(s: str, prop: bool = False) -> str:
    s = s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if prop:
        s = s.replace(":", "%3A").replace(",", "%2C")
    return s


def emit_annotations(reports: List[JarReport], fail_on: str):
    count = 0
    for r in reports:
        for f in _sorted(r.findings):
            if RANK[f.severity] < RANK["medium"] or count >= 50:
                continue
            level = "error" if fail_on != "none" and RANK[f.severity] >= RANK[fail_on] else "warning"
            title = _gh_escape(f"jar-scan {f.severity.upper()} {f.rule}", prop=True)
            msg = _gh_escape(f"{os.path.basename(r.path)} → {f.location}: {f.message}"
                             + (f" ({f.evidence[:150]})" if f.evidence else ""))
            print(f"::{level} title={title}::{msg}")
            count += 1


def _md(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def write_step_summary(path: str, reports: List[JarReport], fail_on: str, failed: bool):
    icon = {"critical": "🟥", "high": "🔴", "medium": "🟠", "low": "🔵", "info": "⚪"}
    lines = [f"## {'❌' if failed else '✅'} Jar scan: {'FAIL' if failed else 'PASS'}", "",
             f"Scanned **{len(reports)}** jar(s) with jar-scan {__version__}, failing on **{fail_on}** and above.", ""]
    lines += ["| Jar | Mod | Worst | Findings | SHA-256 |", "|---|---|---|---|---|"]
    for r in reports:
        visible = [f for f in r.findings if f.severity != "info"]
        worst = r.worst() if visible else None
        lines.append(f"| `{_md(os.path.basename(r.path))}` | {_md(r.mod.get('id', '–'))} | "
                     f"{icon.get(worst, '✅') + ' ' + worst if worst else '✅ clean'} | {len(visible)} | "
                     f"`{r.sha256[:16]}…` |")
    rows = 0
    for r in reports:
        visible = [f for f in _sorted(r.findings) if f.severity != "info"]
        if not visible:
            continue
        lines += ["", f"<details{' open' if r.worst() in ('critical', 'high') else ''}>"
                      f"<summary><b>{_md(os.path.basename(r.path))}</b> ({len(visible)} findings)</summary>", "",
                  "| Severity | Rule | Where | Details |", "|---|---|---|---|"]
        for f in visible:
            if rows >= 300:
                break
            rows += 1
            detail = _md(f.message + (f": `{f.evidence[:120]}`" if f.evidence else ""))
            lines.append(f"| {icon[f.severity]} {f.severity} | `{f.rule}` | `{_md(f.location[-80:])}` | {detail} |")
        lines += ["", "</details>"]
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


# --------------------------------------------------------------------------- main


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Static malware-pattern scanner for Java / Minecraft mod jars.")
    ap.add_argument("paths", nargs="+", help="jar files, folders (scanned recursively) or globs")
    ap.add_argument("--fail-on", choices=SEVERITIES + ["none"], default=None,
                    help="exit 1 if any finding is at or above this severity (default: high)")
    ap.add_argument("--config", default=None, help="JSON config with ignores (default: .jarscan.json if present)")
    ap.add_argument("--json", dest="json_out", help="write a full JSON report to this file")
    ap.add_argument("--show-info", action="store_true", help="also print info-level findings")
    ap.add_argument("--version", action="version", version=f"jar-scan {__version__}")
    args = ap.parse_args(argv)

    # Windows consoles/pipes may not be UTF-8; never crash on a symbol.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
            if not stream.isatty():
                stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError, OSError):
            pass

    try:
        cfg = load_config(args.config or ".jarscan.json", explicit=bool(args.config))
    except (OSError, ValueError) as e:
        print(f"error: bad config: {e}", file=sys.stderr)
        return 2
    fail_on = args.fail_on or cfg.get("fail_on", "high")
    if fail_on not in RANK and fail_on != "none":
        print(f"error: invalid fail_on '{fail_on}'", file=sys.stderr)
        return 2

    jars = collect_jars(args.paths)
    if not jars:
        print("error: no jar files found to scan", file=sys.stderr)
        return 2

    scanner = Scanner()
    reports = []
    for jar in jars:
        rep = scanner.scan_path(jar)
        apply_ignores(rep, cfg.get("ignore", []))
        reports.append(rep)

    failed = fail_on != "none" and any(
        RANK[f.severity] >= RANK[fail_on] for r in reports for f in r.findings) or any(r.error for r in reports)

    print_console(reports, fail_on, args.show_info, failed)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        emit_annotations(reports, fail_on)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        write_step_summary(os.environ["GITHUB_STEP_SUMMARY"], reports, fail_on, failed)
    if os.environ.get("GITHUB_OUTPUT"):
        worst = max((r.worst() for r in reports if r.worst()), key=RANK.__getitem__, default="none")
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as fh:
            fh.write(f"result={'fail' if failed else 'pass'}\nworst={worst}\n"
                     f"findings={sum(len(r.findings) for r in reports)}\n")
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump({"tool": "jar-scan", "version": __version__, "fail_on": fail_on,
                       "result": "fail" if failed else "pass",
                       "jars": [asdict(r) for r in reports]}, fh, indent=2)
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:  # e.g. piped into `head`
        sys.stderr.close()
        sys.exit(1)

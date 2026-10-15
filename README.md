# 🛡️ jar-scan

A GitHub Action (and standalone script) that scans Java / Minecraft mod jars for
malware patterns: token stealers, droppers, hidden payloads and sketchy native code.

It reads class files directly instead of executing anything, so it's safe to point
at jars you don't trust. Nested jars (Fabric jar-in-jar under `META-INF/jars/`) are
unpacked and scanned too. No dependencies, just Python 3.8+.

```
■ mods/totally-legit-fps-boost.jar  [fpsboost 1.0.0]
  CRITICAL  STEALER_PATTERN: Reads credential/token files AND can send data out
            CREDENTIAL_PATHS @ a/Evil.class; DISCORD_WEBHOOK @ a/Evil.class
  CRITICAL  DROPPER_PATTERN: Carries a hidden/embedded payload AND has code to run it
            DISGUISED_EXECUTABLE @ assets/fps/logo.png; EXEC @ a/Evil.class
  HIGH      DISGUISED_EXECUTABLE: Native executable disguised as '.png'
  ...
Result: FAIL (fail threshold: high)
```

In GitHub Actions it also adds error annotations and a summary table to the run page.

## Setup

1. Create a new **public** repo called `jar-scan-action` and push these files to it.
2. Tag a release so other repos can pin it:
   ```bash
   git tag v1 && git push origin v1
   ```
3. In the repo you want to protect, add a workflow. Two ready-made ones are in `examples/`:
   - `examples/mod-build.yml`: builds your mod with Gradle, then scans `build/libs`.
   - `examples/modpack-scan.yml`: scans every jar in `mods/` whenever one is added or changed.

   Replace `YOUR-GITHUB-NAME` with your username.

Minimal usage:

```yaml
- uses: YOUR-GITHUB-NAME/jar-scan-action@v1
  with:
    paths: build/libs        # files, folders or globs; space or newline separated
    fail-on: high            # info | low | medium | high | critical | none
```

| Input | Default | What it does |
|---|---|---|
| `paths` | `build/libs` | What to scan. Folders are searched recursively for `.jar` files. |
| `fail-on` | `high` | Fail the step if anything is at or above this severity. `none` = report only. |
| `config` | `.jarscan.json` | Ignore list (see below). Skipped if the file doesn't exist. |
| `json-report` | `jar-scan-report.json` | Full machine-readable report. Upload it with `actions/upload-artifact`. |

Outputs: `result` (`pass`/`fail`), `worst` (worst severity), `findings` (count).

## Run it locally

Works on Windows, macOS and Linux:

```bash
python jar_scanner.py path/to/some-mod.jar
python jar_scanner.py "%APPDATA%/.minecraft/mods"       # Windows
python jar_scanner.py ~/.minecraft/mods --show-info      # include info-level notes
python jar_scanner.py mods --fail-on medium --json report.json
```

Exit code: `0` pass, `1` fail, `2` nothing to scan / bad config.

## What it detects

**Combined patterns (critical).** These matter most, since one signal alone is often innocent:

| Rule | Meaning |
|---|---|
| `STEALER_PATTERN` | Reads Discord/browser/launcher credential files (or session tokens) **and** has a way to send data out |
| `DROPPER_PATTERN` | Carries an embedded/hidden executable or payload **and** has code to run or load it |
| `ENCODED_PAYLOAD` | A `.class`, `.exe`/ELF or jar hidden inside a Base64 string |
| `DEFENDER_TAMPER` | Strings that disable or add exclusions to Windows Defender |

**High:** `EXEC` (Runtime.exec / ProcessBuilder), `NATIVE_LOAD` (System.load, JNA),
`DISCORD_WEBHOOK`, `TELEGRAM_BOT`, `CREDENTIAL_PATHS`, `DISCORD_TOKEN_REGEX`,
`SHELL_COMMAND` (powershell, cmd.exe, certutil…), `PERSISTENCE` (Startup folder, Run keys),
`EMBEDDED_EXECUTABLE`, `DISGUISED_EXECUTABLE` (e.g. a PE file named `logo.png`),
`ENCRYPTED_LOADER` (decrypts then `defineClass` in one class), `DOWNLOAD_EXECUTE`, `ZIP_BOMB`.

**Medium:** `DYNAMIC_CLASSLOAD`, `EMBEDDED_NATIVE` (.dll/.so), `PAYLOAD_HOST` (pastebin raw,
Discord CDN attachments, ngrok…), `RAW_IP_URL`, `SESSION_TOKEN`, `SCRIPT_EVAL`,
`INSTRUMENTATION`, `JAVA_AGENT`, `OBFUSCATED` (confusing class names), `ENCRYPTED_CLASS`,
`MALFORMED_CLASS`, `DISGUISED_ARCHIVE`, `ENCRYPTED_ENTRY`.

**Low / info:** `UNSAFE`, `LARGE_ENCODED_BLOB`, light obfuscation, plus `NETWORK`, `CRYPTO`
and `SYSTEM_INFO`. Info findings are hidden unless you pass `--show-info`, because almost
every mod with an update checker uses the network.

## False positives and the ignore list

Some legit mods trip rules. A Discord Rich Presence mod loads a native library, for example.
Add a `.jarscan.json` to the repo root (see `.jarscan.example.json`):

```json
{
  "fail_on": "high",
  "ignore": [
    { "rule": "NATIVE_LOAD", "jar": "*discord-rpc*.jar", "reason": "ships its own native lib" },
    { "rule": "EXEC", "location": "com/example/mymod/util/OpenFolder.class" }
  ]
}
```

Each ignore matches by `rule`, `jar` (file name) and/or `location`, and all three accept
`*` wildcards. Write a `reason` so future-you knows why. Keep ignores narrow: ignoring
`EXEC` for one class is fine, ignoring it for every jar defeats the point.

## Limits (read this)

This is a **static pattern scanner**, not an antivirus. A pass means "no known red flags",
not "safe":

- **String encryption beats it.** If a stealer encrypts its strings (common with paid
  obfuscators), the webhook/path rules see nothing. You'll usually still get
  `OBFUSCATED`, `ENCRYPTED_LOADER`, `DYNAMIC_CLASSLOAD` or `LARGE_ENCODED_BLOB`, which is
  why those exist. Treat a heavily obfuscated mod from an unknown source as suspicious
  by default.
- **Split strings** (`"disc" + "ord.com/api/web" + "hooks"`) dodge the string rules.
- **Reflection** (`Class.forName("java.lang.Runtime")`) hides calls from the method rules.
- It doesn't download anything, so a mod that fetches its payload later only shows up
  through `NETWORK` + `DYNAMIC_CLASSLOAD`-style signals.

For anything flagged, check the SHA-256 (printed for every jar) on VirusTotal, open it in
a decompiler, and prefer downloads from Modrinth or CurseForge.

## Development

```bash
python -m unittest discover -s tests -v   # needs a JDK (javac) to build test fixtures
```

The tests compile small fake "malicious" jars (never executed) and check each rule fires,
plus a clean mod that must produce zero findings. `.github/workflows/test.yml` runs them
on Windows, macOS and Linux.

### Adding a rule

- Method-call rules go in `METHOD_RULES`: `(owner class, method name)` in JVM format,
  e.g. `("java/lang/Runtime", "exec")`.
- String rules go in `STRING_RULES` as a regex.
- Combined patterns go in `Scanner._combos`.

Add a test for it in `tests/test_scanner.py`.

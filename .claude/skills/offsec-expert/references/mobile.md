# Mobile Security Reference

## Key Tools

### iOS
- **Frida** — Dynamic instrumentation, runtime hook injection
- **objection** — Frida-based mobile exploration toolkit
- **frida-ios-dump** — IPA extraction from jailbroken device
- **MobSF** — Static + dynamic analysis platform
- **iStaunch / iMazing** — App data extraction
- **SSL Kill Switch 3** — Certificate pinning bypass (Cydia tweak)

### Android
- **apktool** — APK decompilation / recompilation
- **jadx** — DEX → Java decompiler
- **objection** — Runtime exploration (Android + iOS)
- **drozer** — Android attack surface analysis
- **frida** — Dynamic instrumentation
- **MobSF** — Static + dynamic
- **apk-mitm** — Auto-patches APK for MITM proxy

---

## OWASP Mobile Top 10 (2024)

| # | Category | Key Tests |
|---|----------|-----------|
| M1 | Improper Credential Usage | Hardcoded keys/passwords in source, insecure storage |
| M2 | Inadequate Supply Chain Security | Third-party SDK vulns, malicious dependencies |
| M3 | Insecure Authentication/Authorization | Weak token, missing server-side auth checks |
| M4 | Insufficient Input/Output Validation | SQLi, XSS in WebView, path traversal |
| M5 | Insecure Communication | Cert pinning absent, HTTP endpoints, weak TLS |
| M6 | Inadequate Privacy Controls | PII in logs, analytics leakage, clipboard |
| M7 | Insufficient Binary Protections | No obfuscation, debug symbols, root detection bypassable |
| M8 | Security Misconfiguration | Exported activities/providers, debug flags, backup enabled |
| M9 | Insecure Data Storage | Cleartext in SharedPrefs, SQLite, logs, SD card |
| M10 | Insufficient Cryptography | ECB mode, hardcoded IV, weak key derivation |

---

## Static Analysis

### Android APK
```bash
# Decompile
apktool d app.apk -o app_decompiled/
jadx -d app_jadx/ app.apk

# Find secrets
grep -rE "(api_key|secret|password|token|AWS|AKIA)" app_decompiled/

# Check AndroidManifest.xml
# Look for: android:exported="true", android:debuggable="true"
# android:allowBackup="true", custom permissions
cat app_decompiled/AndroidManifest.xml

# Certificate info
keytool -printcert -jarfile app.apk
```

### iOS IPA
```bash
# Unzip IPA
unzip app.ipa -d app_extracted/
# Binary at: Payload/<AppName>.app/<AppName>

# Strings analysis
strings Payload/App.app/App | grep -E "(http|key|secret|token|password)"

# Plist inspection
plutil -p Payload/App.app/Info.plist
```

---

## Dynamic Analysis — Certificate Pinning Bypass

### Frida (universal)
```bash
# objection auto-bypass
objection -g "com.target.app" explore
android sslpinning disable
ios sslpinning disable

# Frida script (Android TrustManager)
frida -U -l ssl_bypass.js com.target.app
```

### Android apk-mitm (no root needed)
```bash
apk-mitm app.apk
# Installs patched APK with pinning removed
adb install app-patched.apk
```

### iOS SSL Kill Switch (jailbroken)
Install via Cydia → enables system-wide pinning bypass for all apps.

---

## Dynamic Analysis — Runtime Exploration

```bash
# List activities (Android)
adb shell am start -n com.target.app/.MainActivity

# Drozer — exported activity abuse
drozer console connect
run app.activity.start --component com.target.app com.target.app.AdminActivity

# Frida — hook function and dump args
frida -U -f com.target.app --no-pause -l hook_login.js

# objection — dump keychain (iOS)
ios keychain dump

# objection — list SQLite databases
android sqlite databases
```

---

## Common Findings

### Insecure Data Storage (M9)
```bash
# Android SharedPreferences
adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml

# Android SQLite
adb shell run-as com.target.app ls /data/data/com.target.app/databases/
adb pull /data/data/com.target.app/databases/app.db
sqlite3 app.db .dump
```

### Exported Components (M8)
```bash
# Activity with no permission — deeplink or direct launch
adb shell am start "intent://target.com/reset?token=123#Intent;scheme=https;package=com.target.app;end"

# Content provider — data extraction
adb shell content query --uri content://com.target.app.provider/users
```

### WebView JavaScript Bridge
Any `addJavascriptInterface` call in Android < 4.2 = RCE. In newer versions, check `@JavascriptInterface` methods for sensitive operations reachable via XSS.

---

## OPSEC Notes
- Jailbroken/rooted devices are detectable — check for jailbreak detection bypass needs
- Frida server on device may be detected by runtime integrity checks (Detect-It-Easy, custom integrity threads)
- Proxy traffic over USB adb tunnel to avoid network-level detection: `adb reverse tcp:8080 tcp:8080`

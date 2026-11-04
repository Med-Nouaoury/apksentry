# Test fixtures

`synthetic.dex` is assembled from the `smali/` sources in this folder with
[smali](https://github.com/baksmali/smali). It is a **harmless synthetic sample**:
it is never executed, it only contains code *shaped like* common Android malware
(IMEI and clipboard leaks, SMS forwarding, a trust-all TrustManager, a fake
Telegram token...) so the tests can check that ApkSentry detects each pattern.

`AndroidManifest.bin` is a compiled (binary XML) manifest declaring the matching
permissions, an accessibility service and an SMS receiver.

Rebuild: `java -jar smali.jar a smali -o synthetic.dex`

`fake_whatsapp_manifest.bin` + `fake_whatsapp.arsc` are the compiled manifest and
resource table of the same sample, renamed to **"WhatsApp"** with the package
`com.wh4tsapp.update`. They test impersonation detection (app name resolved
through `resources.arsc`, wrong package, plus SMS/accessibility permissions).

`pack1.apk`, `pack2.apk`, `pack3.apk` are synthetic **packers** that hide
`synthetic.dex` the way real droppers do: XOR + `DexClassLoader` (file), AES-CBC
with a Base64 key + `InMemoryDexClassLoader`, and RC4 implemented in the app's own
bytecode + zlib + `DexClassLoader` reached through reflection. `emu.dex`
(from `smali-emu/`) checks interpreter arithmetic and sandbox escape attempts.

`pack4.apk` has **two layers**: XOR-decrypts a second packer (its own
`Application` class, another key) which then decrypts `synthetic.dex`.

`pack5.apk` is `pack2` with a different hidden payload: a `VpnService` that routes
all traffic (pattern seen in real droppers on MalwareBazaar).

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

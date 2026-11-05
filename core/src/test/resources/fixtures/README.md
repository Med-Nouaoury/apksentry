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

**Native (ARM64) fixtures** — built from `tools/native-fixtures/*.c` with
`clang --target=aarch64-linux-android24 -fuse-ld=lld -shared -fPIC -O2 -nostdlib -nostdlibinc -Wl,--pack-dyn-relocs=android+relr -Wl,--use-android-relr-tags`
against the JDK's `jni.h`:

- `npack.apk`: `Application.onCreate` → `System.loadLibrary("pack")` → `JNI_OnLoad` decrypts `synthetic.dex` (rolling XOR) and hands it to `InMemoryDexClassLoader` through `NewDirectByteBuffer`.
- `nspy.apk`: a `native` method that decrypts its strings, sends an SMS through `SmsManager` via JNI and resolves a C2 host.
- `libreg.so`: `RegisterNatives` under an obfuscated name, RC4-like string decryption, 64-bit arithmetic printed with `snprintf`.
- `libasset.so` + `core.bin`: reads an asset with `AAssetManager`, XOR + zlib `uncompress`, writes a dex with `fopen`/`fwrite`.
- `libesc.so`: sandbox-escape attempts (`system`, raw `execve`/`openat` syscalls, file writes, infinite loop).

`arm64_cases.txt.gz`: 400 random instructions with register/memory results recorded from Unicorn (`tools/armfuzz/gen.py`).

`rotated.apk` / `mixed.apk`: hand-built APK Signing Blocks (validated with `apksigtool`). `rotated`: v2 signed
with an old key, v3 with a new key plus a proof-of-rotation lineage linking them (legitimate key rotation, as
WhatsApp does). `mixed`: the same old v2 key next to an unrelated v3 key with no lineage (suspicious).

`nstk.apk` (`stk.c`): anti-emulation seen in a real malware family — `JNI_OnLoad` reads `Thread.getStackTrace()`
and only registers its decryptor if the expected Java class is a caller.

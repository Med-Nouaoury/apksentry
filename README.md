# ApkSentry · فاحص تطبيقات APK

تطبيق أندرويد مفتوح المصدر يفحص ملفات **APK / APKS / XAPK** قبل تثبيتها، ويعطيك تقريراً مفصّلاً ودرجتين:
**درجة الخطر** (هل هناك سلوك خبيث محتمل؟) و**درجة التعديل** (هل عُدِّل التطبيق أو أُعيد توقيعه؟).

الفحص يتم كاملاً على هاتفك. لا يُرفع أي ملف إلى أي مكان.

> An open-source Android app that statically inspects APK / APKS / XAPK files before you install them,
> and reports a **risk score** and a **modification score**. Everything runs on-device. [English below](#english).

---

## ماذا يفحص؟

| الطبقة | ما يفعله |
|---|---|
| **قواعد بيانات الفيروسات** | يبحث ببصمة الملف وكل ملفاته الداخلية في MalwareBazaar و VirusTotal (بمفاتيحك المجانية، البصمات فقط) |
| **البصمة التقريبية (TLSH)** | بصمة "تشبه" ماشي "تطابق": نسخة معدّلة شوية من فيروس معروف كتبقى قريبة منو. القاعدة كتتحمّل من MalwareBazaar (آخر 1000 فيروس أندرويد في كل تحديث) وكتخدم بلا أنترنت. تطبيق TLSH مكتوب بـ Kotlin ومتطابق 100% مع المكتبة الرسمية py-tlsh |
| **انتحال الهوية** | يقرأ اسم التطبيق الظاهر (من resources.arsc، بكل اللغات) ويقارنه بـ 40 تطبيق مشهور (WhatsApp، Instagram، Telegram، Binance، Chrome...): الاسم نفسه، خطأ إملائي مقصود، حروف سيريلية تشبه اللاتينية، أرقام بدل حروف، أو حزمة مقلّدة بحرف واحد. إذا كان الاسم ديال تطبيق مشهور والحزمة ماشي ديالو، ويطلب الرسائل أو خدمة الوصول، فهذا أسلوب الفيروسات البنكية |
| **السمعة (F-Droid)** | لائحة توقيعات كل تطبيقات F-Droid (كتتحدّث كل أسبوع). إلا كانت النسخة موقّعة بنفس التوقيع بالضبط، فهي مبنية من الكود المصدري ومراجَعة: القدرات القوية كتبان ولكن ما كتتحسبش خطر. النسخة المعدّلة كتتوقّع بمفتاح آخر فما كتطابقش. القياس كيطفي هاد الطبقة باش ما يغشّش |
| **فك الكود المخفي (محاكي Dalvik)** | الفيروسات "المغلّفة" تحمل كودها الحقيقي مشفّراً وتفكّه وقت التشغيل. ApkSentry ينفّذ كود البداية داخل محاكي Dalvik مكتوب من الصفر، داخل صندوق مغلق (لا ملفات حقيقية، لا إنترنت، لا أوامر، حدود للخطوات والذاكرة والوقت)، ويلتقط الكود الحقيقي لحظة تحميله ثم يفحصه. مختبر على XOR و AES-CBC و RC4 مكتوب داخل التطبيق + zlib + تحميل عبر reflection، ومختبر ضد محاولات الهروب من الصندوق |
| **سلوك الفيروسات المعروفة** | أكثر من 20 قاعدة لعائلات أندرويد الشائعة: أحصنة طروادة البنكية، keyloggers، سرقة الرسائل ورموز OTP، احتيال SMS، clipper، برامج الفدية، droppers، الأبواب الخلفية... |
| **تتبّع البيانات (taint analysis)** | يتبع بياناتك (IMEI، الموقع، جهات الاتصال، الرسائل، الحافظة، الحسابات، الإشعارات، نصوص الشاشة) من مصدرها، عبر السجلات والحقول والوظائف، حتى الإنترنت أو SMS |
| **فك تعليمات DEX كاملة** | كل تعليمة وكل فرع (CFG)، من يستدعي ماذا، والنصوص المشفّرة ودوال فكّها |
| **المكتبات native من الداخل** | الوظائف المستوردة والمصدّرة (JNI)، استدعاءات النظام المباشرة `svc` على ARM64/ARM و `syscall` على x86_64، الكود المشفّر (إنتروبيا)، ونصوص مكافحة التحليل والأوامر |
| **سلامة التوقيع** | تحقق حقيقي من توقيع v2/v3 (التوقيع نفسه + بصمة المحتوى كاملاً): يكشف أي ملف تغيّر بايت واحد منه بعد التوقيع |
| **التوقيع الرسمي** | مقارنة تلقائية مع النسخة المثبتة من Google Play، قائمتك الموثوقة، وكشف مفتاح الاختبار العلني لـ AOSP |
| **الثغرات الأمنية** | TrustManager يقبل أي شهادة، HostnameVerifier مفتوح، WebView يتجاهل أخطاء SSL، تشفير ECB/DES/RC4، مفاتيح تشفير مكتوبة، ContentProvider مفتوح، إعدادات شبكة تثق بشهادات المستخدم أو تسمح بـ HTTP |
| **الأسرار المكتوبة** | مفاتيح خاصة، مفاتيح AWS و Stripe، توكنات GitHub و Slack و JWT، وتوكنات بوتات تيليغرام و Discord webhooks (قنوات تسريب تستعملها برامج التجسس) |
| **أدوات التعديل والحماية** | MT Manager، NP Manager، Lucky Patcher، Xposed، Jiagu، Bangcle، Legu، DexProtector... و packers التي تخفي الكود الحقيقي |
| **الأساسيات** | الصلاحيات، الخدمات الخطيرة، المكوّنات المضافة، الملفات المخفية، الروابط وعناوين IP وآثار التعدين |

يدعم الملفات الضخمة (ألعاب بحجم 7 جيجا أو أكثر) بدون تحميلها إلى الذاكرة، ويقرأ الملفات غير المضغوطة داخل الحزمة مباشرة بدون نسخها.

النتيجة: **درجة الخطر** (سلوك خبيث محتمل) و**درجة التعديل** (معدّل أو أُعيد توقيعه)، وقائمة **الثغرات** منفصلة عنهما، مع تقرير مفصّل ونصائح.

## مراقبة الاتصال (وقت التشغيل)

الفحص الثابت لا يرى ما يفعله الكود المشفّر وهو يعمل، لذلك فيه تبويب **مراقبة الاتصال**:

- تختار تطبيقاً مثبّتاً، فيمر عبر VPN محلي على هاتفك (لا خوادم خارجية).
- ترى كل موقع يطلبه التطبيق مباشرة، مصنّفاً: معروف، إعلانات/تتبّع، غير مألوف، أو **مشبوه** (يشبه اسم الموقع الذي أعاد توقيع التطبيق).
- تمنع أي موقع بضغطة، أو تقطع الإنترنت عن التطبيق كلياً مع تسجيل كل ما يحاول الوصول إليه، حتى الاتصالات المباشرة بعناوين IP.

الحدود: المراقبة عبر طلبات DNS؛ إذا كان "DNS الخاص" مضبوطاً على اسم خادم، أو اتصل التطبيق بعنوان IP مباشرة، فلن يظهر ذلك إلا في وضع المنع الكامل. والأندرويد يسمح بـ VPN واحد فقط في نفس الوقت.

## الاستقرار

- كل مرحلة من الفحص معزولة: ملف تالف أو مُعدّ لإسقاط أدوات التحليل لا يوقف الفحص، ويُسجَّل كعلامة مشبوهة بدل حكم مطمئن.
- حدود للوقت والذاكرة وحجم العمل في كل محلّل (DEX، ELF، تتبّع البيانات)، ضد الملفات المُعدّة لإبطاء الفحص إلى ما لا نهاية.
- اختُبر المحرك بأكثر من ألف ملف مخرَّب عشوائياً (fuzzing)، وعلى تطبيقات حقيقية مثل Bitwarden و NewPipe و Termux و KeePassDX.
- الكود غير المعروف لا يُحسب خطراً إلا إذا ظهر أن التطبيق أُعيد تجميعه، فالتطبيقات السليمة لا تأخذ إنذارات كاذبة بسبب مكتباتها.

## التثبيت

حمّل `ApkSentry.apk` من صفحة [Releases](../../releases). كل ملف هناك مبني تلقائياً من هذا الكود عبر GitHub Actions، وبصماته في `SHA256SUMS.txt`.

**على الحاسوب** (Windows / Mac / Linux، يحتاج Java 17):

```
java -jar apksentry-cli.jar "game.apks" --out report.txt
java -jar apksentry-cli.jar "game.apks" --mb مفتاح_MalwareBazaar --vt مفتاح_VirusTotal
java -jar apksentry-cli.jar "game.apks" --trusted trusted.txt   # كل سطر: اسم_الحزمة بصمة_SHA256
```

## قياس الدقة (benchmark)

ما كنصدّقوش أي رقم ما قسناهش. `bench/benchmark.py` كيحمّل فيروسات أندرويد حقيقية من MalwareBazaar وتطبيقات نظيفة من F-Droid، كيفحصهم بالمحرك بوحدو (بلا قواعد البيانات)، وكيعطي نسبة الكشف ونسبة الإنذارات الكاذبة، مع لائحة الفيروسات اللي فاتتنا.

```bash
export MB_API_KEY=...   # المفتاح ديالك، ما يتكتبش ف أي ملف
python3 bench/benchmark.py --cli apksentry-cli.jar --malware 300 --fdroid 200
```

**الطريقة الأسلم (بلا ما يقيس الحاسوب ديالك):** زيد secret سميتو `MB_API_KEY` ف Settings > Secrets and variables > Actions، ومن بعد Actions > Benchmark > Run workflow. كيتخدم ف سيرفر GitHub اللي كيتمسح من بعد، والنتيجة كتبان ف صفحة الـ run.

الفحص ثابت وما كيشغّل حتى تطبيق. الفيروسات كتتمسح أوتوماتيكياً من بعد الفحص، وما كيتحفظ غير التقرير.

## حدود الفحص (مهم)

- هذا **فحص ثابت**: يقرأ الملف ولا يشغّله. لا يوجد فحص يضمن الأمان 100%.
- الكود المُخفى داخل مكتبات native (مثلاً بأداة NP Manager) لا يظهر سلوكه. التطبيق ينبّهك لذلك.
  في هذه الحالة راقب أول تشغيل بتطبيق [PCAPdroid](https://github.com/emanuele-f/PCAPdroid)، وامنع التطبيق من الإنترنت إن لم يكن يحتاجه.
- تتبّع البيانات تقريبي: لا يحلّ كل حالات الوراثة والاستدعاء غير المباشر، وقد يفوته تسرّب يمر عبر كود native أو reflection.
- القواعد السلوكية قد تعطي إنذاراً على تطبيق سليم يحتاج فعلاً تلك الصلاحيات؛ اقرأ التفاصيل قبل الحكم.
- لا يتحقق من سلامة التوقيع بايتاً ببايت؛ الأندرويد يفعل ذلك عند التثبيت.

## البناء بنفسك

افتح المشروع في Android Studio، أو:

```
./gradlew :core:test :app:assembleDebug
```

| المجلد | المحتوى |
|---|---|
| `core/` | محرك الفحص: Kotlin عادي بدون أندرويد وبدون مكتبات خارجية: ZIP64، AXML، فك تعليمات DEX و CFG، تتبّع البيانات، ELF و syscalls، التوقيعات، القواعد |
| `app/` | واجهة أندرويد (Jetpack Compose) |

### مفتاح توقيع ثابت (اختياري لكن مستحسن)

بدون مفتاح، تُوقَّع كل نسخة بمفتاح debug مختلف، فلا يمكن تحديث التطبيق فوق النسخة القديمة.
لمفتاح ثابت:

1. أنشئ المفتاح مرة واحدة (احتفظ به ولا ترفعه أبداً إلى GitHub):
   ```
   keytool -genkeypair -v -keystore release.jks -alias apksentry -keyalg RSA -keysize 4096 -validity 10000
   ```
2. حوّله إلى نص base64. في PowerShell:
   ```
   [Convert]::ToBase64String([IO.File]::ReadAllBytes("release.jks")) | Set-Clipboard
   ```
3. في GitHub: Settings ← Secrets and variables ← Actions، أضف:
   `KEYSTORE_BASE64` و `KEYSTORE_PASSWORD` و `KEY_ALIAS` (مثلاً `apksentry`) و `KEY_PASSWORD`.

### نشر إصدار

```
git tag v1.0.0
git push origin v1.0.0
```

GitHub Actions يبني التطبيق ونسخة الحاسوب وينشرهما في Releases تلقائياً.

## القادم

- [x] مراقبة اتصالات التطبيقات وقت التشغيل
- [ ] فحص التطبيقات المثبتة على الهاتف
- [ ] واجهة إنجليزية
- [ ] قواعد YARA قابلة للتحديث
- [ ] التحقق من توقيع v1 القديم
- [ ] قاعدة مشتركة لبصمات المطورين الرسميين

---

## English

**ApkSentry** is a static analyzer for Android packages that runs entirely on the phone.

- Parses ZIP/ZIP64, binary AndroidManifest (AXML), full Dalvik bytecode with control-flow graphs, ELF symbols/segments, and APK Signature Scheme v1/v2/v3 — no third-party parsing libraries.
- Flow-sensitive, inter-procedural taint analysis from personal-data sources (IMEI, location, contacts/SMS, clipboard, accounts, notifications, accessibility text) to network/SMS sinks.
- 20+ behaviour rules for common Android malware families, packer/protector detection, string-decryptor detection.
- Native analysis: JNI exports, direct `svc`/`syscall` usage on ARM64/ARM/x86_64, packed code entropy, anti-analysis strings.
- Full APK Signature Scheme v2/v3 verification (signature + chunked content digests), cross-checked against an independent verifier.
- Official-signer verification against the Play-installed copy or a user trust list; AOSP public test-key detection.
- App security audit: trust-all TrustManagers, allow-all HostnameVerifiers, WebView SSL-error bypass, ECB/DES/RC4, hard-coded keys, exported providers, network-security-config issues, leaked secrets and exfiltration tokens (Telegram bots, Discord webhooks).
- Hardened against hostile input: phase isolation, work/time budgets, fuzz-tested parsers. Unknown-library findings only count when the package shows repackaging evidence.
- TLSH fuzzy hashing (pure Kotlin, byte-identical to the reference py-tlsh) matched offline against an on-device database of recent Android malware pulled from MalwareBazaar, to catch lightly modified variants of known samples.
- Impersonation detection: resolves the user-visible app name from `resources.arsc` in every locale and compares it with ~40 popular apps (exact name, deliberate typos, Cyrillic look-alikes, leetspeak, one-character package typosquats). A famous name on a foreign package combined with SMS/accessibility/overlay permissions is flagged as the banking-trojan pattern.
- Hash lookups on MalwareBazaar and VirusTotal with your own free keys (hashes only).
- Handles multi-gigabyte split bundles with low memory by streaming and reading stored entries in place.
- Optional VirusTotal hash lookups with your own API key (hashes only, never files).
- A desktop CLI (`apksentry-cli.jar`) is built from the same engine.

It is a static scanner: it cannot see what native code does at runtime. Pair it with network monitoring (e.g. PCAPdroid) for modified apps.

License: [MIT](LICENSE). Font: IBM Plex Sans Arabic ([SIL OFL 1.1](licenses/IBM-Plex-Sans-Arabic-OFL.txt)). Icons: Material Icons (Apache 2.0). TLSH algorithm and tables ported from the Trend Micro reference implementation (Apache 2.0 / BSD).

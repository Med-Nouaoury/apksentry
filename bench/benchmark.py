#!/usr/bin/env python3
"""
ApkSentry benchmark: كيقيس واش الفحص كيخدم بصح، بالأرقام.

- كيحمّل فيروسات أندرويد حقيقية من MalwareBazaar (بالمفتاح ديالك).
- كيحمّل تطبيقات نظيفة من F-Droid (ولا كيستعمل مجلد ديالك فيه تطبيقات موثوقة).
- كيفحصهم كاملين بنسخة الحاسوب ديال ApkSentry، **بلا** قواعد البيانات (MalwareBazaar/VirusTotal/TLSH)،
  باش نقيسو المحرك بوحدو: واش كيعرف الفيروس من الكود والسلوك، ماشي من البصمة.
- كيكتب تقرير report.md و results.csv.

الفحص ثابت: ما كنشغّلو حتى تطبيق. ولكن الملفات فيروسات حقيقية، فما تفتحهمش وما تثبّتهمش.
برامج الحماية (Windows Defender...) غادي تمسحهم: خدّم السكريبت ف مجلد مستثنى، ولا ف Linux/WSL/Termux.

الاستعمال:
  export MB_API_KEY=المفتاح_ديالك        (Windows: set MB_API_KEY=...)
  python3 benchmark.py --cli apksentry-cli.jar --malware 300 --fdroid 200
  python3 benchmark.py --cli apksentry-cli.jar --malware 300 --clean-dir ~/apks_mn_play

المفتاح ما كيتكتبش ف التقرير وما كيتصيفط لحتى بلاصة من غير MalwareBazaar.
"""
import argparse
import csv
import io
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import zipfile
from collections import defaultdict

MB_API = "https://mb-api.abuse.ch/api/v1/"
FDROID = "https://f-droid.org/repo"
UA = "ApkSentry-benchmark/1.0"
THRESHOLDS = (10, 35, 60)
MAIN_T = 35  # من "منخفض إلى متوسط" لفوق كنعتبروه "تشد"


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def mb_post(key, data, raw=False, timeout=120):
    req = urllib.request.Request(MB_API, data=urllib.parse.urlencode(data).encode(),
                                 headers={"Auth-Key": key, "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read()
    if raw:
        return body
    return json.loads(body)


# عائلات أندرويد معروفة ف MalwareBazaar (اللي ما كايناش كترجع والو، ما فيها مشكل)
FAMILIES = ["SpyNote", "Anatsa", "Hook", "Ermac", "Octo", "Coper", "Medusa", "SharkBot", "Xenomorph", "TeaBot",
            "Cerberus", "Alien", "Hydra", "IRATA", "SpyMax", "CraxsRAT", "AhMyth", "Rafel", "BTMOB", "BtmobRAT",
            "Godfather", "Anubis", "Vultur", "Chameleon", "Brokewell", "PixPirate", "Joker", "FluBot", "BrasDex",
            "Copybara", "ToxicPanda", "Necro", "SpinOk", "TrickMo", "Rocinante", "Antidot", "Gigabud", "NGate",
            "Crocodilus", "Herodotus", "SuperCard", "DroidBot", "Albiriox", "Sturnus", "RatOn", "Klopatra"]


def mb_list(key, n, per_family=25, offset=0, seed=2):
    """أحدث عينات APK + عينات من عائلات معروفة (باش نغطيو أنواع مختلفة)."""
    seen, out = set(), []

    def add(items):
        for it in items or []:
            if it.get("file_type") not in (None, "apk"):
                continue
            if it["sha256_hash"] not in seen:
                seen.add(it["sha256_hash"])
                out.append(it)

    j = mb_post(key, {"query": "get_file_type", "file_type": "apk", "limit": "1000"})
    if j.get("query_status") not in ("ok", "no_results"):
        raise SystemExit(f"MalwareBazaar: {j.get('query_status')}")
    add(j.get("data"))
    log(f"  get_file_type: {len(out)}")
    for fam in FAMILIES:
        if len(out) >= n * 2:
            break
        try:
            j = mb_post(key, {"query": "get_siginfo", "signature": fam, "limit": str((per_family + offset) * 3)})
            before = len(out)
            add([x for x in (j.get("data") or []) if x.get("file_type") == "apk"][offset:offset + per_family])
            if len(out) > before:
                log(f"  {fam}: +{len(out) - before}")
        except Exception as e:
            log(f"  {fam}: {e}")
    # توازن: ما نخليوش عائلة وحدة تسيطر على النتيجة
    random.Random(seed).shuffle(out)
    return out[:n]


def mb_info(key, sha):
    j = mb_post(key, {"query": "get_info", "hash": sha})
    return (j.get("data") or [{}])[0] if j.get("query_status") == "ok" else {}


def unzip_infected(blob, dest):
    """عينات MalwareBazaar مضغوطة بكلمة السر infected."""
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            name = z.namelist()[0]
            data = z.read(name, pwd=b"infected")
    except (NotImplementedError, RuntimeError, zipfile.BadZipFile):
        try:
            import pyzipper  # للضغط AES
        except ImportError:
            raise SystemExit("خاصك: pip install pyzipper")
        with pyzipper.AESZipFile(io.BytesIO(blob)) as z:
            z.setpassword(b"infected")
            data = z.read(z.namelist()[0])
    with open(dest, "wb") as f:
        f.write(data)


def get_malware(key, n, folder, sha_list=None, offset=0, seed=2):
    os.makedirs(folder, exist_ok=True)
    if sha_list:
        items = []
        for sha in sha_list:
            info = mb_info(key, sha)
            items.append({"sha256_hash": sha, "signature": info.get("signature"), "tags": info.get("tags")})
    else:
        items = mb_list(key, n, offset=offset, seed=seed)
    out = []
    for i, it in enumerate(items):
        sha = it["sha256_hash"]
        fam = it.get("signature") or next((t for t in (it.get("tags") or []) if t.lower() != "apk"), None) or "unknown"
        path = os.path.join(folder, sha + ".apk.sample")
        if not os.path.exists(path):
            try:
                blob = mb_post(key, {"query": "get_file", "sha256_hash": sha}, raw=True, timeout=300)
                if blob[:1] == b"{":
                    log(f"  [{i+1}/{len(items)}] {sha[:12]} ما تحمّلش: {blob[:80]!r}")
                    continue
                unzip_infected(blob, path)
            except SystemExit:
                raise
            except Exception as e:
                log(f"  [{i+1}/{len(items)}] {sha[:12]} خطأ: {e}")
                continue
        log(f"  [{i+1}/{len(items)}] فيروس {fam}")
        out.append(("malware", path, sha, fam))
    return out


def get_fdroid(n, folder, max_mb=60, seed=1, skip=0):
    os.makedirs(folder, exist_ok=True)
    log("تحميل فهرس F-Droid...")
    req = urllib.request.Request(FDROID + "/index-v2.json", headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=300) as r:
        idx = json.load(r)
    cands = []
    for pkg, p in idx.get("packages", {}).items():
        vers = list((p.get("versions") or {}).values())
        if not vers:
            continue
        v = max(vers, key=lambda x: x.get("added", 0))
        f = v.get("file") or {}
        if f.get("name") and 0 < f.get("size", 0) <= max_mb * 1024 * 1024:
            cands.append((pkg, f["name"], f.get("sha256", "")))
    random.Random(seed).shuffle(cands)
    out = []
    for pkg, name, sha in cands[skip:skip + n]:
        path = os.path.join(folder, pkg + ".apk")
        if not os.path.exists(path):
            try:
                req = urllib.request.Request(FDROID + name, headers={"User-Agent": UA})
                with urllib.request.urlopen(req, timeout=300) as r, open(path, "wb") as o:
                    shutil.copyfileobj(r, o)
            except Exception as e:
                log(f"  {pkg}: خطأ {e}")
                continue
        log(f"  [{len(out)+1}/{n}] نظيف {pkg}")
        out.append(("clean", path, sha, "F-Droid"))
    return out


def get_dir(folder):
    out = []
    for root, _, files in os.walk(folder):
        for f in files:
            if f.lower().endswith((".apk", ".apks", ".xapk")):
                out.append(("clean", os.path.join(root, f), "", "local"))
    return out


DIAG = re.compile(r"تعذّر|تالف|مشفّر|حماية|packer|Jiagu|ملفات الكود|النوع:|الصلاحيات \(|⚠|كود مضاف|مكتبة غير معروفة|ملاحظة|كود مُعمّى")
RISK = re.compile(r"درجة الخطر: (\d+)/100")
MOD = re.compile(r"درجة التعديل: (\d+)/100")


def diag(text):
    """ملخص قصير علاش المحرك عطا هاد النتيجة: باش نفهمو الأخطاء."""
    lines = [l.strip() for l in text.splitlines() if DIAG.search(l)]
    mods = text.split("🔧 علامات تعديل", 1)[1].split("\n\n", 1)[0].splitlines()[1:6] if "🔧 علامات تعديل" in text else []
    return [l[:160] for l in lines[:25]] + ["MOD " + m.strip()[:160] for m in mods if m.strip()]


def scan(cli, path, timeout, java):
    t0 = time.time()
    try:
        p = subprocess.run([java, "-Xmx1g", "-jar", cli, path, "--no-reputation"],
                           capture_output=True, timeout=timeout)
        text = p.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return None, None, [], "timeout", time.time() - t0, []
    m = RISK.search(text)
    if not m:
        err = [l for l in p.stderr.decode("utf-8", "replace").splitlines() if "خطأ" in l or "Exception" in l or "Error" in l]
        return None, None, [], (err[0] if err else "no result")[:200], time.time() - t0, []
    mod = MOD.search(text)
    dangers = []
    if "⛔ علامات خطر:" in text:
        block = text.split("⛔ علامات خطر:", 1)[1].split("\n\n", 1)[0]
        dangers = [l.strip() for l in block.splitlines() if l.strip().startswith("[")][:4]
    return int(m.group(1)), int(mod.group(1)) if mod else 0, dangers, "", time.time() - t0, diag(text)


def pct(a, b):
    return f"{100.0 * a / b:.1f}%" if b else "-"


def main():
    ap = argparse.ArgumentParser(description="قياس دقة ApkSentry على فيروسات حقيقية وتطبيقات نظيفة")
    ap.add_argument("--cli", required=True, help="apksentry-cli.jar")
    ap.add_argument("--malware", type=int, default=300, help="عدد الفيروسات من MalwareBazaar (حتى 1000)")
    ap.add_argument("--fdroid", type=int, default=0, help="عدد التطبيقات النظيفة من F-Droid")
    ap.add_argument("--clean-dir", help="مجلد فيه تطبيقات نظيفة موثوقة (من Play مثلاً)")
    ap.add_argument("--malware-dir", help="مجلد فيه فيروسات عندك من قبل (بلا تحميل)")
    ap.add_argument("--out", default="bench_out")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--keep", action="store_true", help="ما تمسحش الفيروسات من بعد الفحص")
    ap.add_argument("--java", default="java")
    ap.add_argument("--offset", type=int, default=0, help="نتخطاو أول N عينة ف كل عائلة (باش نجرّبو على عينات جديدة)")
    ap.add_argument("--seed", type=int, default=2)
    ap.add_argument("--sha-list", help="ملف فيه لائحة sha256 (باش نعاودو نفس العينات ونقارنو قبل/بعد)")
    a = ap.parse_args()

    os.makedirs(a.out, exist_ok=True)
    mal_dir = os.path.join(a.out, "malware_samples")
    items = []
    if a.malware_dir:
        items += [("malware", p, os.path.basename(p)[:64], "local") for _, p, _, _ in get_dir_any(a.malware_dir)]
    elif a.malware > 0:
        key = os.environ.get("MB_API_KEY", "").strip()
        if not key:
            raise SystemExit("حط المفتاح ف MB_API_KEY (ما تكتبوش ف السكريبت)")
        log(f"تحميل {a.malware} فيروس من MalwareBazaar...")
        shas = None
        if a.sha_list and os.path.exists(a.sha_list):
            shas = [l.strip().split()[0] for l in open(a.sha_list) if l.strip() and not l.startswith("#")]
            log(f"نفس العينات ديال {a.sha_list}: {len(shas)}")
        items += get_malware(key, a.malware, mal_dir, shas, a.offset, a.seed)
    if a.fdroid > 0:
        items += get_fdroid(a.fdroid, os.path.join(a.out, "clean_fdroid"), skip=a.offset * 16)
    if a.clean_dir:
        items += get_dir(a.clean_dir)
    if not items:
        raise SystemExit("ما كاين والو نفحصو")

    rows = []
    for i, (kind, path, sha, fam) in enumerate(items):
        risk, mod, dangers, err, sec, dg = scan(a.cli, path, a.timeout, a.java)
        tag = "خطأ" if risk is None else f"{risk}/100"
        log(f"[{i+1}/{len(items)}] {kind:7} {fam[:20]:20} {tag}  ({sec:.1f}s)")
        if kind == "malware":
            print(f"SAMPLE {sha} {fam}", flush=True)
        if risk is None:
            print(f"ERROR {kind} {sha or os.path.basename(path)} {err}", flush=True)
        elif (kind == "malware" and risk < MAIN_T) or (kind == "clean" and risk >= MAIN_T):
            print(f"DIAG {kind} {fam} {sha or os.path.basename(path)} risk={risk} mod={mod}", flush=True)
            for l in dangers + dg:
                print(f"  | {l}", flush=True)
        rows.append({"kind": kind, "family": fam, "sha256": sha, "file": os.path.basename(path),
                     "risk": "" if risk is None else risk, "mod": "" if mod is None else mod,
                     "error": err, "seconds": f"{sec:.1f}", "top_findings": " | ".join(dangers)})

    with open(os.path.join(a.out, "results.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    notapk = [r for r in rows if "ليس APK" in r["error"]]
    ok = [r for r in rows if r["risk"] != ""]
    mal = [r for r in ok if r["kind"] == "malware"]
    cln = [r for r in ok if r["kind"] == "clean"]
    errs = [r for r in rows if r["risk"] == "" and r not in notapk]
    L = ["# ApkSentry benchmark", "",
         f"- فيروسات مفحوصة: {len(mal)}", f"- تطبيقات نظيفة مفحوصة: {len(cln)}",
         f"- ملفات ماشي APK (مستثناة): {len(notapk)}",
         f"- أخطاء/وقت زائد: {len(errs)}",
         "- الفحص بلا قواعد البيانات (المحرك بوحدو)", "",
         "| الحد | فيروسات تشدّو (الكشف) | نظيفة تحسبو غلط (إنذار كاذب) |", "|---|---|---|"]
    for t in THRESHOLDS:
        L.append(f"| خطر ≥ {t} | {pct(sum(r['risk'] >= t for r in mal), len(mal))} "
                 f"| {pct(sum(r['risk'] >= t for r in cln), len(cln))} |")
    fams = defaultdict(list)
    for r in mal:
        fams[r["family"]].append(r["risk"])
    L += ["", f"## حسب العائلة (الحد {MAIN_T})", "", "| العائلة | العدد | تشدّو | متوسط الخطر |", "|---|---|---|---|"]
    for fam, rs in sorted(fams.items(), key=lambda x: -len(x[1])):
        L.append(f"| {fam} | {len(rs)} | {pct(sum(x >= MAIN_T for x in rs), len(rs))} | {sum(rs) / len(rs):.0f} |")
    miss = sorted([r for r in mal if r["risk"] < MAIN_T], key=lambda r: r["risk"])
    L += ["", f"## فيروسات فاتتنا ({len(miss)})", ""]
    for r in miss[:60]:
        L.append(f"- {r['family']} `{r['sha256'][:16]}` خطر {r['risk']}: {r['top_findings'] or 'والو'}")
    fp = sorted([r for r in cln if r["risk"] >= MAIN_T], key=lambda r: -r["risk"])
    L += ["", f"## تطبيقات نظيفة تحسبات غلط ({len(fp)})", ""]
    for r in fp[:60]:
        L.append(f"- {r['file']} خطر {r['risk']}: {r['top_findings']}")
    if errs:
        L += ["", "## أخطاء", ""] + [f"- {r['kind']} {r['file'][:40]}: {r['error']}" for r in errs[:30]]
    with open(os.path.join(a.out, "report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")

    if not a.keep and os.path.isdir(mal_dir):
        shutil.rmtree(mal_dir, ignore_errors=True)
    log(f"\nالتقرير: {os.path.join(a.out, 'report.md')}")
    print("\n".join(L[:12]))


def get_dir_any(folder):
    out = []
    for root, _, files in os.walk(folder):
        for f in files:
            out.append(("malware", os.path.join(root, f), "", "local"))
    return out


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
يبني لائحة "الحزمة -> بصمة التوقيع" لكل تطبيقات F-Droid.
F-Droid كيبني التطبيقات من الكود المصدري ديالها ويراجعها، فالنسخة اللي موقّعة بنفس التوقيع
هي نسخة موثوقة. التطبيق المعدّل (حتى بحرف واحد) كيتوقّع بمفتاح آخر، فما كيطابقش.

الاستعمال: python3 tools/fdroid_signers.py core/src/main/resources/reputation/fdroid-signers.tsv
"""
import json
import sys
import time
import urllib.request

URL = "https://f-droid.org/repo/index-v2.json"


def signers_of(version):
    m = version.get("manifest") or {}
    s = m.get("signer") or {}
    v = s.get("sha256") or []
    return [v] if isinstance(v, str) else list(v)


def main(out):
    req = urllib.request.Request(URL, headers={"User-Agent": "ApkSentry-reputation/1.0"})
    with urllib.request.urlopen(req, timeout=600) as r:
        idx = json.load(r)
    rows = []
    for pkg, p in sorted(idx.get("packages", {}).items()):
        fps = set()
        for v in (p.get("versions") or {}).values():
            for fp in signers_of(v):
                fp = fp.strip().lower()
                if len(fp) == 64 and all(c in "0123456789abcdef" for c in fp):
                    fps.add(fp)
        if fps:
            rows.append(f"{pkg}\t{','.join(sorted(fps))}")
    if len(rows) < 1000:
        raise SystemExit(f"عدد قليل بزاف ({len(rows)}): شكل الفهرس تبدّل؟")
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"# F-Droid signers, {len(rows)} apps, {time.strftime('%Y-%m-%d')}, source: {URL}\n")
        f.write("\n".join(rows) + "\n")
    print(f"{len(rows)} تطبيق")


if __name__ == "__main__":
    main(sys.argv[1])

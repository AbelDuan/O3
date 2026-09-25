#!/usr/bin/env python3
"""按关键词查 NVD，筛出「本机 6.18.21 仍在受影响区间」的内核 CVE，输出紧凑表。"""
import json, re, time, urllib.request, urllib.parse, sys

DEV = (6, 18, 21)
KEYS = ["escalation", "binder", "ashmem", "userfaultfd", "vsock", "futex",
        "keyring", "use-after-free", "out-of-bounds write", "packet socket"]
START = "2026-06-01T00:00:00.000"
END   = "2026-09-24T00:00:00.000"

def fetch(kw):
    q = urllib.parse.urlencode({
        "keywordSearch": kw, "pubStartDate": START, "pubEndDate": END,
        "resultsPerPage": 100})
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + q
    req = urllib.request.Request(url, headers={"User-Agent": "cve-scan/1.0"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.load(r)

def parse_ver(s):
    m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", s or "")
    return tuple(int(x) for x in m.groups(default="0")) if m else None

def kernel_618_fix(cve):
    """返回该 CVE 在 6.18.x 上的修复版本上界（即 < 它才受影响）。"""
    best = None
    for aff in cve.get("affected", []):
        for ad in aff.get("affectedData", []):
            if ad.get("product") != "Linux":
                continue
            for v in ad.get("versions", []):
                s = v.get("version", "")
                if s.startswith("6.18") and v.get("status") == "unaffected":
                    p = parse_ver(s)
                    if p and (best is None or p > best):
                        best = p
    for node in cve.get("configurations", []):
        for n in node.get("nodes", []):
            for m in n.get("cpeMatch", []):
                cand = m.get("versionEndExcluding", "")
                if cand.startswith("6.18"):
                    p = parse_ver(cand)
                    if p and (best is None or p > best):
                        best = p
    return best

def cvss(cve):
    for k in ("cvssMetricV31", "cvssMetricV40"):
        for m in cve.get("metrics", {}).get(k, []):
            d = m.get("cvssData", {})
            return d.get("baseScore"), d.get("baseSeverity") or d.get("baseScore")
    return None, None

def files(cve):
    out = set()
    for aff in cve.get("affected", []):
        for ad in aff.get("affectedData", []):
            for f in ad.get("programFiles", []) or []:
                out.add(f)
    return sorted(out)[:3]

seen = {}
for kw in KEYS:
    try:
        data = fetch(kw)
    except Exception as e:
        print(f"[warn] {kw}: {e}", file=sys.stderr); time.sleep(6); continue
    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        if cve["id"] in seen:
            continue
        fix = kernel_618_fix(cve)
        if not fix or fix <= DEV:
            continue          # 本机已修 / 无 6.18 信息
        score, sev = cvss(cve)
        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
        seen[cve["id"]] = dict(id=cve["id"], pub=cve["published"][:10], fix=".".join(map(str, fix)),
                               score=score, files=files(cve),
                               desc=re.sub(r"\s+", " ", desc)[:230])
    time.sleep(6)

for c in sorted(seen.values(), key=lambda x: x["pub"], reverse=True):
    print(f'{c["id"]}  pub={c["pub"]}  fix=6.18.{c["fix"].split(".")[2]}  cvss={c["score"]}')
    print(f'   files: {", ".join(c["files"])}')
    print(f'   {c["desc"]}')
print(f'\n== 候选 {len(seen)} 条（本机 6.18.21 落在受影响区间）')

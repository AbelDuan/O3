#!/usr/bin/env bash
# Re-sync the sanitized jailbreak docs/tools/tests to github.com/AbelDuan/O3
#
#   GH_TOKEN=<pat> bash sync-to-github.sh ["commit message"]
#
# Deliberately EXCLUDES device dumps (bugreport/pstore/APKs): GB-sized and full of
# personal device data. LAN addresses are sanitized to <LAN-IP> on the way out.
set -euo pipefail

SRC=/root/projects
DST=/root/projects/O3-sync
: "${GH_TOKEN:?set GH_TOKEN to a GitHub PAT with repo scope}"
MSG=${1:-"sync: update jailbreak research notes"}

mkdir -p "$DST"/{docs,tools,tests,exploit-src}

sanitize() { sed -E 's/192\.168\.[0-9]+\.[0-9]+/<LAN-IP>/g; s/10\.[0-9]+\.[0-9]+\.[0-9]+/<LAN-IP>/g'; }

# docs
sanitize < "$SRC/cve-hunt/CVE-18.0-report.md" > "$DST/docs/CVE-18.0-report.md"

# analysis + forensic tooling
for f in analyze-log.py nvd_scan.py refine.py hold-auth.py pair-by-code.sh \
         pair-connect.sh pull-blackbox-now.sh watch-run2.sh grab-run2.sh start-holder.sh; do
  [ -f "$SRC/cve-hunt/$f" ] && sanitize < "$SRC/cve-hunt/$f" > "$DST/tools/$f"
done

# TDD guards
for f in test_gate_buffer.py test_ksud_official.py test_pipe_count.py test_repeats_env.py; do
  [ -f "$SRC/cve-hunt/$f" ] && cp "$SRC/cve-hunt/$f" "$DST/tests/$f"
done

# upstream PoC source (already public upstream; source only, no binaries)
cp -r "$SRC/cve64560-src/xiaomi15-dada-cve-2026-64560-main/src/." "$DST/exploit-src/src/" 2>/dev/null || true
cp "$SRC/cve64560-src/profile_lhasa18_draft.json" "$DST/exploit-src/" 2>/dev/null || true

# never commit caches
find "$DST" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true

cd "$DST"
echo "=== secret scan (must all be 0) ==="
for pat in "github_pat_" "080808" "02040860499C3540" "192\.168\."; do
  printf "  %-20s %s\n" "$pat" "$(grep -ral "$pat" . --exclude-dir=.git 2>/dev/null | wc -l)"
done

git add -A
if git diff --cached --quiet; then
  echo "nothing to commit"; exit 0
fi
git -c user.email="agent@localhost" -c user.name="DSH Agent" commit -q -m "$MSG"
git push "https://x-access-token:${GH_TOKEN}@github.com/AbelDuan/O3.git" main
echo "pushed: $(git log --oneline -1)"

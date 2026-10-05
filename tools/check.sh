#!/usr/bin/env bash
# Checks to run before a release.
set -uo pipefail
cd "$(dirname "$0")/.."
fail=0
echo "== Python syntax =="
python3 -m py_compile server/*.py && echo "  OK" || fail=1
echo "== JavaScript syntax =="
python3 - <<'PY' > /tmp/pp_all.js
import re
h = open('client/client.html', encoding='utf-8').read()
print("\n".join(m.group(1) for m in re.finditer(r'<script>(.*?)</script>', h, re.S)))
PY
if command -v node >/dev/null; then node --check /tmp/pp_all.js && echo "  OK" || fail=1; else echo "  (node not installed, skipped)"; fi
echo "== Language files =="
python3 - <<'PY' || fail=1
import glob, sys
def load(p):
    d = {}
    for ln in open(p, encoding='utf-8'):
        ln = ln.strip()
        if ln and not ln.startswith('#') and ' = ' in ln:
            k, v = ln.split(' = ', 1); d[k.strip()] = v.strip()
    return d
en = load('lang/en.lang'); bad = False
for f in sorted(glob.glob('lang/*.lang')):
    d = load(f); miss = [k for k in en if k not in d]
    print(f'  {f:16s} {len(d):4d} keys  ' + ('OK' if not miss else f'MISSING {len(miss)}'))
    bad = bad or bool(miss)
sys.exit(1 if bad else 0)
PY
[ $fail -eq 0 ] && echo "ALL CHECKS PASSED" || echo "CHECKS FAILED"
exit $fail

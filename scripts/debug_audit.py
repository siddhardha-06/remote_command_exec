import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from common.audit import AUDIT_LOG, CHAIN_SECRET

lines = AUDIT_LOG.read_text(encoding='utf-8').splitlines()
import hmac, hashlib
failures = []
for idx, line in enumerate(lines, 1):
    line = line.strip()
    if not line:
        continue
    entry = json.loads(line)
    stored = entry.pop('chain_hash','')
    prev = entry.get('prev_hash','')
    entry_json = json.dumps(entry, separators=(',',':'))
    a = hmac.new(CHAIN_SECRET, (prev+entry_json).encode(), hashlib.sha256).hexdigest()
    b = hmac.new(CHAIN_SECRET, prev.encode()+entry_json.encode(), hashlib.sha256).hexdigest()
    ok = stored in (a,b)
    if not ok:
        failures.append((idx, stored, a, b, prev, entry_json))

print('total_lines=', len(lines))
print('failures=', len(failures))
if failures:
    idx, stored, a, b, prev, entry_json = failures[0]
    print('first_failure_line=', idx)
    print('stored=', stored)
    print('expected_a=', a)
    print('expected_b=', b)
    print('prev=', prev)
    print('entry=', entry_json)

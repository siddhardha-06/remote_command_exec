import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from common.audit import verify_log_integrity, AUDIT_LOG
ok, errors = verify_log_integrity(AUDIT_LOG)
print('ok=', ok)
print('errors_count=', len(errors))
for i, e in enumerate(errors[:20], 1):
    print(f'{i}: {e}')

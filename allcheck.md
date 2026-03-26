touch scripts/__init__.py
ls -la scripts/
python3 -c "
import sys; sys.path.insert(0,'.')
from scripts.fetcher import fetch_app
from scripts.unpacker import unpack_app
from scripts.hunter import hunt_app
from scripts.reviewer import review_top_findings
from scripts.reporter import generate_report
print('✅ All imports OK')
"

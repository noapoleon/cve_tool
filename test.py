import json
from typing import List, Set, Optional
from utils import json_utils

d = {}

d.setdefault("vendor_fix", set()).update({"1", "2", "3"})
d.setdefault("workaround", set()).update({"4", "5", "3"})
d.setdefault("none_available", set()).update({"4", "5", "3"})

if d.get("workaround"):
    d["workaround"] -= d.get("vendor_fix", set())
    d["workaround"] -= d.get("no_fix_planned", set())
    d["workaround"] -= d.get("none_available", set())

print(d)

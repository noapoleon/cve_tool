import copy
from pathlib import Path
import json
from tqdm import tqdm
from typing import Optional, List, Set

t = {
    "vulnerabilities": [
        {
            "product_status": {
                "fixed": [
                    "7Server-ELS:webkitgtk4-0:2.48.3-2.el7_9.s390x",
                    "7Server-ELS:webkitgtk4-0:2.48.3-2.el7_9.src",
                    "7Server-ELS:webkitgtk4-0:2.48.3-2.el7_9.x86_64",
                    "7Server-ELS:webkitgtk4-debuginfo-0:2.48.3-2.el7_9.s390x",
                    "7Server-ELS:webkitgtk4-debuginfo-0:2.48.3-2.el7_9.x86_64",
                    "7Server-ELS:webkitgtk4-devel-0:2.48.3-2.el7_9.s390x",
                    "7Server-ELS:webkitgtk4-devel-0:2.48.3-2.el7_9.x86_64",
                    "7Server-ELS:webkitgtk4-doc-0:2.48.3-2.el7_9.noarch",
                    "7Server-ELS:webkitgtk4-jsc-0:2.48.3-2.el7_9.s390x",
                ],
                "not_fixed": [
                    "7Server-ELS:webkitgtk4-devel-0:2.48.3-2.el7_9.s390x",
                    "7Server-ELS:webkitgtk4-doc-0:2.48.3-2.el7_9.noarch",
                    "7Server-ELS:webkitgtk4-jsc-0:2.48.3-2.el7_9.s390x"
                ],
            }
        }
    ]
}

ins = [
    "accountsservice-0.6.55-4.el8",
    "accountsservice-libs-0.6.55-4.el8",
    "file-5.33-26.el8",
    "filesystem-3.8-6.el8",
    "gd-2.2.5-7.el8",
    "gdm-40.0-27.el8",
    "webkitgtk4-devel-2.48.3-2.el7_9",
    "webkitgtk4-doc-2.48.3-2.el7_9",
    "webkitgtk4-jsc-2.48.3-2.el7_9"
]

def match_normalize_pid(pid: str, match_set: Set[str]):
    parts = pid.split(":", 2)
    if len(parts) < 3:
        return None
    _, ne, vra = parts
    norm = f"{ne.rsplit('-', 1)[0]}-{vra.rsplit('.', 1)[0]}"
    return norm if norm in match_set else None

def get_vex_normed_pids(data: dict, match: List[str]) -> List[str] | None:
    product_status = data.get("vulnerabilities", [])[0].get("product_status") #unsafe
    normed = []
    match_set = set(match)
    for pids in product_status.values():
        for pid in pids:
            norm = match_normalize_pid(pid, match_set)
            if norm is not None:
                normed.append(norm)
    return normed

# normed_pids = get_vex_normed_pids(t, ins)
# print("normed:")
# if normed_pids:
#     for pid in normed_pids:
#         print(pid)

l1 = {"bonjour": "salut", "ok": "non"}

def fun(lll):
    return {"wow": "cool"}

print(l1)
l1 = fun(l1)
print(l1)

import json
from typing import List, Set, Optional
# d = {
#     "1": [0],
#     "2": [0],
#     "3": [0, 1, 3],
#     "4": [0],
# }
#
# t = {1, 5}
#
#
# for key, val in d.items():
#     if key == "3":
#         u = list(set(d[key]).union(t))
#         d[key] = u
#     print(f"{key}: {val} -> type: {type(val)}")
#
#
# with open("./test.out", "w", encoding="utf8") as f:
#     json.dump(d, f, indent=2)

# thing_old = {}
thing1 = {
    "rhel_versions": ["4", "10"],
    "product_status": {
        "fixed": ["a", "b", "c"],
        "known_not_affected": ["x", "y", "z"]
    }
}
thing2 = {
    "rhel_versions": set(),
    "product_status": {
        "fixed": set()
    }
}
# thing_new = {
#     "rhel_versions": {"8"},
#     "product_status": {
#         "fixed": {"d", "e", "f"},
#         "known_affected": {"1", "2", "3"}
#     }
# }
def _norm_for_dump(obj):
    if isinstance(obj, set):
        return list(obj)
    if isinstance(obj, dict):
        return {k: _norm_for_dump(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_norm_for_dump(v) for v in obj]
    return obj
def truc(thing_old, thing_new) -> dict:

    old_vers = set(thing_old.get("rhel_versions", set()))
    thing_new["rhel_versions"] = old_vers | thing_new["rhel_versions"]
    for status, old_set in thing_old.get("product_status", {}).items():
        if status in thing_new["product_status"]:
            thing_new["product_status"][status] = thing_new["product_status"][status] | set(old_set)
        else:
            thing_new["product_status"][status] = set(old_set)
    return thing_new

truc(thing1, thing2)
thing2 = _norm_for_dump(thing2)
print(json.dumps(thing2, indent=2))

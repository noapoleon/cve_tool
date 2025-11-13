import json
from typing import List, Set, Optional

d1 = {

    "product_status": {
        "fixed": ["1", "2", "3"],
        "known_affected": ["x", "y", "z", "a"],
        "known_not_affected": ["a", "b", "c"],
    }
}

s = {
    product
    for status in d1.get("product_status", {}).values()
    for product in status
}
print(s)

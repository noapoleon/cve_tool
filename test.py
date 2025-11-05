import copy
from pathlib import Path
import json

l = {
    "key1": [],
    "key2": [],
    "key3": [],
    "key4": [],
}

ll = []

for k in l:
    ll.append([f"{k}_truc", "ok"])
print(ll)

print("coucou")
print(ll[-1])

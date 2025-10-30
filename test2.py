#!/usr/bin/env python

from typing import List, Tuple, Callable, Optional

def test(prompt: Optional[str] = "Downloading"):
    print(f"hello {prompt}")
    if prompt:
        print("if prompt")
    if prompt is None:
        print("if prompt is None")

print("test 1:")
test()
print("test 2:")
test("coucou")
print("test 3:")
test(None)
print("test 4:")
test("")

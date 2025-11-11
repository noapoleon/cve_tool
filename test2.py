from argparse import ArgumentParser
from pathlib import Path

a = {i for i in range(1, 100)}
b = {i for i in range(80, 300)}

c = a.intersection(b)
print(c)

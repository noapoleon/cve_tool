from argparse import ArgumentParser
from pathlib import Path

def test():
    try:
        print("try1")
    except:
        print("except")
    finally:
        print("finally")
print(test())


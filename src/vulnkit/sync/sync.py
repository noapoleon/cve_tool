from vulnkit import config
# import vulnkit
from pathlib import Path

def run():
    """Syncing data requested from sources in config"""
    # print(f"Syncing in directory: {vulnkit.config.data_dir}")
    # print(f"Sources: {vulnkit.config.sources.keys()}")
    print(f"Syncing in directory: {config.data_dir}")
    print(f"Sources: {config.sources.keys()}")


# def make_dirs():


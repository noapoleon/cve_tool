from vulnkit.config import get_config, other_config

def run():
    """Syncing data requested from sources in config"""

    get_config()
    other_config()

    print("syncing... (not really)")

from pathlib import Path

# TODO: Make singleton in __init__.py (of vulnkit or config idk)
_config: dict = {}

# def init():
# def set_default():
    # pass

def load(
        config: Optional[Path|dict] = None # bad just do path or str
):
    global _config

    if isinstance(config, Path):
        print("config: loading file...")
    elif isinstance(config, dict):
        print("config: assigning from dict...")
        _config = config
    elif config is None:
        print("config: setting up default...")
    else:
        print("config: unsupported type")


def get():
    return _config

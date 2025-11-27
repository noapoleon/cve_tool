from .configuration import Config
config = Config()

from . import sync

__all__ = ["config", "sync"]

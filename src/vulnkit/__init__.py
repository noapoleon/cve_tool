from .configuration import Config
config = Config()

from . import sources
from . import sync

__all__ = [
    "config",
    "sources",
    "sync",
]

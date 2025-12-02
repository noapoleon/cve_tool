from abc import ABC, abstractmethod

class Source(ABC):
    """Interface for vulnerability data providers"""

    @abstractmethod
    def feeds(self) -> set[str]:
        """Return a list of supported data types provided by the source."""
        pass


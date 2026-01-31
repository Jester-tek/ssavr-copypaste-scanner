from abc import ABC, abstractmethod

class BaseSite(ABC):
    def __init__(self, tor_manager):
        self.tor_manager = tor_manager
        self._session = None

    def reset_session(self):
        """Force creation of a new session for this client."""
        if self._session:
            self._session.close()
        # Create session IMMEDIATELY (not lazily) to avoid race conditions
        self._session = self.tor_manager.get_new_session()

    @property
    def session(self):
        if self._session is None:
            self._session = self.tor_manager.get_new_session()
        return self._session

    @abstractmethod
    def read(self):
        """Read content from the site. Returns string or None on failure."""
        pass

    @abstractmethod
    def write(self, content):
        """Write content to the site. Returns True/False."""
        pass
    
    @abstractmethod
    def get_name(self):
        pass

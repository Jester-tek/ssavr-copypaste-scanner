from abc import ABC, abstractmethod

class BaseSite(ABC):
    def __init__(self, session_factory):
        """
        session_factory: a callable that returns a fully configured requests.Session
        (e.g., tor_manager.get_new_session, or a lambda returning a proxy-configured session)
        """
        self.session_factory = session_factory
        self._session = None

    def reset_session(self):
        """Force creation of a new session for this client."""
        if self._session:
            self._session.close()
        # Create session IMMEDIATELY (not lazily) to avoid race conditions
        self._session = self.session_factory()

    @property
    def session(self):
        if self._session is None:
            self._session = self.session_factory()
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

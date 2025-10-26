from typing import Any, Dict, Optional


class SigmaServiceError(Exception):
    """Domain specific exception for sigma service related failures."""

    def __init__(self, message: str, *, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        """Return a serialisable representation of the error."""

        payload: Dict[str, Any] = {"message": self.message}
        if self.details:
            payload["details"] = self.details
        return payload

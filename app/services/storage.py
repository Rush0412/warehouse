from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Iterable, Optional


class SigmaRuleRepository(ABC):
    """Abstract repository used to persist sigma rules for future extensions."""

    @abstractmethod
    def save(self, rule_id: str, payload: Dict[str, Any]) -> None:
        """Persist a sigma rule payload."""

    @abstractmethod
    def load(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Load a sigma rule payload if present."""

    @abstractmethod
    def list(self) -> Iterable[Dict[str, Any]]:
        """Enumerate stored sigma rules."""


class InMemorySigmaRuleRepository(SigmaRuleRepository):
    """Non-persistent in-memory implementation suitable for testing."""

    def __init__(self) -> None:
        self._rules: Dict[str, Dict[str, Any]] = {}

    def save(self, rule_id: str, payload: Dict[str, Any]) -> None:
        self._rules[rule_id] = payload

    def load(self, rule_id: str) -> Optional[Dict[str, Any]]:
        return self._rules.get(rule_id)

    def list(self) -> Iterable[Dict[str, Any]]:
        return self._rules.values()

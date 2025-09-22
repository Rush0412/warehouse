from __future__ import annotations

from io import StringIO
from typing import Any, Dict, List, Optional, Union

import yaml

try:
    from sigma.collection import SigmaCollection
    from sigma.exceptions import SigmaError
except ImportError:  # pragma: no cover - pysigma should be installed in production
    SigmaCollection = None  # type: ignore[assignment]
    SigmaError = Exception  # type: ignore[assignment]

from app.models.requests import SigmaRulePayload
from app.utils.errors import SigmaServiceError


ParsedRule = Union[Dict[str, Any], List[Dict[str, Any]]]


class SigmaParserService:
    """Service responsible for parsing sigma rules via pysigma."""

    def __init__(self, *, pipeline: Optional[Any] = None) -> None:
        if SigmaCollection is None:
            raise SigmaServiceError(
                "pysigma is required to parse sigma rules. Ensure the dependency is installed."
            )
        self.pipeline = pipeline

    def parse_yaml(self, rule_yaml: str) -> ParsedRule:
        """Parse YAML sigma rule content and return a structured representation."""

        collection = self._load_collection(rule_yaml)
        # We return the YAML representation enriched with pipeline results if desired.
        parsed_documents: List[Any] = list(yaml.safe_load_all(rule_yaml))
        if not parsed_documents:
            raise SigmaServiceError("The provided YAML content does not contain any documents.")
        if len(parsed_documents) == 1:
            document = parsed_documents[0]
            if isinstance(document, dict):
                return document
            raise SigmaServiceError(
                "Parsed YAML document must resolve to a mapping that represents a sigma rule."
            )
        # Multiple rules are returned as a list to support batch operations.
        return [doc for doc in parsed_documents if isinstance(doc, dict)]

    def parse_payload(self, payload: SigmaRulePayload) -> ParsedRule:
        """Parse a sigma rule payload that may contain YAML or structured data."""

        if payload.rule_yaml:
            return self.parse_yaml(payload.rule_yaml)
        if payload.parsed_rule:
            # Re-serialise structured data to YAML, then parse again via pysigma for validation.
            yaml_buffer = yaml.safe_dump(payload.parsed_rule)
            return self.parse_yaml(yaml_buffer)
        raise SigmaServiceError("Either YAML or parsed sigma data must be provided.")

    def to_collection(self, payload: SigmaRulePayload) -> "SigmaCollection":
        """Create a SigmaCollection instance from the provided payload."""

        if payload.rule_yaml:
            return self._load_collection(payload.rule_yaml)
        if payload.parsed_rule:
            yaml_buffer = yaml.safe_dump(payload.parsed_rule)
            return self._load_collection(yaml_buffer)
        raise SigmaServiceError("Unable to materialise sigma collection from empty payload.")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _load_collection(self, rule_yaml: str) -> "SigmaCollection":
        try:
            if hasattr(SigmaCollection, "from_yaml"):
                return SigmaCollection.from_yaml(StringIO(rule_yaml), pipeline=self.pipeline)
            if hasattr(SigmaCollection, "load"):
                return SigmaCollection.load(StringIO(rule_yaml), pipeline=self.pipeline)
        except SigmaError as exc:  # pragma: no cover - depends on pysigma runtime behaviour
            raise SigmaServiceError("Failed to parse sigma rule.", details={"error": str(exc)}) from exc
        except TypeError:
            # Some pysigma versions accept raw strings, others require file-like objects.
            try:
                return SigmaCollection.from_yaml(rule_yaml, pipeline=self.pipeline)  # type: ignore[arg-type]
            except SigmaError as exc:  # pragma: no cover
                raise SigmaServiceError(
                    "Failed to parse sigma rule.", details={"error": str(exc)}
                ) from exc
        raise SigmaServiceError(
            "Unsupported pysigma version: unable to locate a parser entry point for YAML content."
        )

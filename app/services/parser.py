from __future__ import annotations

from io import StringIO
import inspect
from typing import Any, Dict, List, Optional, Type, Union

import yaml

try:
    from sigma.collection import SigmaCollection  # type: ignore
except ImportError:  # pragma: no cover - pysigma should be installed in production
    SigmaCollection = None  # type: ignore[assignment]

try:
    from sigma.exceptions import SigmaError
except ImportError:  # pragma: no cover - pysigma should be installed in production
    SigmaError = Exception  # type: ignore[assignment]

try:
    from sigma.rule import SigmaRule  # type: ignore
except ImportError:  # pragma: no cover
    SigmaRule = None  # type: ignore[assignment]

try:
    from sigma.correlations import SigmaCorrelationRule  # type: ignore
except ImportError:  # pragma: no cover
    SigmaCorrelationRule = None  # type: ignore[assignment]

try:
    from sigma.parser.rule import SigmaRuleParser  # type: ignore
except ImportError:  # pragma: no cover
    SigmaRuleParser = None  # type: ignore[assignment]

try:
    from sigma.validation import SigmaValidator  # type: ignore
except ImportError:  # pragma: no cover
    SigmaValidator = None  # type: ignore[assignment]

try:
    from sigma.validators.base import SigmaRuleValidator  # type: ignore
except ImportError:  # pragma: no cover
    SigmaRuleValidator = object  # type: ignore[assignment]

try:
    from sigma.validators.core import validators as CORE_VALIDATORS  # type: ignore
except ImportError:  # pragma: no cover
    CORE_VALIDATORS = {}  # type: ignore[assignment]

from app.models.requests import SigmaRulePayload
from app.utils.errors import SigmaServiceError



DEFAULT_CORRELATION_TIMESPAN = "5m"
DEFAULT_CORRELATION_THRESHOLD = 1
METADATA_TIMESPAN_KEY = "aggregation_timespan"
METADATA_THRESHOLD_KEY = "aggregation_threshold"
METADATA_DIMENSIONS_KEY = "dimensions"
METADATA_EVENT_TIME_KEY = "aggregation_event_time_field"
METADATA_PATTERN_ALIAS_KEY = "aggregation_pattern_alias"
METADATA_CUSTOM_TAGS_KEY = "custom_tags"
CORRELATION_TYPE_ALIASES = {
    "ordered_temporal": "temporal_ordered",
    "temporal_unordered": "temporal",
}
ALLOWED_TAG_NAMESPACES = frozenset(
    {
        "attack",
        "car",
        "cve",
        "d3fend",
        "detection",
        "stp",
        "tlp",
    }
)

if SigmaRule is not None and SigmaCorrelationRule is not None:
    SigmaParsedRule = Union[SigmaRule, SigmaCorrelationRule]
elif SigmaRule is not None:
    SigmaParsedRule = SigmaRule
else:
    SigmaParsedRule = Any


if SigmaRule is not None and SigmaCorrelationRule is not None:
    _RULE_INSTANCE_TYPES: tuple[type, ...] = (SigmaRule, SigmaCorrelationRule)
elif SigmaRule is not None:
    _RULE_INSTANCE_TYPES = (SigmaRule,)
else:
    _RULE_INSTANCE_TYPES = tuple()

if SigmaRuleParser is None:

    class SigmaRuleParser:
        """Fallback parser based on SigmaCollection when sigma.parser is unavailable."""

        def __init__(self, *, pipeline: Optional[Any] = None) -> None:
            self.pipeline = pipeline

        def parse(self, rule_yaml: str) -> List[SigmaParsedRule]:
            collection = self._load_collection(rule_yaml)
            if not _RULE_INSTANCE_TYPES:
                return []
            return [
                rule
                for rule in getattr(collection, "rules", [])
                if isinstance(rule, _RULE_INSTANCE_TYPES)
            ]

        def _invoke_loader(self, loader, *args):
            if self.pipeline is None:
                return loader(*args)
            try:
                parameters = getattr(inspect.signature(loader), "parameters", {})
            except (ValueError, TypeError):
                parameters = {}
            if "pipeline" in parameters:
                return loader(*args, pipeline=self.pipeline)
            if "pipelines" in parameters:
                pipelines_value = (
                    self.pipeline
                    if isinstance(self.pipeline, (list, tuple))
                    else [self.pipeline]
                )
                return loader(*args, pipelines=pipelines_value)
            return loader(*args)

        def _load_collection(self, rule_yaml: str) -> SigmaCollection:
            try:
                if hasattr(SigmaCollection, "from_yaml"):
                    return self._invoke_loader(SigmaCollection.from_yaml, StringIO(rule_yaml))
                if hasattr(SigmaCollection, "load"):
                    return self._invoke_loader(SigmaCollection.load, StringIO(rule_yaml))
            except SigmaError:
                raise
            except TypeError:
                return self._invoke_loader(SigmaCollection.from_yaml, rule_yaml)
            return self._invoke_loader(SigmaCollection.from_yaml, StringIO(rule_yaml))


ParsedRule = Union[Dict[str, Any], List[Dict[str, Any]]]


class SigmaParserService:
    """Service responsible for parsing sigma rules via pysigma."""

    def __init__(self, *, pipeline: Optional[Any] = None) -> None:
        if SigmaCollection is None or SigmaRuleParser is None:
            raise SigmaServiceError(
                "pysigma is required to parse sigma rules. Ensure the dependency is installed."
            )
        self.pipeline = pipeline
        self._rule_parser = SigmaRuleParser(pipeline=pipeline)
        self._validator_classes: tuple[Type[SigmaRuleValidator], ...] = tuple(CORE_VALIDATORS.values()) if CORE_VALIDATORS else tuple()

    def parse_rules(self, rule_yaml: str) -> List[SigmaParsedRule]:
        prepared_yaml = self._prepare_rule_yaml(rule_yaml)
        try:
            return self._rule_parser.parse(prepared_yaml)
        except yaml.YAMLError as exc:
            raise SigmaServiceError(
                "Failed to parse sigma rule: invalid YAML syntax.",
                details={"error": str(exc)},
            ) from exc
        except SigmaError as exc:
            raise SigmaServiceError(
                "Failed to parse sigma rule.", details={"error": str(exc)}
            ) from exc

    def parse_yaml(self, rule_yaml: str) -> ParsedRule:
        """Parse YAML sigma rule content and return a structured representation."""

        rules = self.parse_rules(rule_yaml)
        if not rules:
            raise SigmaServiceError("The provided YAML content does not contain any documents.")
        rule_dicts = self._rules_to_dicts(rules)
        if len(rule_dicts) == 1:
            return rule_dicts[0]
        return rule_dicts

    def parse_payload(self, payload: SigmaRulePayload) -> ParsedRule:
        """Parse a sigma rule payload that may contain YAML or structured data."""

        rules: List[SigmaParsedRule] = []
        if payload.rule_yaml:
            rules = self.parse_rules(payload.rule_yaml)
        elif payload.parsed_rule:
            yaml_buffer = yaml.safe_dump(payload.parsed_rule)
            rules = self.parse_rules(yaml_buffer)
        if not rules:
            raise SigmaServiceError("Either YAML or parsed sigma data must be provided.")
        rule_dicts = self._rules_to_dicts(rules)
        if len(rule_dicts) == 1:
            return rule_dicts[0]
        return rule_dicts

    def to_collection(self, payload: SigmaRulePayload) -> "SigmaCollection":
        """Create a SigmaCollection instance from the provided payload."""

        if payload.rule_yaml:
            prepared_yaml = self._prepare_rule_yaml(payload.rule_yaml)
            return self._load_collection(prepared_yaml)
        if payload.parsed_rule:
            yaml_buffer = yaml.safe_dump(payload.parsed_rule)
            prepared_yaml = self._prepare_rule_yaml(yaml_buffer)
            return self._load_collection(prepared_yaml)
        raise SigmaServiceError(
            "Unable to materialise sigma collection from empty payload."
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _invoke_loader(self, loader, *args):
        """Call a SigmaCollection loader with optional pipeline support."""

        if self.pipeline is None:
            return loader(*args)

        try:
            parameters = getattr(inspect.signature(loader), "parameters", {})
        except (ValueError, TypeError):
            parameters = {}

        if "pipeline" in parameters:
            return loader(*args, pipeline=self.pipeline)

        if "pipelines" in parameters:
            pipelines_value = (
                self.pipeline
                if isinstance(self.pipeline, (list, tuple))
                else [self.pipeline]
            )
            return loader(*args, pipelines=pipelines_value)

        return loader(*args)

    def _load_collection(self, rule_yaml: str) -> "SigmaCollection":
        try:
            if hasattr(SigmaCollection, "from_yaml"):
                return self._invoke_loader(
                    SigmaCollection.from_yaml, StringIO(rule_yaml)
                )
            if hasattr(SigmaCollection, "load"):
                return self._invoke_loader(SigmaCollection.load, StringIO(rule_yaml))
        except (
            SigmaError
        ) as exc:  # pragma: no cover - depends on pysigma runtime behaviour
            raise SigmaServiceError(
                "Failed to parse sigma rule.", details={"error": str(exc)}
            ) from exc
        except TypeError:
            # Some pysigma versions accept raw strings, others require file-like objects.
            try:
                return self._invoke_loader(SigmaCollection.from_yaml, rule_yaml)  # type: ignore[arg-type]
            except SigmaError as exc:  # pragma: no cover
                raise SigmaServiceError(
                    "Failed to parse sigma rule.", details={"error": str(exc)}
                ) from exc
        raise SigmaServiceError(
            "Unsupported pysigma version: unable to locate a parser entry point for YAML content."
        )

    def validate_sigma_rules(self, rules: List[SigmaParsedRule]) -> List[str]:
        if SigmaValidator is None or not self._validator_classes:
            return []
        validator = SigmaValidator(self._validator_classes)
        issues = validator.validate_rules(iter(rules))
        return [str(issue) for issue in issues]

    def _rules_to_dicts(self, rules: List[SigmaParsedRule]) -> List[Dict[str, Any]]:
        return [rule.to_dict() for rule in rules]

    def _collection_to_rule_dicts(
        self, collection: "SigmaCollection"
    ) -> List[Dict[str, Any]]:
        rule_dicts: List[Dict[str, Any]] = []
        for rule in getattr(collection, "rules", []):
            if _RULE_INSTANCE_TYPES and isinstance(rule, _RULE_INSTANCE_TYPES):
                rule_dicts.append(rule.to_dict())
        return rule_dicts

    def _prepare_rule_yaml(self, rule_yaml: str) -> str:
        try:
            documents = list(yaml.safe_load_all(rule_yaml))
        except yaml.YAMLError:
            return rule_yaml
        if not documents:
            return rule_yaml

        modified = False
        sanitized_documents: List[Any] = []
        for document in documents:
            if not isinstance(document, dict):
                sanitized_documents.append(document)
                continue

            doc_modified = False
            if self._normalise_tags(document):
                doc_modified = True
            if self._apply_correlation_defaults(document):
                doc_modified = True

            sanitized_documents.append(document)
            if doc_modified:
                modified = True

        if not modified:
            return rule_yaml

        return yaml.safe_dump_all(
            sanitized_documents,
            sort_keys=False,
            allow_unicode=True,
        )

    def _normalise_tags(self, document: Dict[str, Any]) -> bool:
        tags = document.get("tags")
        if not tags or not isinstance(tags, list):
            return False

        valid_tags: List[str] = []
        custom_tags: List[str] = []
        for tag in tags:
            if not isinstance(tag, str):
                custom_tags.append(str(tag))
                continue
            if "." not in tag:
                custom_tags.append(tag)
                continue
            namespace, _ = tag.split(".", 1)
            if namespace in ALLOWED_TAG_NAMESPACES:
                valid_tags.append(tag)
            else:
                custom_tags.append(tag)

        changed = False
        if len(valid_tags) != len(tags):
            changed = True
        if valid_tags:
            document["tags"] = valid_tags
        else:
            document.pop("tags", None)

        if custom_tags:
            metadata = document.setdefault("metadata", {})
            if isinstance(metadata, dict):
                self._extend_metadata_list(metadata, METADATA_CUSTOM_TAGS_KEY, custom_tags)
                changed = True

        return changed

    def _apply_correlation_defaults(self, document: Dict[str, Any]) -> bool:
        correlation = document.get("correlation")
        if not isinstance(correlation, dict):
            return False

        metadata = document.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}

        modified = False

        corr_type = correlation.get("type")
        if isinstance(corr_type, str):
            alias = CORRELATION_TYPE_ALIASES.get(corr_type.strip().lower())
            if alias is not None:
                correlation["type"] = alias
                modified = True

        condition_value = correlation.get("condition")
        if isinstance(condition_value, str):
            normalised = condition_value.strip().lower()
            if normalised == "all":
                rules = correlation.get("rules")
                if isinstance(rules, list):
                    threshold = len(rules) or DEFAULT_CORRELATION_THRESHOLD
                else:
                    threshold = DEFAULT_CORRELATION_THRESHOLD
                correlation["condition"] = {"gte": max(1, threshold)}
            elif normalised in {"any", "one"}:
                correlation["condition"] = {"gte": DEFAULT_CORRELATION_THRESHOLD}
            else:
                correlation.pop("condition", None)
            modified = True

        timespan_override = metadata.get(METADATA_TIMESPAN_KEY)
        if isinstance(timespan_override, str) and timespan_override:
            if correlation.get("timespan") != timespan_override:
                correlation["timespan"] = timespan_override
                modified = True
        elif not correlation.get("timespan"):
            correlation["timespan"] = DEFAULT_CORRELATION_TIMESPAN
            modified = True

        threshold_override = self._coerce_positive_int(metadata.get(METADATA_THRESHOLD_KEY))
        if threshold_override is not None:
            desired_condition = {"gte": threshold_override}
            if correlation.get("condition") != desired_condition:
                correlation["condition"] = desired_condition
                modified = True
        elif not correlation.get("condition"):
            correlation["condition"] = {"gte": DEFAULT_CORRELATION_THRESHOLD}
            modified = True

        if not correlation.get("group-by"):
            dimensions = metadata.get(METADATA_DIMENSIONS_KEY)
            if isinstance(dimensions, list) and dimensions:
                correlation["group-by"] = list(dimensions)
                modified = True

        return modified

    def _coerce_positive_int(self, value: Any) -> Optional[int]:
        if value is None or isinstance(value, bool):
            return None
        try:
            number = int(value)
        except (TypeError, ValueError):
            return None
        if number <= 0:
            return None
        return number

    def _extend_metadata_list(self, metadata: Dict[str, Any], key: str, values: List[str]) -> None:
        if not values:
            return
        existing = metadata.get(key)
        if isinstance(existing, list):
            combined = existing + values
        else:
            combined = values
        metadata[key] = list(dict.fromkeys(combined))

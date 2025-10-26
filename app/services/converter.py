from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Type

import fnmatch
import re

from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule

from app.backends import AviatorBackend, FlinkCEPBackend, FlinkSQLBackend
from app.models.enums import RuleTargetFormat
from app.models.requests import (
    BatchRuleConversionRequest,
    RuleConversionRequest,
    SigmaRulePayload,
)
from app.services.parser import SigmaParserService
from app.utils.errors import SigmaServiceError


DEFAULT_AGGREGATION_WINDOW = "5m"
DEFAULT_AGGREGATION_THRESHOLD = 1
SQL_EVENT_TIME_COLUMN = "event_time"


@dataclass
class AggregationResult:
    """Aggregation query details derived from correlation rules."""

    window: Optional[str]
    group_by: List[str] = field(default_factory=list)
    threshold: Optional[int] = None
    threshold_operator: str = ">="
    query: Optional[str] = None
    note: Optional[str] = None


@dataclass
class ConversionResult:
    """Represents a single conversion result."""

    format: RuleTargetFormat
    query: str
    aggregation: Optional[AggregationResult] = None


class SigmaConverterRegistry:
    """Registry that stores backend classes for target formats."""

    def __init__(self) -> None:
        self._registry: Dict[RuleTargetFormat, Type] = {}
        self._defaults: Dict[RuleTargetFormat, Dict[str, Any]] = {}

    def register(
        self,
        target_format: RuleTargetFormat,
        backend_cls: Type,
        *,
        default_options: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._registry[target_format] = backend_cls
        self._defaults[target_format] = default_options or {}

    def get(self, target_format: RuleTargetFormat) -> Type:
        try:
            return self._registry[target_format]
        except KeyError as exc:
            raise SigmaServiceError(
                f"No backend registered for target format '{target_format}'."
            ) from exc

    def defaults(self, target_format: RuleTargetFormat) -> Dict[str, Any]:
        return dict(self._defaults.get(target_format, {}))

    def available_formats(self) -> List[RuleTargetFormat]:
        return list(self._registry.keys())




class DetectionExpressionBuilder:
    """Utility kept for backward-compatible expression testing."""

    LOGICAL_KEYWORDS = {"and", "or", "not", "AND", "OR", "NOT"}

    def build(self, detection):
        if not detection:
            raise SigmaServiceError("Sigma rule detection section is missing.")

        selections = {
            key: self._build_selection_expression(value)
            for key, value in detection.items()
            if key != "condition"
        }

        condition = detection.get("condition")
        if condition is None:
            if len(selections) == 1:
                return next(iter(selections.values()))
            return " OR ".join(f"({expr})" for expr in selections.values())

        condition = condition.strip()
        special_match = re.match(r"(\d+|all) of (.+)", condition, re.IGNORECASE)
        if special_match:
            count_str, pattern = special_match.groups()
            matched_expr = self._resolve_pattern(pattern.strip(), selections)
            if count_str.lower() == "all":
                return " AND ".join(f"({expr})" for expr in matched_expr)
            try:
                count = int(count_str)
            except ValueError as exc:  # pragma: no cover - defensive guard
                raise SigmaServiceError("Invalid occurrence count in detection condition.") from exc
            if count <= 1:
                return " OR ".join(f"({expr})" for expr in matched_expr)
            return f"AT_LEAST_{count}(" + ", ".join(matched_expr) + ")"

        token_pattern = re.compile(r"[A-Za-z_][A-Za-z0-9_\-]*")

        def replace_token(match):
            token = match.group(0)
            if token in self.LOGICAL_KEYWORDS:
                return token.upper()
            if token in selections:
                return f"({selections[token]})"
            return token

        return token_pattern.sub(replace_token, condition)

    def _resolve_pattern(self, pattern, selections):
        matched = [expr for name, expr in selections.items() if fnmatch.fnmatch(name, pattern)]
        if not matched:
            raise SigmaServiceError(
                f"Detection condition references '{pattern}' but no matching selections were found."
            )
        return matched

    def _build_selection_expression(self, data):
        if isinstance(data, dict):
            clauses = [self._field_expression(field, value) for field, value in data.items()]
            return " AND ".join(clauses)
        if isinstance(data, list):
            return " OR ".join(f"({self._build_selection_expression(item)})" for item in data)
        raise SigmaServiceError("Unsupported selection structure encountered during conversion.")

    def _field_expression(self, field, value):
        base_field, operator = self._split_field_operator(field)
        if isinstance(value, list):
            expressions = [self._field_expression(field, item) for item in value]
            return " OR ".join(f"({expr})" for expr in expressions)
        if operator == "contains":
            return f"CONTAINS({base_field}, '{value}')"
        if operator == "startswith":
            return f"STARTS_WITH({base_field}, '{value}')"
        if operator == "endswith":
            return f"ENDS_WITH({base_field}, '{value}')"
        if operator == "re":
            return f"REGEXP({base_field}, '{value}')"
        if operator == "wildcard":
            return f"LIKE({base_field}, '{value}')"
        return f"{base_field} = '{value}'"

    def _split_field_operator(self, field):
        if "|" not in field:
            return field, "equals"
        base, operator = field.split("|", 1)
        return base, operator

class SigmaConverterService:
    """Coordinates sigma rule conversions leveraging pySigma backends."""

    def __init__(self, parser_service: SigmaParserService) -> None:
        self.parser_service = parser_service
        self.registry = SigmaConverterRegistry()
        self._register_default_backends()

    def _register_default_backends(self) -> None:
        self.registry.register(RuleTargetFormat.AVIATOR, AviatorBackend)
        self.registry.register(RuleTargetFormat.FLINK_SQL, FlinkSQLBackend)
        self.registry.register(RuleTargetFormat.FLINK_CEP, FlinkCEPBackend)

    def convert_rule(
        self, request: RuleConversionRequest
    ) -> ConversionResult:
        collection = self.parser_service.to_collection(request.payload)
        sigma_rules = self._extract_rules(collection)
        correlation_rules = self._extract_correlation_rules(collection)
        if not sigma_rules:
            raise SigmaServiceError(
                "No sigma rules detected in the provided payload."
            )
        sigma_rule = sigma_rules[0]
        backend_cls = self.registry.get(request.target_format)
        options = self._merge_options(request.target_format, request.options)
        backend = backend_cls(
            processing_pipeline=self.parser_service.pipeline,
            collect_errors=False,
            **options,
        )
        try:
            queries = backend.convert_rule(sigma_rule)
        except SigmaError as exc:
            raise SigmaServiceError(
                "Failed to convert sigma rule.", details={"error": str(exc)}
            ) from exc
        if backend.errors:
            first_error = backend.errors[0][1]
            raise SigmaServiceError(
                "Sigma backend reported an error.", details={"error": str(first_error)}
            )
        query = self._extract_query_output(queries)
        aggregation: Optional[AggregationResult] = None
        match = self._match_correlation_rule(sigma_rule, correlation_rules)
        if match is not None:
            reference_queries = self._collect_reference_queries(
                base_rule=sigma_rule,
                correlation_rule=match,
                base_query=query,
                target_format=request.target_format,
                options=options,
                all_rules=sigma_rules,
            )
            aggregation = self._build_aggregation_details(
                sigma_rule, match, query, request.target_format, options, reference_queries
            )
        return ConversionResult(format=request.target_format, query=query, aggregation=aggregation)


    def convert_all_formats(
        self,
        payload: SigmaRulePayload,
        *,
        formats: Optional[List[RuleTargetFormat]] = None,
        options: Optional[Dict[RuleTargetFormat, Dict[str, Any]]] = None,
    ) -> List[ConversionResult]:
        target_formats = formats or self.registry.available_formats()
        format_options = options or {}
        results: List[ConversionResult] = []
        for fmt in target_formats:
            request = RuleConversionRequest(
                payload=payload,
                target_format=fmt,
                options=format_options.get(fmt, {}),
            )
            results.append(self.convert_rule(request))
        return results

    def convert_batch(
        self, request: BatchRuleConversionRequest
    ) -> List[ConversionResult]:
        results: List[ConversionResult] = []
        for item in request.rules:
            single_request = RuleConversionRequest(
                payload=item.payload,
                target_format=request.target_format,
                options=item.options,
            )
            results.append(self.convert_rule(single_request))
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _merge_options(
        self, target_format: RuleTargetFormat, options: Dict[str, Any]
    ) -> Dict[str, Any]:
        merged = self.registry.defaults(target_format)
        if options:
            merged.update(options)
        return merged

    def _extract_rules(self, collection) -> List[SigmaRule]:
        return [rule for rule in getattr(collection, "rules", []) if isinstance(rule, SigmaRule)]

    def _extract_correlation_rules(self, collection) -> List[SigmaCorrelationRule]:
        return [
            rule
            for rule in getattr(collection, "rules", [])
            if isinstance(rule, SigmaCorrelationRule)
        ]

    def _match_correlation_rule(
        self, base_rule: SigmaRule, correlation_rules: List[SigmaCorrelationRule]
    ) -> Optional[SigmaCorrelationRule]:
        identifiers = {
            str(value)
            for value in (
                getattr(base_rule, "id", None),
                getattr(base_rule, "name", None),
            )
            if value
        }
        if not identifiers:
            return None
        for correlation_rule in correlation_rules:
            for reference in getattr(correlation_rule, "rules", []):
                ref_id = getattr(reference, "reference", None)
                if ref_id is not None and str(ref_id) in identifiers:
                    return correlation_rule
                linked_rule = getattr(reference, "rule", None)
                if linked_rule is not None:
                    linked_identifiers = {
                        str(value)
                        for value in (
                            getattr(linked_rule, "id", None),
                            getattr(linked_rule, "name", None),
                        )
                        if value
                    }
                    if identifiers & linked_identifiers:
                        return correlation_rule
        return None

    def _build_aggregation_details(
        self,
        base_rule: SigmaRule,
        correlation_rule: SigmaCorrelationRule,
        base_query: str,
        target_format: RuleTargetFormat,
        options: Dict[str, Any],
        rule_queries: Dict[str, str],
    ) -> AggregationResult:
        try:
            builder = AggregationQueryBuilder(
                target_format=target_format,
                base_rule=base_rule,
                correlation_rule=correlation_rule,
                base_query=base_query,
                options=options,
                rule_queries=rule_queries,
            )
            return builder.build()
        except SigmaServiceError as exc:
            return AggregationResult(
                window=None,
                group_by=[],
                threshold=None,
                query=None,
                note=str(exc),
            )
        except Exception as exc:  # pragma: no cover - defensive guard
            return AggregationResult(
                window=None,
                group_by=[],
                threshold=None,
                query=None,
                note=f"Failed to build aggregation query: {exc}",
            )

    def _collect_reference_queries(
        self,
        *,
        base_rule: SigmaRule,
        correlation_rule: SigmaCorrelationRule,
        base_query: str,
        target_format: RuleTargetFormat,
        options: Dict[str, Any],
        all_rules: List[SigmaRule],
    ) -> Dict[str, str]:
        queries: Dict[str, str] = {}

        def _register(rule: SigmaRule, query_text: str, reference: Optional[str] = None) -> None:
            identifiers = set()
            if reference:
                identifiers.add(str(reference))
            for attr in ("id", "name"):
                value = getattr(rule, attr, None)
                if value:
                    identifiers.add(str(value))
            if not identifiers:
                identifiers.add(str(getattr(rule, "title", "base_rule")))
            for identifier in identifiers:
                queries.setdefault(identifier, query_text)

        _register(base_rule, base_query)

        rule_lookup: Dict[str, SigmaRule] = {}
        for rule in all_rules:
            for attr in ("id", "name"):
                value = getattr(rule, attr, None)
                if value:
                    rule_lookup[str(value)] = rule

        backend_cls = self.registry.get(target_format)
        backend = backend_cls(
            processing_pipeline=self.parser_service.pipeline,
            collect_errors=False,
            **options,
        )

        processed_rules = {id(base_rule)}

        for reference in getattr(correlation_rule, "rules", []):
            rule_obj = getattr(reference, "rule", None)
            if rule_obj is None:
                ref_value = getattr(reference, "reference", None)
                if ref_value:
                    rule_obj = rule_lookup.get(str(ref_value))
            if rule_obj is None:
                continue
            if rule_obj is base_rule:
                continue
            if id(rule_obj) in processed_rules:
                continue
            try:
                converted = backend.convert_rule(rule_obj)
                query_text = self._extract_query_output(converted)
                _register(rule_obj, query_text, getattr(reference, "reference", None))
                processed_rules.add(id(rule_obj))
            except SigmaError:
                continue
        return queries

    def _extract_query_output(self, output: Any) -> str:
        if isinstance(output, (list, tuple)):
            if not output:
                raise SigmaServiceError("Sigma backend returned no queries.")
            return self._extract_query_output(output[0])
        if isinstance(output, bytes):
            return output.decode("utf-8")
        return str(output)


__all__ = [
    "SigmaConverterService",
    "SigmaConverterRegistry",
    "ConversionResult",
    "DetectionExpressionBuilder",
]


class AggregationQueryBuilder:
    """Build aggregation-aware queries for different backends."""

    def __init__(
        self,
        *,
        target_format: RuleTargetFormat,
        base_rule: SigmaRule,
        correlation_rule: SigmaCorrelationRule,
        base_query: str,
        options: Dict[str, Any],
        rule_queries: Dict[str, str],
    ) -> None:
        self.target_format = target_format
        self.base_rule = base_rule
        self.correlation_rule = correlation_rule
        self.base_query = base_query.strip()
        self.options = options or {}
        self.rule_queries = rule_queries or {}
        self.metadata = self._merge_metadata()
        self.notes: List[str] = []
        self.window = self._resolve_window()
        self.threshold, self.threshold_operator = self._resolve_threshold()
        self.group_by = self._resolve_group_by()
        self.event_time_column = self._resolve_event_time_column()
        self.pattern_alias = self._resolve_pattern_alias()
        self.rule_entries = self._hydrate_rule_entries()

    def _resolve_event_time_column(self) -> str:
        override = self.metadata.get("aggregation_event_time_field")
        if isinstance(override, str) and override.strip():
            return override.strip()
        return SQL_EVENT_TIME_COLUMN

    def _resolve_pattern_alias(self) -> Optional[str]:
        alias = self.metadata.get("aggregation_pattern_alias")
        if isinstance(alias, str) and alias.strip():
            return alias.strip()
        return None

    def build(self) -> AggregationResult:
        corr_type_enum = getattr(self.correlation_rule, "type", None)
        if corr_type_enum is None:
            self.notes.append("Correlation rule lacks a type definition; please review manually.")
            return AggregationResult(
                window=self.window,
                group_by=self.group_by,
                threshold=self.threshold,
                threshold_operator=self.threshold_operator,
                query=None,
                note=self._notes_text(),
            )

        corr_type = corr_type_enum.name.lower()
        supported_types = {"event_count", "value_count", "temporal", "temporal_ordered"}
        if corr_type not in supported_types:
            self.notes.append(f"Aggregation type '{corr_type}' is not supported yet.")
            query = None
        else:
            query = self._generate_query(corr_type)
        return AggregationResult(
            window=self.window,
            group_by=self.group_by,
            threshold=self.threshold,
            threshold_operator=self.threshold_operator,
            query=query,
            note=self._notes_text(),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _generate_query(self, corr_type: str) -> Optional[str]:
        if self.target_format == RuleTargetFormat.FLINK_SQL:
            return self._build_flink_sql_query(corr_type)
        if self.target_format == RuleTargetFormat.AVIATOR:
            return self._build_aviator_query(corr_type)
        if self.target_format == RuleTargetFormat.FLINK_CEP:
            return self._build_flink_cep_query(corr_type)
        self.notes.append(
            f"Aggregation conversion is not implemented for target format '{self.target_format.value}'."
        )
        return None

    def _merge_metadata(self) -> Dict[str, Any]:
        metadata: Dict[str, Any] = {}
        for rule in (self.base_rule, self.correlation_rule):
            attrs = getattr(rule, "custom_attributes", None)
            if isinstance(attrs, dict):
                rule_metadata = attrs.get("metadata")
                if isinstance(rule_metadata, dict):
                    metadata.update(rule_metadata)
        return metadata

    def _hydrate_rule_entries(self) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        references = getattr(self.correlation_rule, "rules", [])

        def _candidate_identifiers(rule: Optional[SigmaRule], reference: Any) -> List[str]:
            candidates: List[str] = []
            reference_value = getattr(reference, "reference", None)
            if reference_value:
                candidates.append(str(reference_value))
            if rule is not None:
                for attr in ("id", "name", "title"):
                    value = getattr(rule, attr, None)
                    if value:
                        candidates.append(str(value))
            return candidates

        for index, reference in enumerate(references):
            rule_obj = getattr(reference, "rule", None)
            identifiers = _candidate_identifiers(rule_obj, reference)
            query_text: Optional[str] = None
            for identifier in identifiers:
                if identifier in self.rule_queries:
                    query_text = self.rule_queries[identifier]
                    break
            if query_text is None and rule_obj is self.base_rule:
                query_text = self.base_query
            display_name = getattr(rule_obj, "name", None) or (identifiers[0] if identifiers else f"rule_{index+1}")
            entries.append(
                {
                    "reference": reference,
                    "rule": rule_obj,
                    "query": query_text,
                    "name": display_name,
                    "identifiers": identifiers,
                }
            )

        if not entries:
            entries.append(
                {
                    "reference": None,
                    "rule": self.base_rule,
                    "query": self.base_query,
                    "name": getattr(self.base_rule, "name", None)
                    or getattr(self.base_rule, "title", "base_rule"),
                    "identifiers": [],
                }
            )

        return entries

    def _resolve_window(self) -> str:
        meta_window = self.metadata.get("aggregation_timespan")
        if isinstance(meta_window, str) and meta_window.strip():
            spec = getattr(getattr(self.correlation_rule, "timespan", None), "spec", None)
            if spec and spec != meta_window:
                self.notes.append(
                    f"Correlation timespan '{spec}' overridden by metadata aggregation_timespan '{meta_window}'."
                )
            return meta_window.strip()
        timespan = getattr(self.correlation_rule, "timespan", None)
        spec = getattr(timespan, "spec", None)
        if isinstance(spec, str) and spec:
            return spec
        self.notes.append(
            f"Window not provided; defaulted to {DEFAULT_AGGREGATION_WINDOW}."
        )
        return DEFAULT_AGGREGATION_WINDOW

    def _resolve_threshold(self) -> Tuple[int, str]:
        condition = getattr(self.correlation_rule, "condition", None)
        if condition is not None:
            count = getattr(condition, "count", None)
            threshold = self._coerce_positive_int(count)
            if threshold is not None:
                op_name = getattr(getattr(condition, "op", None), "name", "").upper()
                operator_token = self._map_condition_operator(op_name)
                if operator_token is None:
                    if op_name:
                        self.notes.append(
                            f"Correlation condition operator '{op_name.lower()}' is not supported; defaulted to '>='."
                        )
                    operator_token = ">="
                return threshold, operator_token
        meta_threshold = self._coerce_positive_int(self.metadata.get("aggregation_threshold"))
        if meta_threshold is not None:
            return meta_threshold, ">="
        self.notes.append(
            f"Threshold not provided; defaulted to {DEFAULT_AGGREGATION_THRESHOLD}."
        )
        return DEFAULT_AGGREGATION_THRESHOLD, ">="

    def _resolve_group_by(self) -> List[str]:
        if getattr(self.correlation_rule, "group_by", None):
            groups = [str(item) for item in self.correlation_rule.group_by if str(item)]
            if groups:
                return groups
        metadata_dimensions = self.metadata.get("dimensions")
        if isinstance(metadata_dimensions, list):
            groups = [str(item) for item in metadata_dimensions if str(item)]
            if groups:
                return groups
        self.notes.append(
            "Aggregation rule does not define grouping dimensions; please supply them manually."
        )
        return []

    def _resolve_value_field(self) -> Optional[str]:
        condition = getattr(self.correlation_rule, "condition", None)
        fieldref = getattr(condition, "fieldref", None)
        if isinstance(fieldref, str) and fieldref.strip():
            return fieldref.strip()
        metadata_field = self.metadata.get("aggregation_field")
        if isinstance(metadata_field, str) and metadata_field.strip():
            return metadata_field.strip()
        return None

    def _map_condition_operator(self, op_name: str) -> Optional[str]:
        if not op_name:
            return None
        mapping = {
            "GTE": ">=",
            "GE": ">=",
            "GT": ">",
            "LTE": "<=",
            "LE": "<=",
            "LT": "<",
            "EQ": "=",
        }
        return mapping.get(op_name)

    def _build_flink_sql_query(self, corr_type: str) -> Optional[str]:
        if corr_type == "event_count":
            return self._build_flink_sql_event_count()
        if corr_type == "value_count":
            return self._build_flink_sql_value_count()
        if corr_type == "temporal":
            return self._build_flink_sql_temporal(ordered=False)
        if corr_type == "temporal_ordered":
            return self._build_flink_sql_temporal(ordered=True)
        self.notes.append(f"Flink SQL conversion for '{corr_type}' is not available.")
        return None

    def _build_flink_sql_event_count(self) -> str:
        table_name, where_clause = self._extract_sql_parts()
        if not table_name:
            table_name = self.options.get("table") or "event_stream"
            self.notes.append(f"Base table defaulted to '{table_name}'.")
        if not where_clause:
            where_clause = "TRUE -- TODO: add filtering conditions from the base rule"
            self.notes.append("Unable to derive WHERE clause from the base query.")
        interval_expr = self._to_flink_interval(self.window)
        select_columns = list(self.group_by)
        select_columns.extend(["window_start", "window_end", "COUNT(*) AS match_count"])
        select_section = ",\n    ".join(select_columns) if select_columns else "COUNT(*) AS match_count"
        group_columns = ["window_start", "window_end"] + self.group_by
        group_section = ",\n    ".join(group_columns)
        if not self.group_by:
            self.notes.append("Populate GROUP BY dimensions to complete the aggregation query.")
        if self.event_time_column == SQL_EVENT_TIME_COLUMN:
            self.notes.append("Event time column not provided; defaulted to 'event_time'.")
        operator = self.threshold_operator
        query_lines = [
            "WITH base_events AS (",
            "    SELECT *",
            f"    FROM {table_name}",
            f"    WHERE {where_clause}",
            ")",
            "SELECT",
            f"    {select_section}",
            "FROM TABLE(",
            "    TUMBLE(",
            "        TABLE (",
            f"            SELECT *, COALESCE({self.event_time_column}, PROCTIME()) AS event_time_source",
            "            FROM base_events",
            "        ),",
            f"        DESCRIPTOR(event_time_source), {interval_expr}",
            "    )",
            ")",
            "GROUP BY",
            f"    {group_section}",
            f"HAVING COUNT(*) {operator} {self.threshold};",
        ]
        return "\n".join(query_lines)

    def _build_flink_sql_temporal(self, *, ordered: bool) -> Optional[str]:
        parsed_entries = self._parse_rule_entries_for_sql()
        if len(parsed_entries) < 2:
            self.notes.append("Temporal correlation requires at least two referenced rule filters.")
            return None
        if ordered:
            return self._build_flink_sql_temporal_ordered(parsed_entries)
        return self._build_flink_sql_temporal_unordered(parsed_entries)

    def _parse_rule_entries_for_sql(self) -> List[Dict[str, str]]:
        parsed: List[Dict[str, str]] = []
        tables: List[str] = []
        for entry in self.rule_entries:
            query_text = entry.get("query") or (self.base_query if entry.get("rule") is self.base_rule else None)
            if not query_text:
                self.notes.append(f"No converted query available for rule '{entry['name']}'.")
                continue
            table_name, where_clause = self._extract_sql_parts(query_text)
            if not table_name or not where_clause:
                self.notes.append(f"Unable to parse SQL parts for rule '{entry['name']}'.")
                continue
            parsed.append({"name": entry["name"], "table": table_name, "where": where_clause})
            tables.append(table_name)
        if not parsed:
            return []
        if len(set(tables)) > 1:
            self.notes.append("Referenced rules target different tables; review join logic manually.")
        return parsed

    def _build_filtered_events_cte(self, parsed_entries: List[Dict[str, str]]) -> List[str]:
        lines: List[str] = ["WITH", "    filtered_events AS ("]
        for idx, entry in enumerate(parsed_entries):
            if idx:
                lines.append("        UNION ALL")
            lines.append(f"        SELECT *, '{entry['name']}' AS rule_name")
            lines.append(f"        FROM {entry['table']}")
            lines.append(f"        WHERE {entry['where']}")
        lines.append("    ),")
        lines.append("    windowed_events AS (")
        lines.append(
            f"        SELECT *, COALESCE({self.event_time_column}, PROCTIME()) AS event_time_source"
        )
        lines.append("        FROM filtered_events")
        lines.append("    )")
        return lines

    def _build_flink_sql_temporal_unordered(self, parsed_entries: List[Dict[str, str]]) -> str:
        interval_expr = self._to_flink_interval(self.window)
        cte_lines = self._build_filtered_events_cte(parsed_entries)
        select_columns = list(self.group_by)
        select_columns.extend(
            [
                "window_start",
                "window_end",
                "COUNT(DISTINCT rule_name) AS matched_rule_count",
            ]
        )
        select_section = ",\n    ".join(select_columns)
        group_columns = ["window_start", "window_end"] + self.group_by
        group_section = ",\n    ".join(group_columns)
        threshold_value, operator = self._normalise_temporal_threshold(len(parsed_entries))
        if not self.group_by:
            self.notes.append("Populate GROUP BY dimensions to complete the aggregation query.")
        if self.event_time_column == SQL_EVENT_TIME_COLUMN:
            self.notes.append("Event time column not provided; defaulted to 'event_time'.")
        query_lines: List[str] = cte_lines + [
            "SELECT",
            f"    {select_section}",
            "FROM TABLE(",
            "    TUMBLE(",
            "        TABLE windowed_events,",
            f"        DESCRIPTOR(event_time_source), {interval_expr}",
            "    )",
            ")",
            "GROUP BY",
            f"    {group_section}",
            f"HAVING COUNT(DISTINCT rule_name) {operator} {threshold_value};",
        ]
        return "\n".join(query_lines)

    def _build_aviator_value_count(self) -> Optional[str]:
        value_field = self._resolve_value_field()
        if not value_field:
            self.notes.append("Value count correlation requires a field reference; skipping aggregation query.")
            return None
        base_expression = self.base_query.strip() or "TRUE"
        if not self.group_by:
            self.notes.append("Aviator aggregation requires grouping dimensions; added placeholder.")
        group_clause = ", ".join(self.group_by) if self.group_by else "<add-group-dimensions>"
        query_lines = [
            f"WINDOW {self.window} BY {group_clause} HAVING COUNT_DISTINCT({value_field}) {self.threshold_operator} {self.threshold}",
            "FILTER (",
            f"  {base_expression}",
            ")",
        ]
        return "\n".join(query_lines)

    def _build_aviator_temporal(self, *, ordered: bool) -> Optional[str]:
        if len(self.rule_entries) < 2:
            self.notes.append("Temporal correlation requires at least two referenced rules.")
            return None
        if not self.group_by:
            self.notes.append("Aviator aggregation requires grouping dimensions; added placeholder.")
        group_clause = ", ".join(self.group_by) if self.group_by else "<add-group-dimensions>"
        header = f"WINDOW {self.window} BY {group_clause} MATCH {'SEQUENCE' if ordered else 'CO_OCCURRENCE'}"
        required_matches, operator = self._normalise_temporal_threshold(len(self.rule_entries))
        pattern_lines: List[str] = []
        for idx, entry in enumerate(self.rule_entries):
            expr = entry.get("query") or (self.base_query if entry.get("rule") is self.base_rule else None)
            if not expr:
                self.notes.append(f"No converted query available for rule '{entry['name']}'. Inserted placeholder.")
                expr = "<add-condition>"
            expr = expr.strip() or "<add-condition>"
            label = entry["name"]
            if ordered:
                prefix = "  -> " if idx else "  "
                pattern_lines.append(f"{prefix}STEP {idx + 1} '{label}' => ({expr})")
            else:
                connector = "  AND " if idx else "  "
                pattern_lines.append(f"{connector}RULE '{label}' => ({expr})")
        query_lines = [header, "PATTERN ("]
        query_lines.extend(pattern_lines)
        query_lines.append(")")
        query_lines.append(f"REQUIRES {operator} {required_matches} MATCHES")
        return "\n".join(query_lines)

    def _alias_sequence(self, count: int) -> List[str]:
        if count <= 0:
            return []
        aliases: List[str] = []
        primary_alias = self.pattern_alias or self.options.get("pattern_name")
        if isinstance(primary_alias, str) and primary_alias.strip():
            aliases.append(primary_alias.strip())
        letters = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        idx = 0
        while len(aliases) < count:
            candidate = letters[idx % len(letters)]
            idx += 1
            if any(candidate.lower() == existing.lower() for existing in aliases):
                continue
            aliases.append(candidate)
        return aliases[:count]

    def _normalise_temporal_threshold(self, rule_count: int) -> Tuple[int, str]:
        operator = self.threshold_operator
        if operator not in {">=", "="}:
            self.notes.append(
                f"Temporal correlation operator '{operator}' is not supported; defaulted to '>='."
            )
            operator = ">="
        threshold_value = self.threshold
        if operator == ">=" and threshold_value < rule_count:
            self.notes.append(
                f"Temporal correlation requires matches for {rule_count} rules; threshold adjusted."
            )
            threshold_value = rule_count
        if operator == "=" and threshold_value != rule_count:
            self.notes.append(
                f"Temporal correlation with '=' operator expects threshold equal to rule count; adjusted to {rule_count}."
            )
            threshold_value = rule_count
        self.threshold = threshold_value
        self.threshold_operator = operator
        return threshold_value, operator

    def _build_flink_sql_temporal_ordered(self, parsed_entries: List[Dict[str, str]]) -> str:
        interval_expr = self._to_flink_interval(self.window)
        cte_lines = self._build_filtered_events_cte(parsed_entries)
        self._normalise_temporal_threshold(len(parsed_entries))
        pattern_aliases = [f"R{index + 1}" for index in range(len(parsed_entries))]
        pattern_clause = " ".join(pattern_aliases)
        measures = [
            f"FIRST({pattern_aliases[0]}.event_time_source) AS first_event_time",
            f"LAST({pattern_aliases[-1]}.event_time_source) AS last_event_time",
        ]
        define_entries = [
            f"{alias} AS rule_name = '{entry['name']}'"
            for alias, entry in zip(pattern_aliases, parsed_entries)
        ]
        query_lines: List[str] = cte_lines + [
            "SELECT",
            "    *",
            "FROM windowed_events",
            "MATCH_RECOGNIZE (",
        ]
        if self.group_by:
            query_lines.append(f"    PARTITION BY {', '.join(self.group_by)}")
        query_lines.extend(
            [
                "    ORDER BY event_time_source",
                "    MEASURES",
            ]
        )
        for idx, measure in enumerate(measures):
            suffix = "," if idx < len(measures) - 1 else ""
            query_lines.append(f"        {measure}{suffix}")
        query_lines.extend(
            [
                "    ONE ROW PER MATCH",
                "    AFTER MATCH SKIP PAST LAST ROW",
                f"    PATTERN ({pattern_clause})",
                f"    WITHIN {interval_expr}",
                "    DEFINE",
            ]
        )
        for idx, definition in enumerate(define_entries):
            suffix = "," if idx < len(define_entries) - 1 else ""
            query_lines.append(f"        {definition}{suffix}")
        query_lines.append(");")
        return "\n".join(query_lines)

    def _build_flink_sql_value_count(self) -> Optional[str]:
        value_field = self._resolve_value_field()
        if not value_field:
            self.notes.append("Value count correlation requires a field reference; skipping aggregation query.")
            return None
        table_name, where_clause = self._extract_sql_parts()
        if not table_name:
            table_name = self.options.get("table") or "event_stream"
            self.notes.append(f"Base table defaulted to '{table_name}'.")
        if not where_clause:
            where_clause = "TRUE -- TODO: add filtering conditions from the base rule"
            self.notes.append("Unable to derive WHERE clause from the base query.")
        interval_expr = self._to_flink_interval(self.window)
        select_columns = list(self.group_by)
        select_columns.extend(
            [
                "window_start",
                "window_end",
                f"COUNT(DISTINCT {value_field}) AS distinct_value_count",
            ]
        )
        select_section = ",\n    ".join(select_columns) if select_columns else f"COUNT(DISTINCT {value_field}) AS distinct_value_count"
        group_columns = ["window_start", "window_end"] + self.group_by
        group_section = ",\n    ".join(group_columns)
        if not self.group_by:
            self.notes.append("Populate GROUP BY dimensions to complete the aggregation query.")
        if self.event_time_column == SQL_EVENT_TIME_COLUMN:
            self.notes.append("Event time column not provided; defaulted to 'event_time'.")
        operator = self.threshold_operator
        query_lines = [
            "WITH base_events AS (",
            "    SELECT *",
            f"    FROM {table_name}",
            f"    WHERE {where_clause}",
            ")",
            "SELECT",
            f"    {select_section}",
            "FROM TABLE(",
            "    TUMBLE(",
            "        TABLE (",
            f"            SELECT *, COALESCE({self.event_time_column}, PROCTIME()) AS event_time_source",
            "            FROM base_events",
            "        ),",
            f"        DESCRIPTOR(event_time_source), {interval_expr}",
            "    )",
            ")",
            "GROUP BY",
            f"    {group_section}",
            f"HAVING COUNT(DISTINCT {value_field}) {operator} {self.threshold};",
        ]
        return "\n".join(query_lines)


    def _build_aviator_query(self, corr_type: str) -> Optional[str]:
        if corr_type == "event_count":
            return self._build_aviator_event_count()
        if corr_type == "value_count":
            return self._build_aviator_value_count()
        if corr_type == "temporal":
            return self._build_aviator_temporal(ordered=False)
        if corr_type == "temporal_ordered":
            return self._build_aviator_temporal(ordered=True)
        self.notes.append(f"Aviator conversion for '{corr_type}' is not available.")
        return None

    def _build_aviator_event_count(self) -> str:
        base_expression = self.base_query.strip() or "TRUE"
        if not self.group_by:
            self.notes.append("Aviator aggregation requires grouping dimensions; added placeholder.")
        group_clause = ", ".join(self.group_by) if self.group_by else "<add-group-dimensions>"
        query_lines = [
            f"WINDOW {self.window} BY {group_clause} HAVING COUNT {self.threshold_operator} {self.threshold}",
            "FILTER (",
            f"  {base_expression}",
            ")",
        ]
        return "\n".join(query_lines)


    def _build_flink_cep_query(self, corr_type: str) -> Optional[str]:
        if corr_type == "event_count":
            return self._build_flink_cep_event_count()
        if corr_type == "value_count":
            return self._build_flink_cep_value_count()
        if corr_type == "temporal":
            return self._build_flink_cep_temporal(ordered=False)
        if corr_type == "temporal_ordered":
            return self._build_flink_cep_temporal(ordered=True)
        self.notes.append(f"Flink CEP conversion for '{corr_type}' is not available.")
        return None

    def _build_flink_cep_event_count(self) -> str:
        pattern_name = self.pattern_alias or self.options.get("pattern_name") or self._extract_pattern_name()
        if not pattern_name:
            pattern_name = "A"
            self.notes.append("Pattern name not detected; defaulted to 'A'.")
        condition = self._condition_for_cep_alias(self.base_query, pattern_name)
        group_clause = (
            "GROUP BY " + ", ".join(self.group_by)
            if self.group_by
            else "-- TODO: supply GROUP BY dimensions"
        )
        if not self.group_by:
            self.notes.append("CEP aggregation is missing GROUP BY dimensions.")
        query_parts = [
            f"PATTERN SEQ({pattern_name}+)",
            f"WITHIN {self.window}",
            f"WHERE {condition}",
            group_clause,
            f"HAVING COUNT({pattern_name}) {self.threshold_operator} {self.threshold}",
        ]
        return "\n".join(query_parts)

    def _build_flink_cep_value_count(self) -> Optional[str]:
        value_field = self._resolve_value_field()
        if not value_field:
            self.notes.append("Value count correlation requires a field reference; skipping CEP aggregation.")
            return None
        pattern_name = self.pattern_alias or self.options.get("pattern_name") or self._extract_pattern_name()
        if not pattern_name:
            pattern_name = "A"
            self.notes.append("Pattern name not detected; defaulted to 'A'.")
        condition = self._condition_for_cep_alias(self.base_query, pattern_name)
        group_clause = (
            "GROUP BY " + ", ".join(self.group_by)
            if self.group_by
            else "-- TODO: supply GROUP BY dimensions"
        )
        if not self.group_by:
            self.notes.append("CEP aggregation is missing GROUP BY dimensions.")
        query_parts = [
            f"PATTERN SEQ({pattern_name}+)",
            f"WITHIN {self.window}",
            f"WHERE {condition}",
            group_clause,
            f"HAVING COUNT(DISTINCT {pattern_name}.{value_field}) {self.threshold_operator} {self.threshold}",
        ]
        return "\n".join(query_parts)

    def _build_flink_cep_temporal(self, *, ordered: bool) -> Optional[str]:
        if len(self.rule_entries) < 2:
            self.notes.append("Temporal CEP correlation requires at least two referenced rules; aggregation omitted.")
            return None
        threshold_value, operator = self._normalise_temporal_threshold(len(self.rule_entries))
        if operator != "=":
            self.notes.append(
                "CEP temporal pattern enforces one occurrence per rule; review threshold logic if stricter counting is required."
            )
        aliases = self._alias_sequence(len(self.rule_entries))
        if ordered:
            pattern_clause = ", ".join(aliases)
        else:
            pattern_clause = ", ".join(aliases)
            self.notes.append(
                "Unordered temporal correlation emitted as sequential CEP pattern; adjust order or conditions if needed."
            )
        condition_lines: List[str] = []
        for alias, entry in zip(aliases, self.rule_entries):
            condition = self._condition_for_cep_alias(entry.get("query") or self.base_query, alias)
            condition_lines.append(f"  {condition}")
        query_lines: List[str] = [
            f"PATTERN SEQ({pattern_clause})",
            f"WITHIN {self.window}",
            "WHERE",
            " AND\n".join(condition_lines),
        ]
        if self.group_by:
            query_lines.append("GROUP BY " + ", ".join(self.group_by))
        else:
            self.notes.append("CEP temporal aggregation missing GROUP BY dimensions; add partitions as needed.")
            query_lines.append("-- TODO: add GROUP BY dimensions for CEP aggregation")
        return "\n".join(query_lines)
    def _to_flink_interval(self, window: str) -> str:
        match = re.fullmatch(r"(\d+)([smhd])", window.strip(), re.IGNORECASE)
        if match:
            value, unit = match.groups()
            unit_map = {"s": "SECOND", "m": "MINUTE", "h": "HOUR", "d": "DAY"}
            mapped = unit_map.get(unit.lower())
            if mapped:
                return f"INTERVAL '{value}' {mapped}"
        self.notes.append(
            f"Window '{window}' could not be translated to a Flink INTERVAL literal; inserted as raw text."
        )
        return f"INTERVAL '{window}'"

    def _condition_for_cep_alias(self, query: str, alias: str) -> str:
        condition = self._extract_after_keyword(query, "WHERE")
        if not condition:
            self.notes.append(f"Unable to read CEP WHERE clause from rule query for alias '{alias}'.")
            return f"{alias}.-- TODO: add conditions"
        condition = condition.rstrip(";").strip()
        if not condition:
            self.notes.append(f"Missing CEP condition content for alias '{alias}'.")
            return f"{alias}.-- TODO: add conditions"

        def _prefix_fragment(fragment: str) -> str:
            fragment = fragment.strip()
            if not fragment:
                return fragment
            first_token = fragment.split()[0]
            if "." not in first_token:
                return f"{alias}.{fragment}"
            existing_alias = first_token.split(".", 1)[0]
            if existing_alias.lower() != alias.lower():
                self.notes.append(
                    f"Replaced CEP alias '{existing_alias}' with '{alias}' in condition fragment."
                )
                return fragment.replace(f"{existing_alias}.", f"{alias}.", 1)
            return fragment

        fragments: List[str] = []
        last_index = 0
        for match in re.finditer(r"\bAND\b|\bOR\b", condition, flags=re.IGNORECASE):
            fragment = condition[last_index:match.start()].strip()
            operator = match.group(0).upper()
            if fragment:
                fragments.append(_prefix_fragment(fragment))
                fragments.append(operator)
            last_index = match.end()
        remainder = condition[last_index:].strip()
        if remainder:
            fragments.append(_prefix_fragment(remainder))

        rebuilt: List[str] = []
        for item in fragments:
            if item in {"AND", "OR"}:
                rebuilt.append(item)
            else:
                rebuilt.append(item)
        return " ".join(rebuilt)

    def _extract_sql_parts(self, query_text: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
        query = (query_text or self.base_query).strip().rstrip(';')
        upper = query.upper()
        from_idx = upper.find(' FROM ')
        where_clause = None
        table_name = None
        if from_idx != -1:
            after_from = query[from_idx + 6 :]
            where_idx = after_from.upper().find(' WHERE ')
            if where_idx != -1:
                table_name = after_from[:where_idx].strip()
                where_clause = after_from[where_idx + 7 :].strip()
            else:
                table_name = after_from.strip()
        if where_clause:
            limit_match = re.search(r"\sLIMIT\s+\d+\s*$", where_clause, re.IGNORECASE)
            if limit_match:
                where_clause = where_clause[: limit_match.start()].strip()
        return table_name, where_clause

    def _extract_pattern_name(self) -> Optional[str]:
        match = re.search(r"PATTERN\s+SEQ\(\s*([A-Za-z][A-Za-z0-9_]*)", self.base_query, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    def _extract_after_keyword(self, text: str, keyword: str) -> Optional[str]:
        index = text.upper().find(keyword.upper())
        if index == -1:
            return None
        return text[index + len(keyword) :].strip()

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

    def _notes_text(self) -> Optional[str]:
        if not self.notes:
            return None
        return '; '.join(dict.fromkeys(self.notes))


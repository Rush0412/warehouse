from enum import Enum


class RuleTargetFormat(str, Enum):
    """Supported target formats for sigma rule conversion."""

    AVIATOR = "aviator"
    FLINK_SQL = "flink_sql"
    FLINK_CEP = "flink_cep"


class RuleProcessingMode(str, Enum):
    """Processing modes for future extensibility."""

    SINGLE = "single"
    BATCH = "batch"

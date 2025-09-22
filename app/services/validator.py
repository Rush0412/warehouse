from __future__ import annotations

from typing import Dict, List, Tuple

from app.models.requests import RuleValidationRequest
from app.services.parser import SigmaParserService
from app.utils.errors import SigmaServiceError


class SigmaValidationService:
    """Provides validation helpers for sigma rules."""

    REQUIRED_FIELDS = {"title", "logsource", "detection"}

    def __init__(self, parser_service: SigmaParserService) -> None:
        self.parser_service = parser_service

    def validate(self, request: RuleValidationRequest) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        try:
            parsed = self.parser_service.parse_yaml(request.rule_yaml)
        except SigmaServiceError as exc:
            return False, [exc.message]

        rules_to_check = parsed if isinstance(parsed, list) else [parsed]
        for rule in rules_to_check:
            missing = self.REQUIRED_FIELDS - rule.keys()
            if missing:
                errors.append(
                    f"Rule '{rule.get('title', 'unknown')}' is missing required fields: {', '.join(sorted(missing))}."
                )
            detection = rule.get("detection", {})
            if isinstance(detection, dict) and "condition" not in detection:
                errors.append(
                    f"Rule '{rule.get('title', 'unknown')}' detection must define a condition."
                )
        return (len(errors) == 0, errors)

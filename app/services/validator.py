from __future__ import annotations

from typing import List, Tuple

from app.models.requests import RuleValidationRequest
from app.services.parser import SigmaParserService
from app.utils.errors import SigmaServiceError


class SigmaValidationService:
    """Provides validation helpers for sigma rules."""

    def __init__(self, parser_service: SigmaParserService) -> None:
        self.parser_service = parser_service

    def validate(self, request: RuleValidationRequest) -> Tuple[bool, List[str]]:
        try:
            rules = self.parser_service.parse_rules(request.rule_yaml)
        except SigmaServiceError as exc:
            return False, [exc.message]

        issues = self.parser_service.validate_sigma_rules(rules)
        return (len(issues) == 0, issues)

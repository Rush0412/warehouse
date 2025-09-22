from __future__ import annotations

from typing import List

from fastapi import FastAPI, status
from fastapi.responses import JSONResponse

from app.models.requests import (
    BatchRuleConversionRequest,
    RuleConversionRequest,
    RuleParseRequest,
    RuleParseResponse,
    RuleValidationRequest,
    RuleValidationResponse,
)
from app.services.converter import SigmaConverterService
from app.services.parser import SigmaParserService
from app.services.validator import SigmaValidationService
from app.utils.errors import SigmaServiceError

app = FastAPI(
    title="Sigma Rule Service",
    description="RESTful service for parsing, validating, and converting sigma rules.",
    version="0.1.0",
)


@app.exception_handler(SigmaServiceError)
async def sigma_service_error_handler(_, exc: SigmaServiceError) -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=exc.to_dict())


def get_parser_service() -> SigmaParserService:
    return SigmaParserService()


def get_validation_service(parser_service: SigmaParserService) -> SigmaValidationService:
    return SigmaValidationService(parser_service)


def get_converter_service(parser_service: SigmaParserService) -> SigmaConverterService:
    return SigmaConverterService(parser_service)


@app.post("/rules/parse", response_model=RuleParseResponse)
async def parse_rule(request: RuleParseRequest) -> RuleParseResponse:
    parser_service = get_parser_service()
    parsed = parser_service.parse_yaml(request.rule_yaml)
    return RuleParseResponse(parsed=parsed)


@app.post("/rules/validate", response_model=RuleValidationResponse)
async def validate_rule(request: RuleValidationRequest) -> RuleValidationResponse:
    parser_service = get_parser_service()
    validation_service = get_validation_service(parser_service)
    valid, errors = validation_service.validate(request)
    return RuleValidationResponse(valid=valid, errors=errors or None)


@app.post("/rules/convert")
async def convert_rule(request: RuleConversionRequest) -> dict:
    parser_service = get_parser_service()
    converter_service = get_converter_service(parser_service)
    result = converter_service.convert_rule(request)
    return {"format": result.format, "query": result.query}


@app.post("/rules/convert/batch")
async def convert_rules_batch(request: BatchRuleConversionRequest) -> List[dict]:
    parser_service = get_parser_service()
    converter_service = get_converter_service(parser_service)
    results = converter_service.convert_batch(request)
    return [{"format": item.format, "query": item.query} for item in results]


@app.get("/health")
async def health_check() -> dict:
    return {"status": "ok"}

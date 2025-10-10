from __future__ import annotations

from sigma.conversion.base import TextQueryBackend


class SimpleTextBackend(TextQueryBackend):
    """Common defaults for custom text backends built on pySigma."""

    token_separator = " "
    or_token = "OR"
    and_token = "AND"
    not_token = "NOT"
    eq_token = " = "
    group_expression = "({expr})"

    field_quote = None
    field_quote_pattern = None
    field_quote_pattern_negation = False
    field_escape = None
    field_escape_pattern = None

    str_quote = "'"
    str_quote_pattern = None
    str_quote_pattern_negation = False
    escape_char = "\\"
    add_escaped = ""
    wildcard_multi = "*"
    wildcard_single = "?"

    startswith_expression = "STARTS_WITH({field}, {value})"
    endswith_expression = "ENDS_WITH({field}, {value})"
    contains_expression = "CONTAINS({field}, {value})"
    wildcard_match_expression = "LIKE({field}, {value})"
    re_expression = "REGEXP({field}, '{regex}')"
    re_escape = ("'",)
    re_escape_char = "\\"

    field_exists_expression = "EXISTS({field})"
    field_not_exists_expression = "NOT EXISTS({field})"

    unbound_value_str_expression = "{value}"
    unbound_value_num_expression = "{value}"
    unbound_value_re_expression = "{value}"

    field_in_list_expression = "{field} {op} ({list})"
    list_separator = ", "

    def finalize_output_default(self, queries, output_format):  # type: ignore[override]
        return queries

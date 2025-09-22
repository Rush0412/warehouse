from app.services.converter import DetectionExpressionBuilder


def test_simple_condition():
    detection = {
        "selection": {"Image": "powershell.exe"},
        "condition": "selection",
    }
    builder = DetectionExpressionBuilder()
    expression = builder.build(detection)
    assert expression == "(Image = 'powershell.exe')"


def test_operator_contains():
    detection = {
        "sel": {"CommandLine|contains": "-enc"},
        "condition": "sel",
    }
    builder = DetectionExpressionBuilder()
    expression = builder.build(detection)
    assert expression == "(CONTAINS(CommandLine, '-enc'))"


def test_one_of_pattern():
    detection = {
        "selection_process": {"Image": "cmd.exe"},
        "selection_powershell": {"Image": "powershell.exe"},
        "condition": "1 of selection_*",
    }
    builder = DetectionExpressionBuilder()
    expression = builder.build(detection)
    assert expression == "(Image = 'cmd.exe') OR (Image = 'powershell.exe')"

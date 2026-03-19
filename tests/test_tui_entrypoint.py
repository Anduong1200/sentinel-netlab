from sensor.tui.__main__ import format_missing_dependency_message


def test_format_missing_dependency_message_for_yaml():
    message = format_missing_dependency_message("yaml")

    assert message is not None
    assert "PyYAML" in message
    assert "pip install -e ." in message


def test_format_missing_dependency_message_for_unknown_module():
    assert format_missing_dependency_message("totally_unknown") is None

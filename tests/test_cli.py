import json

import yaml
from click.testing import CliRunner

from pycloak.cli import main


def _write(path, content):
    path.write_text(content, encoding="utf-8")


def test_cli_process_json(tmp_path):
    rules = tmp_path / "rules.yaml"
    _write(rules, yaml.safe_dump({"email": "fixed:X"}))
    inp = tmp_path / "in.json"
    _write(inp, json.dumps([{"email": "a"}, {"email": "b"}]))
    out = tmp_path / "out.json"

    result = CliRunner().invoke(main, ["process", str(inp), "-r", str(rules), "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text()) == [{"email": "X"}, {"email": "X"}]


def test_cli_process_csv_autodetect(tmp_path):
    rules = tmp_path / "rules.yaml"
    _write(rules, yaml.safe_dump({"email": "fixed:X"}))
    inp = tmp_path / "in.csv"
    _write(inp, "name,email\nalice,a@x.com\n")
    out = tmp_path / "out.csv"

    result = CliRunner().invoke(main, ["process", str(inp), "-r", str(rules), "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert "X" in out.read_text()
    assert "a@x.com" not in out.read_text()


def test_cli_dry_run(tmp_path):
    rules = tmp_path / "rules.yaml"
    _write(rules, yaml.safe_dump({"email": "fixed:X"}))
    inp = tmp_path / "in.json"
    _write(inp, json.dumps([{"email": "a@x.com", "name": "Alice"}]))

    result = CliRunner().invoke(main, ["process", str(inp), "-r", str(rules), "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "email" in result.output
    assert "fixed:X" in result.output
    assert "no rule" in result.output  # for "name"


def test_cli_scan(tmp_path):
    inp = tmp_path / "in.json"
    _write(inp, json.dumps([
        {"email": "a@x.com", "ssn": "123-45-6789", "note": "hi"},
        {"email": "b@x.com", "ssn": "987-65-4321", "note": "yo"},
    ]))
    out = tmp_path / "rules.yaml"

    result = CliRunner().invoke(main, ["scan", str(inp), "-o", str(out)])
    assert result.exit_code == 0, result.output
    suggestions = yaml.safe_load(out.read_text())
    assert "email" in suggestions
    assert "ssn" in suggestions
    assert "note" not in suggestions


def test_cli_unknown_rule_fails_cleanly(tmp_path):
    rules = tmp_path / "rules.yaml"
    _write(rules, yaml.safe_dump({"x": "nonsense_rule"}))
    inp = tmp_path / "in.json"
    _write(inp, json.dumps([{"x": "1"}]))

    result = CliRunner().invoke(main, ["process", str(inp), "-r", str(rules), "-o", "-"])
    assert result.exit_code != 0
    assert "Unknown rule" in result.output or "Error" in result.output

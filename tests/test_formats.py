import io
import json

from pycloak import Anonymizer
from pycloak.formats import process_csv, process_json, process_ndjson, process_sql


# --- JSON ---------------------------------------------------------------------

def test_json_list():
    a = Anonymizer({"email": "fixed:X"})
    inp = io.StringIO(json.dumps([{"email": "a"}, {"email": "b"}]))
    out = io.StringIO()
    count = process_json(inp, out, a)
    assert count == 2
    assert json.loads(out.getvalue()) == [{"email": "X"}, {"email": "X"}]


def test_json_dict():
    a = Anonymizer({"email": "fixed:X"})
    inp = io.StringIO(json.dumps({"email": "a", "name": "n"}))
    out = io.StringIO()
    process_json(inp, out, a)
    assert json.loads(out.getvalue()) == {"email": "X", "name": "n"}


# --- NDJSON -------------------------------------------------------------------

def test_ndjson_streams_line_by_line():
    a = Anonymizer({"email": "fixed:X"})
    data = '{"email": "a"}\n{"email": "b"}\n\n{"email": "c"}\n'
    out = io.StringIO()
    count = process_ndjson(io.StringIO(data), out, a)
    assert count == 3
    rows = [json.loads(line) for line in out.getvalue().strip().split("\n")]
    assert rows == [{"email": "X"}, {"email": "X"}, {"email": "X"}]


# --- CSV ----------------------------------------------------------------------

def test_csv_roundtrip():
    a = Anonymizer({"email": "fixed:X"})
    src = "name,email\nalice,a@x.com\nbob,b@x.com\n"
    out = io.StringIO()
    count = process_csv(io.StringIO(src), out, a)
    assert count == 2
    lines = out.getvalue().strip().split("\r\n")
    assert lines[0] == "name,email"
    assert lines[1] == "alice,X"
    assert lines[2] == "bob,X"


# --- SQL ----------------------------------------------------------------------

def test_sql_simple_insert():
    a = Anonymizer({"email": "fixed:X"})
    src = "INSERT INTO users (id, email) VALUES (1, 'alice@example.com');"
    out = io.StringIO()
    count = process_sql(io.StringIO(src), out, a)
    assert count == 1
    assert "'X'" in out.getvalue()
    assert "1" in out.getvalue()


def test_sql_multi_row_insert():
    a = Anonymizer({"email": "fixed:X"})
    src = (
        "INSERT INTO `users` (`id`, `email`) VALUES "
        "(1, 'a@x.com'), (2, 'b@x.com'), (3, NULL);"
    )
    out = io.StringIO()
    count = process_sql(io.StringIO(src), out, a)
    assert count == 3
    rendered = out.getvalue()
    assert rendered.count("'X'") == 2
    assert "NULL" in rendered


def test_sql_escaped_quote():
    a = Anonymizer({"name": "fixed:X"})
    src = "INSERT INTO t (id, name) VALUES (1, 'O''Brien');"
    out = io.StringIO()
    process_sql(io.StringIO(src), out, a)
    assert "'X'" in out.getvalue()


def test_sql_passes_through_non_inserts():
    a = Anonymizer({"email": "fixed:X"})
    src = (
        "CREATE TABLE users (id INT, email TEXT);\n"
        "INSERT INTO users (id, email) VALUES (1, 'a@x.com');\n"
    )
    out = io.StringIO()
    process_sql(io.StringIO(src), out, a)
    rendered = out.getvalue()
    assert "CREATE TABLE" in rendered
    assert "'X'" in rendered


def test_sql_handles_numbers_and_null():
    a = Anonymizer({"email": "fixed:X"})
    src = "INSERT INTO t (id, email, score) VALUES (42, 'a@x.com', 3.14);"
    out = io.StringIO()
    process_sql(io.StringIO(src), out, a)
    rendered = out.getvalue()
    assert "42" in rendered
    assert "3.14" in rendered
    assert "'X'" in rendered

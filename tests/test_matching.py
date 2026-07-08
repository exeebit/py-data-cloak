from pycloak import Anonymizer


def test_exact_match():
    a = Anonymizer({"email": "fixed:X"})
    assert a.process_record({"email": "a", "other": "b"}) == {"email": "X", "other": "b"}


def test_glob_match():
    a = Anonymizer({"*_email": "fixed:X"})
    out = a.process_record({"user_email": "a", "admin_email": "b", "name": "Alice"})
    assert out == {"user_email": "X", "admin_email": "X", "name": "Alice"}


def test_regex_match():
    a = Anonymizer({"re:.*_secret$": "redact"})
    out = a.process_record({"api_secret": "k", "shared_secret": "k", "name": "Alice"})
    assert out["api_secret"] == "[REDACTED]"
    assert out["shared_secret"] == "[REDACTED]"
    assert out["name"] == "Alice"


def test_nested_path_exact():
    a = Anonymizer({"user.profile.email": "fixed:X"})
    out = a.process_record({"user": {"profile": {"email": "a", "age": 30}}})
    assert out["user"]["profile"]["email"] == "X"
    assert out["user"]["profile"]["age"] == 30


def test_nested_path_glob():
    a = Anonymizer({"user.*": "fixed:X"})
    out = a.process_record({"user": {"email": "a", "name": "b"}, "other": "keep"})
    assert out == {"user": {"email": "X", "name": "X"}, "other": "keep"}


def test_exact_beats_glob():
    a = Anonymizer({"email": "fixed:exact", "*_email": "fixed:glob"})
    out = a.process_record({"email": "x", "user_email": "y"})
    assert out["email"] == "exact"
    assert out["user_email"] == "glob"


def test_list_of_records():
    a = Anonymizer({"name": "fixed:X"})
    out = a.process_record({"items": [{"name": "a"}, {"name": "b"}]})
    assert out["items"] == [{"name": "X"}, {"name": "X"}]

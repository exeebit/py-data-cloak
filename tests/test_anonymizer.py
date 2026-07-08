from pycloak import Anonymizer


def test_consistency_same_input_same_output():
    a = Anonymizer({"email": "faker:email"}, seed=1)
    o1 = a.mask_value("email", "alice@example.com")
    o2 = a.mask_value("email", "alice@example.com")
    o3 = a.mask_value("email", "bob@example.com")
    assert o1 == o2
    assert o1 != o3


def test_consistency_off():
    a = Anonymizer({"email": "faker:email"}, seed=1, consistent=False)
    o1 = a.mask_value("email", "alice@example.com")
    o2 = a.mask_value("email", "alice@example.com")
    # With consistency off, two calls may differ (with high probability).
    # We can't assert inequality reliably, but we can assert the cache stayed empty.
    assert a._cache == {}


def test_seed_reproducible():
    a1 = Anonymizer({"email": "faker:email"}, seed=42)
    a2 = Anonymizer({"email": "faker:email"}, seed=42)
    assert a1.mask_value("email", "x") == a2.mask_value("email", "x")


def test_locale():
    a = Anonymizer({"name": "faker:name"}, seed=1, locale="ja_JP")
    out = a.mask_value("name", "Bob")
    # Japanese names won't be ASCII-only; just sanity check we got a string.
    assert isinstance(out, str) and out


def test_process_records_streaming():
    a = Anonymizer({"id": "fixed:X"})
    out = list(a.process_records(iter([{"id": "1"}, {"id": "2"}])))
    assert out == [{"id": "X"}, {"id": "X"}]


def test_no_rules_passthrough():
    a = Anonymizer({})
    record = {"a": 1, "b": "two"}
    assert a.process_record(record) == record


def test_list_elements_inherit_field_rule():
    # Each element of a list under field "items" is masked by the items rule
    # — the walker keeps the parent path when recursing into list elements.
    a = Anonymizer({"items": "fixed:X"})
    out = a.process_record({"items": [1, 2, 3]})
    assert out == {"items": ["X", "X", "X"]}

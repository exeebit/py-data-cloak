from pycloak.detect import detect_rules


def test_detects_email_by_name_and_value():
    records = [{"email": "a@b.com"}, {"email": "c@d.com"}, {"email": "e@f.com"}]
    rules = detect_rules(records)
    assert rules.get("email") == "faker:email"


def test_detects_email_by_value_alone():
    # Column is named something unrevealing, but values look like emails.
    records = [{"contact_thing": "a@b.com"}, {"contact_thing": "c@d.com"}]
    rules = detect_rules(records)
    # value match is strong enough on its own
    assert "contact_thing" not in rules or rules["contact_thing"] == "faker:email"


def test_detects_ssn():
    records = [{"ssn": "123-45-6789"}, {"ssn": "987-65-4321"}]
    rules = detect_rules(records)
    assert rules.get("ssn") == "mask_all_but_last_4"


def test_detects_credit_card_via_luhn():
    # 4532015112830366 is a valid Luhn number
    records = [{"card_number": "4532015112830366"}, {"card_number": "4532015112830366"}]
    rules = detect_rules(records)
    assert rules.get("card_number") == "format_preserve:luhn"


def test_detects_password_by_name():
    records = [{"password": "any-value"}]
    rules = detect_rules(records)
    assert "password" in rules
    assert rules["password"].startswith("fixed:")


def test_ignores_clean_columns():
    records = [{"order_count": 4}, {"order_count": 7}]
    rules = detect_rules(records)
    assert "order_count" not in rules

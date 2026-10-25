import pytest

from gatekeeper.ipnet import EntryMatcher, entry_for, normalize_entry


def test_ipv4_is_approved_as_single_address():
    assert entry_for("203.0.113.20") == "203.0.113.20"


def test_ipv6_is_widened_to_its_64():
    assert entry_for("2001:db8:1:2:1234:5678:9abc:def0") == "2001:db8:1:2::/64"
    assert entry_for("2001:db8:1:230::1", ipv6_prefix=56) == "2001:db8:1:200::/56"


def test_invalid_ip_raises():
    with pytest.raises(ValueError):
        entry_for("not-an-ip")


@pytest.mark.parametrize("raw,expected", [
    ("1.2.3.4/32", "1.2.3.4"),
    ("1.2.3.0/24", "1.2.3.0/24"),
    ("2001:DB8:1:2:0000::/64", "2001:db8:1:2::/64"),
    ("2001:db8::1/128", "2001:db8::1"),
    (" 9.9.9.9 ", "9.9.9.9"),
])
def test_normalize_matches_cloudflare_storage(raw, expected):
    assert normalize_entry(raw) == expected


def test_matcher_finds_exact_and_network_entries():
    m = EntryMatcher(["1.2.3.4", "2001:db8:1:2::/64", "10.0.0.0/8"])
    assert m.match("1.2.3.4") == "1.2.3.4"
    assert m.match("2001:db8:1:2:aaaa::5") == "2001:db8:1:2::/64"
    assert m.match("10.9.8.7") == "10.0.0.0/8"
    assert m.match("1.2.3.5") is None
    assert m.match("2001:db8:1:3::1") is None
    assert m.match("garbage") is None

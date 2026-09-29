import pytest

from wol_server import validation as validate
from wol_server.errors import CommandError
from wol_server.protocol import Err


@pytest.mark.parametrize(
    "raw",
    ["aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff", "AABBCCDDEEFF", " aa:bb:cc:dd:ee:ff "],
)
def test_mac_normalization(raw):
    assert validate.mac(raw) == "AA:BB:CC:DD:EE:FF"


@pytest.mark.parametrize("raw", ["", "aa:bb:cc:dd:ee", "gg:bb:cc:dd:ee:ff", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01"])
def test_mac_rejects_invalid_and_multicast(raw):
    with pytest.raises(CommandError) as exc:
        validate.mac(raw)
    assert exc.value.code is Err.INVALID_MAC


@pytest.mark.parametrize("name", ["ab", "a" * 33, "bad name", "zażółć", ""])
def test_username_rules(name):
    with pytest.raises(CommandError):
        validate.username(name)


def test_username_accepts_simple_names():
    assert validate.username("john.doe_1") == "john.doe_1"


@pytest.mark.parametrize("password", ["short", " " * 12, "x" * 129])
def test_password_rules(password):
    with pytest.raises(CommandError) as exc:
        validate.password(password)
    assert exc.value.code is Err.WEAK_PASSWORD


def test_label_normalizes_and_rejects_control_chars():
    assert validate.label("  Biuro PC  ") == "Biuro PC"
    for bad in ["", " ", "x" * 65, "evil\u202eexe", "tab\there"]:
        with pytest.raises(CommandError):
            validate.label(bad)


def test_label_accepts_emoji_joined_with_zwj():
    technologist = "\U0001f468\u200d\U0001f4bb"
    assert validate.label(f"PC {technologist}") == f"PC {technologist}"


def test_email_rules():
    assert validate.email(" a@b.pl ") == "a@b.pl"
    for bad in ["a", "a@b", "a b@c.pl", "x" * 250 + "@b.pl", "a\x00@b.pl", "\ud800@b.cc"]:
        with pytest.raises(CommandError):
            validate.email(bad)


def test_device_id_rules():
    assert validate.device_id("A" * 16) == "A" * 16
    for bad in ["short", "bad id with spaces!", "\x00" * 16]:
        with pytest.raises(CommandError) as exc:
            validate.device_id(bad)
        assert exc.value.code is Err.NOT_FOUND

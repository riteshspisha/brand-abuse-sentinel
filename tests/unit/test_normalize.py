import pytest

from brandsentinel.matching.normalize import InvalidName, canonical_host, normalize


def test_lowercases_and_strips_wildcard_and_trailing_dot():
    n = normalize("*.Sadhguru-Donate.COM.")
    assert n.host == "sadhguru-donate.com"
    assert n.wildcard
    assert n.folded == "sadhgurudonate.com"


def test_punycode_is_decoded_and_skeletonized():
    n = normalize("xn--sadhgur-t2a.com")
    assert n.idn and not n.idn_invalid
    assert n.unicode_host == "sadhgurü.com"
    assert n.skeleton == "sadhguru.com"


def test_unicode_input_is_encoded_to_punycode():
    assert canonical_host("SADHGURÜ.com") == ("xn--sadhgur-t2a.com", False)


@pytest.mark.parametrize(
    ("code_point", "latin"), [(0x0430, "a"), (0x043E, "o"), (0x03B9, "i"), (0x0131, "i")]
)
def test_confusables_map_to_latin(code_point, latin):
    n = normalize("x" + chr(code_point) + "y.com")
    assert n.skeleton == f"x{latin}y.com"


def test_fullwidth_letters_are_folded_by_nfkc():
    n = normalize("".join(chr(0xFF00 + ord(c) - 0x20) for c in "isha") + ".com")
    assert n.skeleton == "isha.com"


@pytest.mark.parametrize(
    "label",
    [
        "xn--99999999999",  # undecodable
        "xn--",  # decodes to nothing
        "xn--a-ecp",  # decodes to text that NFKC turns into a dot
        "xn--abc-",  # decodes to pure ASCII
    ],
)
def test_bad_idn_label_is_kept_raw_and_flagged(label):
    n = normalize(label + ".com")
    assert n.idn_invalid and not n.idn
    assert n.unicode_host == label + ".com"
    assert n.unicode_host.count(".") == 1


def test_invisible_and_bidi_characters_are_removed_from_display_form():
    name = "a" + chr(0x202E) + "b" + chr(0x200D) + "c.com"
    n = normalize(name)
    assert n.unicode_host == "abc.com"
    assert n.host.startswith("xn--")


@pytest.mark.parametrize(
    ("name", "registrable"),
    [
        ("shop.ishalife.com", "ishalife.com"),
        ("a.b.co.in", "b.co.in"),
        ("isha.in.secure-donate.com", "secure-donate.com"),
        ("sadhguru.github.io", "sadhguru.github.io"),  # private suffix: separate owner
        ("co.in", ""),
    ],
)
def test_registrable_domain_uses_bundled_public_suffix_list(name, registrable):
    assert normalize(name).registrable_domain == registrable


def test_underscore_labels_are_accepted():
    assert normalize("_dmarc.example.com").host == "_dmarc.example.com"


@pytest.mark.parametrize(
    "bad",
    ["", ".", "*.", "a b.com", "a..com", "x" * 64 + ".com", ("a" * 60 + ".") * 5 + "com",
     "192.168.0.1", "::1", "a/b.com", "a\nb.com"],
)  # fmt: skip
def test_invalid_names_are_rejected(bad):
    with pytest.raises(InvalidName):
        canonical_host(bad)

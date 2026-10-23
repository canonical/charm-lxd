"""Unit tests for `_normalize_pem` in `src/charm.py`."""

import pytest
from charm import _normalize_pem

# Body of 150 characters: wraps to lines of 64, 64 and 22 characters.
LINE_1 = "A" * 64
LINE_2 = "B" * 64
LINE_3 = "C" * 22
BODY = LINE_1 + LINE_2 + LINE_3

INTERMEDIATE_BODY = "MIIB1TCCAT6gAwIBAgIUQ4h5m" * 3  # 75 characters, wraps to 64 + 11
ROOT_BODY = "MIIC2DCCAcCgAwIBAgIUJk98r" * 2  # 50 characters, single line
KEY_BODY = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg"  # PKCS#8 private key body

SAMPLE_CA_BUNDLE = f"""
-----BEGIN CERTIFICATE-----
{INTERMEDIATE_BODY}
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
{ROOT_BODY}
-----END CERTIFICATE-----
"""


def _block(label: str, *lines: str) -> str:
    return "\n".join([f"-----BEGIN {label}-----", *lines, f"-----END {label}-----"])


def _noisy(body: str) -> str:
    """Split a body into chunks joined by spaces, tabs, CRLF and indentation."""
    chunks = [body[i : i + 16] for i in range(0, len(body), 16)]
    return " \t\r\n  ".join(chunks)


def test_single_block_body_is_wrapped_at_64_columns():
    """Wrap a single-line body at 64 characters."""
    pem = f"-----BEGIN CERTIFICATE-----\n{BODY}\n-----END CERTIFICATE-----\n"

    assert _normalize_pem(pem) == _block("CERTIFICATE", LINE_1, LINE_2, LINE_3) + "\n"


def test_body_of_exactly_64_characters_is_not_split():
    """A body of exactly 64 characters stays on one line."""
    body = "D" * 64
    pem = f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"

    assert _normalize_pem(pem) == _block("CERTIFICATE", body) + "\n"


def test_whitespace_and_crlf_inside_body_are_removed():
    """Spaces, tabs, CRLF and indentation inside the body are dropped before wrapping."""
    pem = f"  -----BEGIN CERTIFICATE-----\r\n{_noisy(BODY)}\r\n-----END CERTIFICATE-----  \r\n"

    assert _normalize_pem(pem) == _block("CERTIFICATE", LINE_1, LINE_2, LINE_3) + "\n"


@pytest.mark.parametrize(
    "label",
    ["CERTIFICATE", "RSA PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY"],
)
def test_label_is_preserved(label):
    """The label of each block is kept, covering PKCS#1, PKCS#8, EC and certificates."""
    pem = f"-----BEGIN {label}-----\n{BODY}\n-----END {label}-----\n"

    assert _normalize_pem(pem) == _block(label, LINE_1, LINE_2, LINE_3) + "\n"


def test_surrounding_whitespace_is_dropped():
    """Blank lines and indentation around a single block are removed."""
    pem = f"\n\n   -----BEGIN PRIVATE KEY-----\n{KEY_BODY}\n-----END PRIVATE KEY-----\n\n\n"

    assert _normalize_pem(pem) == _block("PRIVATE KEY", KEY_BODY) + "\n"


def test_ca_bundle_preserves_every_block_in_order():
    """Intermediate and root certificates are both kept, each wrapped, in input order."""
    expected = (
        _block("CERTIFICATE", INTERMEDIATE_BODY[:64], INTERMEDIATE_BODY[64:])
        + "\n"
        + _block("CERTIFICATE", ROOT_BODY)
        + "\n"
    )

    assert _normalize_pem(SAMPLE_CA_BUNDLE) == expected


def test_certificate_followed_by_key_keeps_both_blocks():
    """A certificate and a private key in one payload are both normalized and kept in order."""
    pem = (
        f"-----BEGIN CERTIFICATE-----\n{_noisy(ROOT_BODY)}\n-----END CERTIFICATE-----\n"
        f"-----BEGIN PRIVATE KEY-----\r\n{_noisy(KEY_BODY)}\r\n-----END PRIVATE KEY-----\r\n"
    )
    expected = _block("CERTIFICATE", ROOT_BODY) + "\n" + _block("PRIVATE KEY", KEY_BODY) + "\n"

    assert _normalize_pem(pem) == expected


def test_text_outside_blocks_is_discarded():
    """Text outside PEM blocks, such as openssl preambles, is dropped when blocks exist."""
    pem = (
        "Bag Attributes\nsubject=CN = example\n"
        f"-----BEGIN CERTIFICATE-----\n{ROOT_BODY}\n-----END CERTIFICATE-----\n"
    )

    assert _normalize_pem(pem) == _block("CERTIFICATE", ROOT_BODY) + "\n"


@pytest.mark.parametrize(
    ("pem", "expected"),
    [
        ("  hello world \n\n", "hello world\n"),
        ("", "\n"),
        ("\n\n", "\n"),
    ],
)
def test_input_without_blocks_is_stripped(pem, expected):
    """Input with no PEM blocks is stripped and newline-terminated."""
    assert _normalize_pem(pem) == expected


@pytest.mark.parametrize(
    "pem",
    [
        "-----BEGIN CERTIFICATE-----\nABC\n",
        "-----BEGIN CERTIFICATE-----\nABC\n-----END PRIVATE KEY-----\n",
    ],
    ids=["unterminated", "mismatched-end-label"],
)
def test_incomplete_block_is_not_treated_as_pem(pem):
    """A BEGIN line without a matching END line is returned as plain text."""
    assert _normalize_pem(pem) == pem


@pytest.mark.parametrize(
    "pem",
    [
        f"  -----BEGIN CERTIFICATE-----\r\n{_noisy(BODY)}\r\n-----END CERTIFICATE-----\r\n",
        SAMPLE_CA_BUNDLE,
    ],
    ids=["single-block", "ca-bundle"],
)
def test_normalization_is_idempotent(pem):
    """Normalizing already-normalized output does not change it."""
    once = _normalize_pem(pem)

    assert _normalize_pem(once) == once

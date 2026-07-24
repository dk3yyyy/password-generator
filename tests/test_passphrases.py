import math
from pathlib import Path

import pytest

from passphrases import (
    BUILTIN_WORDLIST,
    BUILTIN_WORDLIST_PATH,
    calculate_passphrase_entropy,
    load_wordlist,
)


def test_bundled_eff_wordlist_has_expected_integrity():
    assert BUILTIN_WORDLIST_PATH.name == "eff_large_wordlist.txt"
    assert len(BUILTIN_WORDLIST) == 7776
    assert len(set(BUILTIN_WORDLIST)) == 7776
    assert BUILTIN_WORDLIST[0] == "abacus"
    assert BUILTIN_WORDLIST[-1] == "zoom"


def test_bundled_wordlist_is_cached():
    assert load_wordlist() is load_wordlist()


def test_load_wordlist_rejects_duplicates(tmp_path: Path):
    path = tmp_path / "duplicate.txt"
    path.write_text("alpha\nalpha\n")

    with pytest.raises(ValueError, match="duplicate words"):
        load_wordlist(path, expected_count=2)


def test_load_wordlist_rejects_unexpected_size(tmp_path: Path):
    path = tmp_path / "short.txt"
    path.write_text("alpha\nbeta\n")

    with pytest.raises(ValueError, match="expected 3 words, found 2"):
        load_wordlist(path, expected_count=3)


def test_passphrase_entropy_uses_word_count_not_character_count():
    assert calculate_passphrase_entropy(6, 7776) == pytest.approx(
        6 * math.log2(7776)
    )


def test_random_number_suffix_adds_one_hundred_uniform_choices():
    assert calculate_passphrase_entropy(6, 7776, number_choices=100) == pytest.approx(
        (6 * math.log2(7776)) + math.log2(100)
    )


@pytest.mark.parametrize(
    ("word_count", "pool_size", "number_choices"),
    [(0, 7776, 1), (6, 0, 1), (6, 7776, 0)],
)
def test_passphrase_entropy_rejects_non_positive_inputs(
    word_count, pool_size, number_choices
):
    with pytest.raises(ValueError, match="must be positive"):
        calculate_passphrase_entropy(word_count, pool_size, number_choices)

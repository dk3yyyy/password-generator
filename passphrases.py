"""Shared passphrase wordlist loading and entropy calculation."""

from functools import lru_cache
import math
from pathlib import Path

EXPECTED_BUILTIN_WORD_COUNT = 7776
BUILTIN_WORDLIST_PATH = (
    Path(__file__).resolve().parent / "wordlists" / "eff_large_wordlist.txt"
)


@lru_cache(maxsize=None)
def load_wordlist(
    path: Path | str = BUILTIN_WORDLIST_PATH,
    expected_count: int = EXPECTED_BUILTIN_WORD_COUNT,
) -> tuple[str, ...]:
    """Load and validate a one-word-per-line passphrase wordlist once."""
    wordlist_path = Path(path)
    words = tuple(
        line.strip()
        for line in wordlist_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    )

    if len(words) != expected_count:
        raise ValueError(
            f"Invalid wordlist: expected {expected_count} words, found {len(words)}"
        )
    if len(set(words)) != len(words):
        raise ValueError("Invalid wordlist: duplicate words found")
    if any(
        word != word.lower()
        or not word.isascii()
        or not word.replace("-", "").isalpha()
        for word in words
    ):
        raise ValueError("Invalid wordlist: entries must be lowercase ASCII words")

    return words


def calculate_passphrase_entropy(
    word_count: int,
    pool_size: int,
    number_choices: int = 1,
) -> float:
    """Return entropy from independent word and optional suffix choices."""
    if word_count <= 0 or pool_size <= 0 or number_choices <= 0:
        raise ValueError("Entropy inputs must be positive")
    return (word_count * math.log2(pool_size)) + math.log2(number_choices)


BUILTIN_WORDLIST = load_wordlist()

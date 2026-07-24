"""Shared cryptographically secure random-password generation and entropy."""

from itertools import combinations
import math
import secrets
import string

AMBIGUOUS_CHARS = frozenset("0O1lI")


def _selected_character_sets(
    use_upper: bool,
    use_lower: bool,
    use_digits: bool,
    use_symbols: bool,
    no_ambiguous: bool = False,
    exclude_chars: str = "",
) -> tuple[str, ...]:
    requested = (
        ("uppercase", string.ascii_uppercase, use_upper),
        ("lowercase", string.ascii_lowercase, use_lower),
        ("digits", string.digits, use_digits),
        ("symbols", string.punctuation, use_symbols),
    )
    selected = [(name, chars) for name, chars, enabled in requested if enabled]
    if not selected:
        raise ValueError("At least one character type must be selected")

    excluded = set(exclude_chars)
    character_sets = []
    for name, chars in selected:
        if no_ambiguous:
            chars = "".join(char for char in chars if char not in AMBIGUOUS_CHARS)
        if excluded:
            chars = "".join(char for char in chars if char not in excluded)
        if not chars:
            raise ValueError(
                f"Selected {name} character set is empty after exclusions"
            )
        character_sets.append(chars)

    return tuple(character_sets)


def _validate_length(length: int, character_sets: tuple[str, ...]) -> None:
    if length < len(character_sets):
        raise ValueError("Length too short for selected character types")


def generate_password(
    length: int,
    use_upper: bool,
    use_lower: bool,
    use_digits: bool,
    use_symbols: bool,
    no_ambiguous: bool = False,
    exclude_chars: str = "",
) -> tuple[str, int]:
    """Generate uniformly from passwords containing every selected type.

    Independent candidates are sampled from the complete character pool and
    rejected until every requested character type appears. Conditional on
    acceptance, every valid password has the same probability.
    """
    character_sets = _selected_character_sets(
        use_upper,
        use_lower,
        use_digits,
        use_symbols,
        no_ambiguous,
        exclude_chars,
    )
    _validate_length(length, character_sets)
    character_pool = "".join(character_sets)

    while True:
        password = "".join(secrets.choice(character_pool) for _ in range(length))
        contains_every_type = all(
            any(char in character_set for char in password)
            for character_set in character_sets
        )
        if contains_every_type:
            return password, len(character_pool)


def calculate_password_entropy(
    length: int,
    use_upper: bool,
    use_lower: bool,
    use_digits: bool,
    use_symbols: bool,
    no_ambiguous: bool = False,
    exclude_chars: str = "",
) -> float:
    """Return log2 of the exact valid-password sample space.

    Inclusion-exclusion removes strings missing one or more requested character
    types. This matches ``generate_password``'s uniform rejection sampling.
    """
    character_sets = _selected_character_sets(
        use_upper,
        use_lower,
        use_digits,
        use_symbols,
        no_ambiguous,
        exclude_chars,
    )
    _validate_length(length, character_sets)
    pool_size = sum(len(character_set) for character_set in character_sets)

    valid_passwords = 0
    for missing_count in range(len(character_sets) + 1):
        for missing_sets in combinations(character_sets, missing_count):
            available = pool_size - sum(len(chars) for chars in missing_sets)
            term = available**length
            valid_passwords += term if missing_count % 2 == 0 else -term

    return math.log2(valid_passwords)

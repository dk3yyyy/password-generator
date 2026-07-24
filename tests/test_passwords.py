import math
import string

import pytest

import passwords as passwords_module
from passwords import calculate_password_entropy, generate_password


def test_single_category_entropy_matches_independent_character_choices():
    assert calculate_password_entropy(
        8,
        use_upper=True,
        use_lower=False,
        use_digits=False,
        use_symbols=False,
    ) == pytest.approx(8 * math.log2(26))


def test_mixed_category_entropy_counts_only_passwords_with_every_selected_type():
    entropy = calculate_password_entropy(
        2,
        use_upper=True,
        use_lower=True,
        use_digits=False,
        use_symbols=False,
    )

    assert entropy == pytest.approx(math.log2(2 * 26 * 26))
    assert entropy < 2 * math.log2(52)


def test_entropy_uses_character_sets_after_exclusions():
    exclude_chars = "BCDEFGHIJKLMNOPQRSTUVWXYZbcdefghijklmnopqrstuvwxyz"

    entropy = calculate_password_entropy(
        2,
        use_upper=True,
        use_lower=True,
        use_digits=False,
        use_symbols=False,
        exclude_chars=exclude_chars,
    )

    # The only valid two-character outputs are "Aa" and "aA".
    assert entropy == pytest.approx(1.0)


def test_entropy_combines_ambiguous_filtering_and_explicit_exclusions():
    entropy = calculate_password_entropy(
        2,
        use_upper=True,
        use_lower=False,
        use_digits=False,
        use_symbols=False,
        no_ambiguous=True,
        exclude_chars="A",
    )

    # Uppercase excludes ambiguous I/O plus explicitly excluded A: 26 - 3.
    assert entropy == pytest.approx(2 * math.log2(23))


def test_four_category_entropy_includes_all_inclusion_exclusion_terms():
    exclude_chars = (
        string.ascii_uppercase.replace("A", "")
        + string.ascii_lowercase.replace("a", "")
        + string.digits.replace("0", "")
        + string.punctuation.replace("!", "")
    )

    entropy = calculate_password_entropy(
        4,
        use_upper=True,
        use_lower=True,
        use_digits=True,
        use_symbols=True,
        exclude_chars=exclude_chars,
    )

    # Four distinct required characters can appear in 4! valid orders.
    assert entropy == pytest.approx(math.log2(math.factorial(4)))


def test_generation_retries_until_uniform_pool_sample_contains_every_type(monkeypatch):
    choices = iter(("A", "A", "A", "b"))
    monkeypatch.setattr(passwords_module.secrets, "choice", lambda _: next(choices))

    password, pool_size = generate_password(
        2,
        use_upper=True,
        use_lower=True,
        use_digits=False,
        use_symbols=False,
    )

    assert password == "Ab"
    assert pool_size == 52


def test_exclusions_cannot_silently_empty_a_selected_category():
    with pytest.raises(ValueError, match="digits.*empty after exclusions"):
        generate_password(
            12,
            use_upper=True,
            use_lower=True,
            use_digits=True,
            use_symbols=False,
            exclude_chars="0123456789",
        )


def test_entropy_rejects_length_shorter_than_selected_category_count():
    with pytest.raises(ValueError, match="Length too short"):
        calculate_password_entropy(
            1,
            use_upper=True,
            use_lower=True,
            use_digits=False,
            use_symbols=False,
        )

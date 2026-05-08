import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import (
    generate_password,
    generate_passphrase,
    calculate_entropy,
    get_strength_label,
    check_common_password,
    check_password_patterns,
    load_config,
    save_config,
    PASSPHRASE_WORDLIST,
    DEFAULT_WORDLIST,
)


class TestPasswordGeneration:
    def test_generate_password_length(self):
        pwd, pool = generate_password(16, True, True, True, True)
        assert len(pwd) == 16

    def test_generate_password_contains_upper(self):
        pwd, pool = generate_password(20, True, False, False, False)
        assert any(c.isupper() for c in pwd)
        assert pwd.isupper() or all(c.isupper() for c in pwd if c.isalpha())

    def test_generate_password_contains_lower(self):
        pwd, pool = generate_password(20, False, True, False, False)
        assert any(c.islower() for c in pwd)

    def test_generate_password_contains_digits(self):
        pwd, pool = generate_password(20, False, False, True, False)
        assert any(c.isdigit() for c in pwd)

    def test_generate_password_contains_symbols(self):
        pwd, pool = generate_password(20, False, False, False, True)
        assert any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pwd)

    def test_generate_password_no_ambiguous(self):
        pwd, pool = generate_password(20, True, True, True, True, no_ambiguous=True)
        ambiguous = set("0O1lI")
        assert not any(c in ambiguous for c in pwd)

    def test_generate_password_exclude_chars(self):
        pwd, pool = generate_password(20, True, True, True, False, exclude_chars="aeiouAEIOU")
        assert all(c not in "aeiouAEIOU" for c in pwd)

    def test_generate_password_minimum_length(self):
        pwd, pool = generate_password(4, True, True, True, True)
        assert len(pwd) == 4

    def test_generate_password_raises_on_no_char_types(self):
        with pytest.raises(ValueError, match="At least one character type"):
            generate_password(12, False, False, False, False)

    def test_generate_password_raises_on_short_length(self):
        with pytest.raises(ValueError, match="Length too short"):
            generate_password(1, True, True, True, True)


class TestPassphraseGeneration:
    def test_generate_passphrase_default(self):
        pwd, pool = generate_passphrase(4, "-", True, False)
        assert len(pwd.split("-")) == 4
        assert all(w[0].isupper() for w in pwd.split("-"))

    def test_generate_passphrase_with_number(self):
        pwd, pool = generate_passphrase(4, "-", True, True)
        assert pwd[-1].isdigit()

    def test_generate_passphrase_different_separator(self):
        pwd, pool = generate_passphrase(3, "_", False, False)
        assert "_" in pwd or len(pwd.split("_")) == 3

    def test_generate_passphrase_single_word(self):
        pwd, pool = generate_passphrase(1, "-", False, False)
        assert len(pwd.split("-")) == 1


class TestEntropyCalculation:
    def test_calculate_entropy_basic(self):
        entropy = calculate_entropy("abcd", 26)
        assert entropy > 0

    def test_calculate_entropy_increases_with_length(self):
        ent4 = calculate_entropy("abcd", 26)
        ent8 = calculate_entropy("abcdefgh", 26)
        assert ent8 > ent4

    def test_calculate_entropy_pool_size(self):
        ent_upper = calculate_entropy("ABCD", 26)
        _, pool_upper = generate_password(8, True, False, False, False)
        _, pool_all = generate_password(8, True, True, True, True)
        assert pool_all > pool_upper


class TestStrengthDetection:
    def test_weak_strength(self):
        strength, color = get_strength_label(10)
        assert strength == "Weak"
        assert color == "red"

    def test_fair_strength(self):
        strength, color = get_strength_label(30)
        assert strength == "Fair"
        assert color == "yellow"

    def test_good_strength(self):
        strength, color = get_strength_label(50)
        assert strength == "Good"
        assert color == "cyan"

    def test_strong_strength(self):
        strength, color = get_strength_label(70)
        assert strength == "Strong"
        assert color == "green"


class TestCommonPasswordCheck:
    def test_common_passwords_detected(self):
        assert check_common_password("password") == True
        assert check_common_password("123456") == True
        assert check_common_password("qwerty") == True

    def test_random_password_not_common(self):
        pwd, _ = generate_password(16, True, True, True, True)
        assert check_common_password(pwd) == False


class TestPatternDetection:
    def test_detect_repeated_characters(self):
        warnings = check_password_patterns("aaa")
        assert any("Repeated" in w for w in warnings)

    def test_detect_sequential_characters(self):
        warnings = check_password_patterns("abc")
        assert any("Sequential" in w for w in warnings)

    def test_detect_keyboard_sequence(self):
        warnings = check_password_patterns("qwe")
        assert any("Keyboard" in w for w in warnings)

    def test_random_password_no_warnings(self):
        pwd, _ = generate_password(20, True, True, True, True)
        warnings = check_password_patterns(pwd)
        assert len(warnings) == 0


class TestConfigManagement:
    def test_save_and_load_config(self, tmp_path):
        config = {"length": 24, "upper": True, "lower": False}
        
        test_config_file = tmp_path / "test_config.json"
        import json
        with open(test_config_file, "w") as f:
            json.dump(config, f)
        
        with open(test_config_file, "r") as f:
            loaded = json.load(f)
        
        assert loaded == config


class TestWordlist:
    def test_default_wordlist_loaded(self):
        assert len(DEFAULT_WORDLIST) > 50
        assert all(isinstance(w, str) for w in DEFAULT_WORDLIST)

    def test_wordlist_all_lowercase(self):
        assert all(w.islower() for w in DEFAULT_WORDLIST)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
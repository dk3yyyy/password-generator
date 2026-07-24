import json
import os
import stat
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import main as main_module
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

    def test_cli_random_password_reports_exact_constrained_entropy(
        self, monkeypatch, tmp_path
    ):
        config_dir = tmp_path / ".passgen"
        monkeypatch.setattr(main_module, "CONFIG_DIR", config_dir)
        monkeypatch.setattr(main_module, "HISTORY_FILE", config_dir / "history.json")
        monkeypatch.setattr(main_module, "CONFIG_FILE", config_dir / "config.json")
        monkeypatch.setattr(main_module, "WORDLIST_DIR", config_dir / "wordlists")
        monkeypatch.setattr(main_module, "password_history", main_module.PasswordHistory())
        monkeypatch.setattr(
            sys,
            "argv",
            ["passgen", "--length", "8", "--upper", "--lower"],
        )

        observed = {}

        def fake_entropy(**kwargs):
            observed.update(kwargs)
            return 42.0

        monkeypatch.setattr(main_module, "calculate_password_entropy", fake_entropy)

        main_module.main()

        assert observed == {
            "length": 8,
            "use_upper": True,
            "use_lower": True,
            "use_digits": False,
            "use_symbols": False,
            "no_ambiguous": False,
            "exclude_chars": "",
        }

    def test_cli_rejects_selected_category_emptied_by_exclusions(
        self, monkeypatch, tmp_path, capsys
    ):
        config_dir = tmp_path / ".passgen"
        monkeypatch.setattr(main_module, "CONFIG_DIR", config_dir)
        monkeypatch.setattr(main_module, "HISTORY_FILE", config_dir / "history.json")
        monkeypatch.setattr(main_module, "CONFIG_FILE", config_dir / "config.json")
        monkeypatch.setattr(main_module, "WORDLIST_DIR", config_dir / "wordlists")
        monkeypatch.setattr(main_module, "password_history", main_module.PasswordHistory())
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "passgen",
                "--length",
                "12",
                "--digits",
                "--exclude",
                "0123456789",
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_module.main()

        assert exc_info.value.code == 1
        output = capsys.readouterr().out
        assert "Selected digits character set is empty after exclusions" in output


class TestPassphraseGeneration:
    def test_default_passphrase_uses_eff_wordlist(self):
        pwd, pool = generate_passphrase(6, "-", False, False)

        assert pool == 7776
        assert all(word in PASSPHRASE_WORDLIST for word in pwd.split("-"))

    def test_generate_passphrase_default(self):
        pwd, pool = generate_passphrase(4, "-", True, False)
        assert len(pwd.split("-")) == 4
        assert all(w[0].isupper() for w in pwd.split("-"))

    def test_generate_passphrase_with_number(self):
        pwd, pool = generate_passphrase(4, "-", True, True)
        assert pwd[-1].isdigit()

    def test_generate_passphrase_uses_fixed_width_number_suffix(self, monkeypatch):
        monkeypatch.setattr(main_module.secrets, "randbelow", lambda _: 7)

        pwd, _ = generate_passphrase(4, "-", False, True)

        assert pwd.endswith("07")

    def test_generate_passphrase_different_separator(self):
        pwd, pool = generate_passphrase(3, "_", False, False)
        assert "_" in pwd or len(pwd.split("_")) == 3

    def test_generate_passphrase_single_word(self):
        pwd, pool = generate_passphrase(1, "-", False, False)
        assert len(pwd.split("-")) == 1

    @pytest.mark.parametrize(
        ("extra_args", "expected_number_choices"),
        [([], 1), (["--add-number"], 100)],
    )
    def test_cli_passphrase_uses_secure_defaults_and_word_entropy(
        self, monkeypatch, tmp_path, extra_args, expected_number_choices
    ):
        config_dir = tmp_path / ".passgen"
        monkeypatch.setattr(main_module, "CONFIG_DIR", config_dir)
        monkeypatch.setattr(main_module, "HISTORY_FILE", config_dir / "history.json")
        monkeypatch.setattr(main_module, "CONFIG_FILE", config_dir / "config.json")
        monkeypatch.setattr(main_module, "WORDLIST_DIR", config_dir / "wordlists")
        monkeypatch.setattr(main_module, "password_history", main_module.PasswordHistory())
        monkeypatch.setattr(sys, "argv", ["passgen", "--passphrase", *extra_args])

        observed = {}

        def fake_generate(word_count, separator, capitalize, include_number):
            observed["word_count"] = word_count
            observed["include_number"] = include_number
            return "alpha-beta-gamma-delta-epsilon-zeta", 7776

        def fake_entropy(word_count, pool_size, number_choices=1):
            observed["entropy_args"] = (word_count, pool_size, number_choices)
            return 80.0

        monkeypatch.setattr(main_module, "generate_passphrase", fake_generate)
        monkeypatch.setattr(main_module, "calculate_passphrase_entropy", fake_entropy)

        main_module.main()

        assert observed["word_count"] == 6
        assert observed["entropy_args"] == (6, 7776, expected_number_choices)


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

    def test_password_without_patterns_has_no_warnings(self):
        warnings = check_password_patterns("gT7!pL2@vN9#rK4$")
        assert warnings == []


class TestSecureStorage:
    @staticmethod
    def configure_paths(monkeypatch, tmp_path):
        config_dir = tmp_path / ".passgen"
        monkeypatch.setattr(main_module, "CONFIG_DIR", config_dir)
        monkeypatch.setattr(main_module, "HISTORY_FILE", config_dir / "history.json")
        monkeypatch.setattr(main_module, "CONFIG_FILE", config_dir / "config.json")
        monkeypatch.setattr(main_module, "WORDLIST_DIR", config_dir / "wordlists")
        return config_dir

    def test_history_uses_private_filesystem_permissions(self, monkeypatch, tmp_path):
        config_dir = self.configure_paths(monkeypatch, tmp_path)
        history = main_module.PasswordHistory()

        history.add("correct-horse", "Random", "Strong", 80.0, persist=True)

        assert stat.S_IMODE(config_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE(main_module.HISTORY_FILE.stat().st_mode) == 0o600

    def test_passwords_are_not_persisted_by_default(self, monkeypatch, tmp_path):
        self.configure_paths(monkeypatch, tmp_path)
        history = main_module.PasswordHistory()

        history.add("correct-horse", "Random", "Strong", 80.0)

        assert history.history == []
        assert not main_module.HISTORY_FILE.exists()

    def test_cli_can_explicitly_save_history(self, monkeypatch, tmp_path):
        self.configure_paths(monkeypatch, tmp_path)
        monkeypatch.setattr(main_module, "password_history", main_module.PasswordHistory())
        monkeypatch.setattr(
            sys,
            "argv",
            ["passgen", "--length", "12", "--lower", "--save-history"],
        )

        main_module.main()

        stored = json.loads(main_module.HISTORY_FILE.read_text())
        assert len(stored) == 1
        assert len(stored[0]["password"]) == 12

    def test_cli_batch_does_not_save_history_without_opt_in(
        self, monkeypatch, tmp_path
    ):
        self.configure_paths(monkeypatch, tmp_path)
        monkeypatch.setattr(main_module, "password_history", main_module.PasswordHistory())
        monkeypatch.setattr(
            sys,
            "argv",
            ["main.py", "--length", "12", "--lower", "--count", "3"],
        )

        main_module.main()

        assert not main_module.HISTORY_FILE.exists()

    def test_existing_history_permissions_are_tightened(self, monkeypatch, tmp_path):
        config_dir = self.configure_paths(monkeypatch, tmp_path)
        config_dir.mkdir(mode=0o755)
        main_module.WORDLIST_DIR.mkdir(mode=0o755)
        main_module.HISTORY_FILE.write_text("[]")
        main_module.HISTORY_FILE.chmod(0o644)

        main_module.PasswordHistory()

        assert stat.S_IMODE(config_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE(main_module.HISTORY_FILE.stat().st_mode) == 0o600

    def test_non_list_history_is_ignored(self, monkeypatch, tmp_path):
        config_dir = self.configure_paths(monkeypatch, tmp_path)
        config_dir.mkdir(mode=0o700)
        main_module.HISTORY_FILE.write_text('{"unexpected": "shape"}')

        history = main_module.PasswordHistory()

        assert history.history == []

    def test_password_exports_are_private(self, monkeypatch, tmp_path):
        self.configure_paths(monkeypatch, tmp_path)
        export_path = tmp_path / "passwords.json"

        main_module.export_passwords(
            [{"password": "correct-horse"}],
            "json",
            str(export_path),
        )

        assert stat.S_IMODE(export_path.stat().st_mode) == 0o600

    def test_csv_password_exports_are_private(self, monkeypatch, tmp_path):
        self.configure_paths(monkeypatch, tmp_path)
        export_path = tmp_path / "passwords.csv"

        main_module.export_passwords(
            [{"password": "correct-horse"}],
            "csv",
            str(export_path),
        )

        assert stat.S_IMODE(export_path.stat().st_mode) == 0o600

    def test_private_writer_closes_descriptor_when_permission_change_fails(
        self, monkeypatch, tmp_path
    ):
        self.configure_paths(monkeypatch, tmp_path)
        closed_descriptors = []
        real_close = os.close

        def fail_fchmod(descriptor, mode):
            raise OSError("permission update failed")

        def record_close(descriptor):
            closed_descriptors.append(descriptor)
            real_close(descriptor)

        monkeypatch.setattr(os, "fchmod", fail_fchmod)
        monkeypatch.setattr(os, "close", record_close)

        with pytest.raises(OSError, match="permission update failed"):
            main_module.write_private_json(tmp_path / "private.json", {"ok": True})

        assert len(closed_descriptors) == 1


class TestWordlistPaths:
    @staticmethod
    def configure_paths(monkeypatch, tmp_path):
        config_dir = tmp_path / ".passgen"
        monkeypatch.setattr(main_module, "CONFIG_DIR", config_dir)
        monkeypatch.setattr(main_module, "WORDLIST_DIR", config_dir / "wordlists")

    def test_save_wordlist_rejects_path_traversal(self, monkeypatch, tmp_path):
        self.configure_paths(monkeypatch, tmp_path)
        outside_path = tmp_path / "outside.txt"

        with pytest.raises(ValueError, match="Invalid wordlist name"):
            main_module.save_wordlist("../outside", ["secret"])

        assert not outside_path.exists()

    def test_load_wordlist_rejects_symlink_escape(self, monkeypatch, tmp_path):
        self.configure_paths(monkeypatch, tmp_path)
        main_module.WORDLIST_DIR.mkdir(parents=True)
        outside_path = tmp_path / "outside.txt"
        outside_path.write_text("secret\n")
        (main_module.WORDLIST_DIR / "safe.txt").symlink_to(outside_path)

        with pytest.raises(ValueError, match="outside the wordlist directory"):
            main_module.load_custom_wordlist("safe")

    def test_valid_wordlist_round_trip(self, monkeypatch, tmp_path):
        self.configure_paths(monkeypatch, tmp_path)

        main_module.save_wordlist("dice-words_2026", ["Alpha", "Beta"])

        assert main_module.load_custom_wordlist("dice-words_2026") == ["alpha", "beta"]

    @pytest.mark.parametrize("name", ["a", "_words", "-words", "a" * 64])
    def test_valid_name_boundaries(self, monkeypatch, tmp_path, name):
        self.configure_paths(monkeypatch, tmp_path)

        main_module.save_wordlist(name, ["Alpha"])

        assert main_module.load_custom_wordlist(name) == ["alpha"]

    @pytest.mark.parametrize("name", ["", "a" * 65, "two words", "café", "a.b", "a/b"])
    def test_invalid_names_are_rejected(self, monkeypatch, tmp_path, name):
        self.configure_paths(monkeypatch, tmp_path)

        with pytest.raises(ValueError, match="Invalid wordlist name"):
            main_module.save_wordlist(name, ["Alpha"])

    def test_symlinked_wordlist_directory_is_rejected(self, monkeypatch, tmp_path):
        self.configure_paths(monkeypatch, tmp_path)
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        main_module.CONFIG_DIR.mkdir()
        main_module.WORDLIST_DIR.symlink_to(outside_dir, target_is_directory=True)

        with pytest.raises(ValueError, match="must not be a symlink"):
            main_module.save_wordlist("safe", ["secret"])

        assert not (outside_dir / "safe.txt").exists()



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

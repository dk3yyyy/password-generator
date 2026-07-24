import argparse
import secrets
import string
import random
import subprocess
import sys
import math
import os
import json
from contextlib import contextmanager
from pathlib import Path
from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box
from datetime import datetime

CONFIG_DIR = Path.home() / ".passgen"
HISTORY_FILE = CONFIG_DIR / "history.json"
CONFIG_FILE = CONFIG_DIR / "config.json"
WORDLIST_DIR = CONFIG_DIR / "wordlists"

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
    "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
    "ashley", "bailey", "passw0rd", "shadow", "123123", "654321", "superman",
    "qazwsx", "michael", "football", "password1", "password123", "welcome",
    "hello", "admin", "login", "pass", "test", "guest", "demo", "changeme"
}

custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "red bold",
    "success": "green bold",
    "password": "bold magenta",
})

console = Console(theme=custom_theme)
AMBIGUOUS_CHARS = set("0O1lI")

DEFAULT_WORDLIST = [
    "apple", "banana", "cherry", "dragon", "eagle", "forest", "garden", "harbor",
    "island", "jungle", "knight", "lemon", "mountain", "night", "ocean", "planet",
    "quiet", "river", "sunset", "thunder", "umbrella", "volcano", "winter", "yellow",
    "zebra", "anchor", "breeze", "castle", "diamond", "ember", "falcon", "glacier",
    "harmony", "ivory", "jasmine", "kingdom", "lantern", "marble", "nebula", "orchid",
    "phoenix", "quartz", "rainbow", "silver", "tiger", "unicorn", "velvet", "willow",
    "xenon", "yacht", "azure", "bronze", "copper", "dawn", "echo", "frost",
    "golden", "horizon", "iris", "jade", "karma", "lotus", "mystic", "nectar",
    "opal", "pearl", "quest", "ruby", "storm", "topaz", "ultra", "vivid",
    "whisper", "xray", "zenith", "amber", "blaze", "cloud", "dream", "energy",
    "flare", "glow", "halo", "ink", "joy", "kindle", "light", "mist",
    "nova", "orbit", "prism", "ray", "spark", "trail", "unity", "vapor",
    "wave", "xerox", "yonder", "zest"
]

PASSPHRASE_WORDLIST = DEFAULT_WORDLIST

VERSION = "1.0.0"


def check_password_patterns(password: str) -> list[str]:
    warnings = []
    lower = password.lower()

    for i in range(len(password) - 2):
        if password[i] == password[i+1] == password[i+2]:
            warnings.append("Repeated character found")
            break

    sequences = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    for seq in sequences:
        for i in range(len(password) - 2):
            chunk = password[i:i+3]
            for j in range(len(seq) - 2):
                if chunk == seq[j:j+3] or chunk == seq[j:j+3][::-1]:
                    warnings.append("Sequential characters found")
                    break
            if warnings and warnings[-1] == "Sequential characters found":
                break
        if warnings and "Sequential" in warnings[-1]:
            break

    keyboard_rows = [
        "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "qwertzuiop", "asdfghjkl", "yxcvbnm"
    ]
    for row in keyboard_rows:
        for i in range(len(lower) - 2):
            chunk = lower[i:i+3]
            for j in range(len(row) - 2):
                if chunk == row[j:j+3]:
                    warnings.append("Keyboard sequence found")
                    break
            if warnings and "Keyboard" in warnings[-1]:
                break
        if warnings and "Keyboard" in warnings[-1]:
            break

    return warnings


def ensure_config_dir():
    CONFIG_DIR.mkdir(mode=0o700, exist_ok=True)
    WORDLIST_DIR.mkdir(mode=0o700, exist_ok=True)
    CONFIG_DIR.chmod(0o700)
    WORDLIST_DIR.chmod(0o700)


@contextmanager
def open_private_text(path: Path, *, newline=None):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", newline=newline) as file:
            descriptor = None
            yield file
    finally:
        if descriptor is not None:
            os.close(descriptor)


def write_private_json(path: Path, data) -> None:
    ensure_config_dir()
    with open_private_text(path) as file:
        json.dump(data, file, indent=2)


def load_config() -> dict:
    if not CONFIG_FILE.exists():
        return {}
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def save_config(config: dict):
    ensure_config_dir()
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def wordlist_path(name: str) -> Path:
    valid_characters = string.ascii_letters + string.digits + "_-"
    if (
        not isinstance(name, str)
        or not 1 <= len(name) <= 64
        or any(character not in valid_characters for character in name)
    ):
        raise ValueError(
            "Invalid wordlist name: use 1-64 ASCII letters, numbers, hyphens, or underscores"
        )
    if WORDLIST_DIR.is_symlink():
        raise ValueError("Wordlist directory must not be a symlink")
    path = WORDLIST_DIR / f"{name}.txt"
    if path.resolve(strict=False).parent != WORDLIST_DIR.resolve():
        raise ValueError("Wordlist path resolves outside the wordlist directory")
    return path


def load_custom_wordlist(name: str) -> list[str]:
    path = wordlist_path(name)
    if not path.exists():
        raise ValueError(f"Wordlist '{name}' not found")
    with open(path) as f:
        words = [w.strip().lower() for w in f if w.strip()]
    if not words:
        raise ValueError(f"Wordlist '{name}' is empty")
    return words


def save_wordlist(name: str, words: list[str]):
    path = wordlist_path(name)
    ensure_config_dir()
    with open(path, "w") as f:
        f.write("\n".join(words))


def list_wordlists() -> list[str]:
    if not WORDLIST_DIR.exists():
        return []
    return [f.stem for f in WORDLIST_DIR.glob("*.txt")]


def check_common_password(password: str) -> bool:
    return password.lower() in COMMON_PASSWORDS


def export_passwords(passwords: list[dict], format: str, filepath: str):
    ensure_config_dir()
    if format == "json":
        write_private_json(Path(filepath), passwords)
    elif format == "csv":
        import csv
        path = Path(filepath)
        with open_private_text(path, newline="") as f:
            if passwords:
                writer = csv.DictWriter(f, fieldnames=passwords[0].keys())
                writer.writeheader()
                writer.writerows(passwords)


def calculate_entropy(password: str, pool_size: int) -> float:
    if pool_size == 0:
        return 0.0
    return len(password) * math.log2(pool_size)


def get_strength_label(entropy: float) -> tuple[str, str]:
    if entropy < 25:
        return "Weak", "red"
    elif entropy < 45:
        return "Fair", "yellow"
    elif entropy < 60:
        return "Good", "cyan"
    else:
        return "Strong", "green"


def generate_password(
    length: int,
    use_upper: bool,
    use_lower: bool,
    use_digits: bool,
    use_symbols: bool,
    no_ambiguous: bool = False,
    exclude_chars: str = ""
) -> tuple[str, int]:
    required_chars = []
    char_sets = []

    if use_upper:
        chars = string.ascii_uppercase
        if no_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARS)
        char_sets.append(chars)
        if chars:
            required_chars.append(secrets.choice(chars))

    if use_lower:
        chars = string.ascii_lowercase
        if no_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARS)
        char_sets.append(chars)
        if chars:
            required_chars.append(secrets.choice(chars))

    if use_digits:
        chars = string.digits
        if no_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARS)
        char_sets.append(chars)
        if chars:
            required_chars.append(secrets.choice(chars))

    if use_symbols:
        char_sets.append(string.punctuation)
        required_chars.append(secrets.choice(string.punctuation))

    if not char_sets:
        raise ValueError("At least one character type must be selected")

    char_pool = "".join(char_sets)

    if exclude_chars:
        char_pool = "".join(c for c in char_pool if c not in exclude_chars)
        required_chars = [c for c in required_chars if c not in exclude_chars]

    if not char_pool:
        raise ValueError("No characters available in pool after exclusions")

    if length < len(required_chars):
        raise ValueError("Length too short for selected character types")

    password_chars = required_chars + [secrets.choice(char_pool) for _ in range(length - len(required_chars))]

    random.SystemRandom().shuffle(password_chars)

    return "".join(password_chars), len(char_pool)


def generate_passphrase(
    word_count: int,
    separator: str,
    capitalize: bool,
    include_number: bool
) -> tuple[str, int]:
    if word_count < 1:
        raise ValueError("Word count must be at least 1")

    words = [secrets.choice(PASSPHRASE_WORDLIST) for _ in range(word_count)]

    if capitalize:
        words = [w.capitalize() for w in words]

    passphrase = separator.join(words)

    if include_number:
        number = str(secrets.randbelow(100))
        passphrase += number

    pool_size = len(PASSPHRASE_WORDLIST)
    return passphrase, pool_size


class PasswordHistory:
    def __init__(self, max_size: int = 50):
        self.max_size = max_size
        self.history: list[dict] = []
        self.load()

    def load(self):
        if not HISTORY_FILE.exists():
            return
        ensure_config_dir()
        HISTORY_FILE.chmod(0o600)
        try:
            with open(HISTORY_FILE) as f:
                loaded = json.load(f)
                if isinstance(loaded, list):
                    self.history = [
                        entry for entry in loaded if isinstance(entry, dict)
                    ][:self.max_size]
        except (json.JSONDecodeError, IOError):
            self.history = []

    def save(self):
        write_private_json(HISTORY_FILE, self.history)

    def add(
        self,
        password: str,
        password_type: str,
        strength: str,
        entropy: float,
        category: str = "",
        persist: bool = False,
    ):
        if not persist:
            return
        entry = {
            "password": password,
            "type": password_type,
            "strength": strength,
            "entropy": entropy,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "category": category
        }
        self.history.insert(0, entry)
        if len(self.history) > self.max_size:
            self.history.pop()
        self.save()

    def show(self, console: Console, category_filter: str = None):
        history = self.history
        if category_filter:
            history = [h for h in history if h.get("category") == category_filter]

        if not history:
            console.print("[dim]No password history yet.[/dim]")
            return

        table = Table(box=box.ROUNDED, show_header=True, header_style="bold yellow")
        table.add_column("#", style="dim", justify="right", width=4)
        table.add_column("Date", style="dim", width=12)
        table.add_column("Type", width=10)
        table.add_column("Category", width=10)
        table.add_column("Password", style="password")
        table.add_column("Strength", justify="center")

        for i, entry in enumerate(history, 1):
            color_map = {"Weak": "red", "Fair": "yellow", "Good": "cyan", "Strong": "green"}
            color = color_map.get(entry["strength"], "white")
            cat = entry.get("category", "-")
            table.add_row(
                str(i),
                entry["timestamp"],
                entry["type"],
                cat,
                entry["password"],
                f"[{color}]{entry['strength']}[/{color}]"
            )

        console.print(Panel.fit(
            "[bold yellow]📜 Password History[/bold yellow]",
            border_style="yellow",
            padding=(1, 2)
        ))
        console.print(table)


password_history = PasswordHistory()
    
    

def get_interactive_options():
    console.print(Panel.fit(
        "[bold cyan]🔐 Password Generator[/bold cyan]\n[dim]Interactive Mode[/dim]",
        border_style="cyan",
        padding=(1, 2)
    ))
    console.print("[info]1. Random Password (characters)[/info]")
    console.print("[info]2. Passphrase (memorable words)[/info]")
    console.print("[info]3. View History[/info]")
    console.print("[info]4. Manage Wordlists[/info]")
    console.print("[info]5. Export Passwords[/info]")
    choice = console.input("\n[info]Choose option (1/2/3/4/5): [/info]").strip()

    if choice == "3":
        return "history", None, None, None, None, None, None, None, None, False, None

    if choice == "4":
        return manage_wordlists_interactive()

    if choice == "5":
        return export_interactive()

    if choice == "2":
        wordlists = list_wordlists()
        wordlist_choice = None
        if wordlists:
            console.print("\n[info]Available wordlists:[/info]")
            console.print("[info]  default - Built-in wordlist[/info]")
            for w in wordlists:
                console.print(f"[info]  {w}[/info]")
            wordlist_choice = console.input("\n[info]Choose wordlist (or press Enter for default): [/info]").strip()

        if wordlist_choice:
            global PASSPHRASE_WORDLIST
            try:
                PASSPHRASE_WORDLIST = load_custom_wordlist(wordlist_choice)
                console.print(f"[success]Loaded custom wordlist: {wordlist_choice} ({len(PASSPHRASE_WORDLIST)} words)[/success]")
            except ValueError as e:
                console.print(f"[warning]{e}. Using default wordlist.[/warning]")

        try:
            word_count = int(console.input("\n[info]Number of words (default 4): [/info]") or 4)
            separator = console.input("[info]Separator (default -): [/info]") or "-"
            capitalize = console.input("[info]Capitalize words? [Y/n]: [/info]").lower() in ("", "y")
            include_number = console.input("[info]Add a number at the end? [Y/n]: [/info]").lower() in ("", "y")
            count = int(console.input("\n[info]How many passphrases? (default 1): [/info]") or 1)
            category = console.input("[info]Category (wifi/email/social/other, or Enter for none): [/info]").strip()
            copy_to_clipboard = console.input("[info]Copy to clipboard? [y/N]: [/info]").lower() == "y"
        except ValueError:
            console.print("[warning]Invalid input. Using defaults.[/warning]")
            word_count, separator, capitalize, include_number = 4, "-", True, False
            count, copy_to_clipboard = 1, False
            category = ""

        return "passphrase", word_count, separator, capitalize, include_number, None, None, count, None, copy_to_clipboard, category

    try:
        length = int(console.input("\n[info]Password length (default 12): [/info]") or 12)
        use_upper = console.input("[info]Include uppercase? [Y/n]: [/info]").lower() in ("", "y")
        use_lower = console.input("[info]Include lowercase? [Y/n]: [/info]").lower() in ("", "y")
        use_digits = console.input("[info]Include digits? [Y/n]: [/info]").lower() in ("", "y")
        use_symbols = console.input("[info]Include symbols? [Y/n]: [/info]").lower() in ("", "y")
        no_ambiguous = console.input("[info]Exclude ambiguous chars (0, O, l, 1, I)? [y/N]: [/info]").lower() == "y"
        exclude = console.input("[info]Exclude specific characters (or press Enter for none): [/info]")
        count = int(console.input("\n[info]How many passwords? (default 1): [/info]") or 1)
        category = console.input("[info]Category (wifi/email/social/other, or Enter for none): [/info]").strip()
        copy_to_clipboard = console.input("[info]Copy to clipboard? [y/N]: [/info]").lower() == "y"
    except ValueError:
        console.print("[warning]Invalid input. Using defaults.[/warning]")
        length, use_upper, use_lower, use_digits, use_symbols = 12, True, True, True, True
        no_ambiguous, exclude, count, copy_to_clipboard = False, "", 1, False
        category = ""

    return "random", length, use_upper, use_lower, use_digits, use_symbols, no_ambiguous, count, exclude, copy_to_clipboard, category


def manage_wordlists_interactive():
    console.print(Panel.fit(
        "[bold magenta]📝 Manage Wordlists[/bold magenta]",
        border_style="magenta",
        padding=(1, 2)
    ))
    console.print("[info]1. List wordlists[/info]")
    console.print("[info]2. Create wordlist[/info]")
    console.print("[info]3. Delete wordlist[/info]")
    choice = console.input("\n[info]Choose option (1/2/3): [/info]").strip()

    if choice == "1":
        wordlists = list_wordlists()
        if wordlists:
            console.print("[success]Available wordlists:[/success]")
            for w in wordlists:
                console.print(f"  - {w}")
        else:
            console.print("[dim]No custom wordlists found.[/dim]")
    elif choice == "2":
        name = console.input("[info]Enter wordlist name: [/info]").strip()
        words_input = console.input("[info]Enter words (comma-separated): [/info]").strip()
        words = [w.strip() for w in words_input.split(",") if w.strip()]
        if words:
            save_wordlist(name, words)
            console.print(f"[success]Wordlist '{name}' created with {len(words)} words![/success]")
        else:
            console.print("[warning]No words provided.[/warning]")
    elif choice == "3":
        wordlists = list_wordlists()
        if not wordlists:
            console.print("[dim]No wordlists to delete.[/dim]")
            return "list", None, None, None, None, None, None, None, None, False, None
        name = console.input("[info]Enter wordlist name to delete: [/info]").strip()
        if name in wordlists:
            (WORDLIST_DIR / f"{name}.txt").unlink()
            console.print(f"[success]Wordlist '{name}' deleted![/success]")
        else:
            console.print("[error]Wordlist not found.[/error]")

    return "list", None, None, None, None, None, None, None, None, False, None


def export_interactive():
    history = password_history.history
    if not history:
        console.print("[warning]No passwords to export.[/warning]")
        return "list", None, None, None, None, None, None, None, None, False, None

    console.print(Panel.fit(
        "[bold magenta]📤 Export Passwords[/bold magenta]",
        border_style="magenta",
        padding=(1, 2)
    ))
    console.print("[info]1. Export all to JSON[/info]")
    console.print("[info]2. Export all to CSV[/info]")
    console.print("[info]3. Export by category[/info]")
    choice = console.input("\n[info]Choose option (1/2/3): [/info]").strip()

    export_history = history
    category = None

    if choice == "3":
        categories = set(h.get("category", "") for h in history if h.get("category"))
        if not categories:
            console.print("[warning]No categorized passwords to export.[/warning]")
            return "list", None, None, None, None, None, None, None, None, False, None
        console.print("[info]Available categories:[/info]")
        for c in categories:
            console.print(f"  - {c}")
        category = console.input("[info]Enter category: [/info]").strip()
        export_history = [h for h in history if h.get("category") == category]

    format_choice = console.input("[info]Export format (json/csv): [/info]").strip().lower()
    if format_choice not in ("json", "csv"):
        format_choice = "json"

    filename = f"passwords.{format_choice}"
    export_path = CONFIG_DIR / filename
    export_passwords(export_history, format_choice, str(export_path))
    console.print(f"[success]Exported {len(export_history)} passwords to {export_path}![/success]")

    return "list", None, None, None, None, None, None, None, None, False, None


def copy_to_clipboard(text: str):
    try:
        import pyperclip
        pyperclip.copy(text)
        return True
    except Exception:
        try:
            subprocess.run(["pbcopy"], input=text.encode(), check=True)
            return True
        except Exception:
            try:
                subprocess.run(["xclip", "-selection", "clipboard"], input=text.encode(), check=True)
                return True
            except Exception:
                return False


def main():
    ensure_config_dir()

    parser = argparse.ArgumentParser(description="Secure Password Generator")
    parser.add_argument("--length", type=int, default=12, help="Password length")
    parser.add_argument("--upper", action="store_true", help="Include uppercase letters")
    parser.add_argument("--lower", action="store_true", help="Include lowercase letters")
    parser.add_argument("--digits", action="store_true", help="Include digits")
    parser.add_argument("--symbols", action="store_true", help="Include symbols")
    parser.add_argument("--no-ambiguous", action="store_true", help="Exclude ambiguous characters (0, O, l, 1, I)")
    parser.add_argument("--exclude", type=str, default="", help="Characters to exclude")
    parser.add_argument("--count", type=int, default=1, help="Number of passwords to generate")
    parser.add_argument("--copy", action="store_true", help="Copy password to clipboard")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("--passphrase", action="store_true", help="Generate passphrase instead of random password")
    parser.add_argument("--words", type=int, default=4, help="Number of words for passphrase")
    parser.add_argument("--separator", type=str, default="-", help="Separator for passphrase words")
    parser.add_argument("--capitalize", action="store_true", help="Capitalize passphrase words")
    parser.add_argument("--add-number", action="store_true", help="Add number at end of passphrase")
    parser.add_argument("--history", action="store_true", help="Show saved password history")
    parser.add_argument(
        "--save-history",
        action="store_true",
        help="Explicitly save generated passwords to local history",
    )
    parser.add_argument("--clear-history", action="store_true", help="Clear all password history")
    parser.add_argument("--category", type=str, default="", help="Category for password (wifi/email/social/other)")
    parser.add_argument("--wordlist", type=str, default="", help="Custom wordlist name for passphrase")
    parser.add_argument("--export", type=str, choices=["json", "csv"], help="Export history to file")
    parser.add_argument("--save-config", action="store_true", help="Save current options as defaults")
    parser.add_argument("--config", action="store_true", help="Use saved defaults from config")
    parser.add_argument("--quick", action="store_true", help="Quick: generate one strong 20-char password")
    parser.add_argument("--version", action="version", version=f"passgen v{VERSION}")

    args = parser.parse_args()

    if args.config:
        saved = load_config()
        if saved:
            key_map = {
                "length": "length", "upper": "upper", "lower": "lower",
                "digits": "digits", "symbols": "symbols",
                "no_ambiguous": "no_ambiguous", "exclude": "exclude",
                "passphrase": "passphrase", "words": "words",
                "separator": "separator", "capitalize": "capitalize",
                "add_number": "add_number", "wordlist": "wordlist",
                "category": "category",
            }
            defaults = {action.dest: action.default for action in parser._actions if action.dest != "help"}
            for config_key, arg_key in key_map.items():
                if config_key in saved and getattr(args, arg_key) == defaults.get(arg_key):
                    setattr(args, arg_key, saved[config_key])

    if args.quick:
        args.length = 20
        args.upper = args.lower = args.digits = args.symbols = True
        args.count = 1
        args.copy = True

    if args.save_config:
        config = {
            "length": args.length,
            "upper": args.upper,
            "lower": args.lower,
            "digits": args.digits,
            "symbols": args.symbols,
            "no_ambiguous": args.no_ambiguous,
            "exclude": args.exclude,
            "passphrase": args.passphrase,
            "words": args.words,
            "separator": args.separator,
            "capitalize": args.capitalize,
            "add_number": args.add_number,
            "wordlist": args.wordlist,
            "category": args.category,
        }
        save_config(config)
        console.print("[success]Config saved successfully![/success]")
        return

    if args.history:
        password_history.show(console, args.category if args.category else None)
        return

    if args.clear_history:
        password_history.history.clear()
        password_history.save()
        console.print("[success]History cleared![/success]")
        return

    if args.export:
        if not password_history.history:
            console.print("[warning]No passwords to export.[/warning]")
            return
        export_history = password_history.history
        if args.category:
            export_history = [h for h in export_history if h.get("category") == args.category]
        export_path = CONFIG_DIR / f"exported_passwords.{args.export}"
        export_passwords(export_history, args.export, str(export_path))
        console.print(f"[success]Exported {len(export_history)} passwords to {export_path}![/success]")
        return

    if args.wordlist:
        global PASSPHRASE_WORDLIST
        try:
            PASSPHRASE_WORDLIST = load_custom_wordlist(args.wordlist)
        except ValueError as e:
            console.print(f"[error]{e}[/error]")
            return

    is_interactive = args.interactive or len(sys.argv) == 1
    result = None

    if is_interactive:
        result = get_interactive_options()
        if result[0] in ("history", "list", "export"):
            return
        elif result[0] == "passphrase":
            p_type, word_count, separator, capitalize, _, _, _, count, _, copy_flag, category = result
            passphrase_mode = True
            length = 0
            use_upper = use_lower = use_digits = use_symbols = False
            no_ambiguous = False
            exclude = ""
        else:
            p_type, length, use_upper, use_lower, use_digits, use_symbols, no_ambiguous, count, exclude, copy_flag, category = result
            passphrase_mode = False

        if args.copy:
            copy_flag = True
    else:
        passphrase_mode = args.passphrase
        length = args.length
        use_upper = args.upper
        use_lower = args.lower
        use_digits = args.digits
        use_symbols = args.symbols
        no_ambiguous = args.no_ambiguous
        exclude = args.exclude
        count = args.count
        copy_flag = args.copy
        category = args.category

    try:
        if count < 1:
            raise ValueError("Count must be at least 1")

        if passphrase_mode:
            if is_interactive and result and result[0] == "passphrase":
                word_count = result[1]
                separator = result[2]
                capitalize = result[3]
                include_number = result[4]
            else:
                word_count = args.words
                separator = args.separator
                capitalize = args.capitalize
                include_number = args.add_number

            console.print(Panel.fit(
                f"[bold cyan]🔐 Generating {count} passphrase(s)[/bold cyan]\n[dim]Words: {word_count} | Separator: {separator} | Capitalize: {capitalize} | Number: {include_number}[/dim]",
                border_style="cyan",
                padding=(1, 2)
            ))

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                progress.add_task("Generating...", total=None)
                passwords = []
                for _ in range(count):
                    pwd, pool_size = generate_passphrase(
                        word_count=word_count,
                        separator=separator,
                        capitalize=capitalize,
                        include_number=include_number
                    )
                    passwords.append((pwd, pool_size))
        else:
            if length < 1:
                raise ValueError("Length must be at least 1")

            console.print(Panel.fit(
                f"[bold cyan]🔐 Generating {count} password(s)[/bold cyan]\n[dim]Length: {length} | Upper: {use_upper} | Lower: {use_lower} | Digits: {use_digits} | Symbols: {use_symbols}[/dim]",
                border_style="cyan",
                padding=(1, 2)
            ))

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                progress.add_task("Generating...", total=None)
                passwords = []
                for _ in range(count):
                    pwd, pool_size = generate_password(
                        length=length,
                        use_upper=use_upper,
                        use_lower=use_lower,
                        use_digits=use_digits,
                        use_symbols=use_symbols,
                        no_ambiguous=no_ambiguous,
                        exclude_chars=exclude
                    )
                    passwords.append((pwd, pool_size))

        table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
        table.add_column("#", style="dim", justify="right", width=4)
        table.add_column("Password", style="password")
        table.add_column("Strength", justify="center")
        table.add_column("Entropy", justify="right")

        for i, (pwd, pool_size) in enumerate(passwords, 1):
            entropy = calculate_entropy(pwd, pool_size)
            strength, color = get_strength_label(entropy)
            p_type = "Passphrase" if passphrase_mode else "Random"

            if check_common_password(pwd):
                console.print(f"[warning]⚠ Warning: Password '{pwd[:10]}...' is commonly used. Consider regenerating.[/warning]")

            pattern_warnings = check_password_patterns(pwd)
            for w in pattern_warnings:
                console.print(f"[warning]⚠ {w} in generated password.[/warning]")

            password_history.add(
                pwd,
                p_type,
                strength,
                entropy,
                category or "",
                persist=args.save_history,
            )
            table.add_row(
                str(i),
                pwd,
                f"[{color}]{strength}[/{color}]",
                f"{entropy:.1f} bits"
            )

        console.print(table)

        if copy_flag and passwords:
            if copy_to_clipboard(passwords[0][0]):
                console.print("\n[success]✓ Password copied to clipboard![/success]")
            else:
                console.print("\n[error]✗ Failed to copy to clipboard.[/error]")

    except ValueError as e:
        console.print(f"[error]Error: {e}[/error]")
        exit(1)
    
if __name__ == "__main__":
    main()
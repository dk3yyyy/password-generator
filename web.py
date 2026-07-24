import secrets
import string
import random
import math
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

app = FastAPI(title="Password Generator")

TEMPLATE_PATH = Path(__file__).parent / "templates" / "index.html"

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
]


def calculate_entropy(password: str, pool_size: int) -> float:
    if pool_size == 0:
        return 0.0
    return len(password) * math.log2(pool_size)


def get_strength(entropy: float) -> tuple[str, str, str]:
    if entropy < 25:
        return "Weak", "red", "danger"
    elif entropy < 45:
        return "Fair", "yellow", "warning"
    elif entropy < 60:
        return "Good", "cyan", "info"
    else:
        return "Strong", "green", "success"


def generate_password(
    length: int,
    use_upper: bool,
    use_lower: bool,
    use_digits: bool,
    use_symbols: bool,
    no_ambiguous: bool = False,
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

    if not char_pool:
        raise ValueError("No characters available in pool")

    if length < len(required_chars):
        raise ValueError("Length too short for selected character types")

    password_chars = required_chars + [secrets.choice(char_pool) for _ in range(length - len(required_chars))]
    random.SystemRandom().shuffle(password_chars)

    return "".join(password_chars), len(char_pool)


def generate_passphrase(
    word_count: int,
    separator: str,
    capitalize: bool,
    include_number: bool,
) -> tuple[str, int]:
    words = [secrets.choice(DEFAULT_WORDLIST) for _ in range(word_count)]
    if capitalize:
        words = [w.capitalize() for w in words]
    passphrase = separator.join(words)
    if include_number:
        passphrase += str(secrets.randbelow(100))
    return passphrase, len(DEFAULT_WORDLIST)


def parse_bounded_integer(value, field: str, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=422, detail=f"{field} must be an integer") from error
    if not minimum <= parsed <= maximum:
        raise HTTPException(
            status_code=422,
            detail=f"{field} must be between {minimum} and {maximum}",
        )
    return parsed


@app.get("/", response_class=HTMLResponse)
async def home():
    return TEMPLATE_PATH.read_text()


@app.post("/generate")
async def generate(request: Request):
    form = await request.form()
    mode = form.get("mode", "random")
    if mode not in {"random", "passphrase"}:
        raise HTTPException(
            status_code=422,
            detail="mode must be 'random' or 'passphrase'",
        )
    count = parse_bounded_integer(form.get("count", 1), "count", 1, 20)

    passwords = []

    if mode == "passphrase":
        word_count = parse_bounded_integer(
            form.get("word_count", 4),
            "word_count",
            2,
            10,
        )
        separator = form.get("separator", "-")
        if separator not in {"-", "_", ".", " "}:
            raise HTTPException(status_code=422, detail="separator is not supported")
        capitalize = "capitalize" in form
        include_number = "add_number" in form

        for _ in range(count):
            pwd, pool_size = generate_passphrase(word_count, separator, capitalize, include_number)
            entropy = calculate_entropy(pwd, pool_size)
            strength, color, badge = get_strength(entropy)
            passwords.append({
                "password": pwd,
                "strength": strength,
                "color": color,
                "badge": badge,
                "entropy": f"{entropy:.1f}",
            })
    else:
        length = parse_bounded_integer(form.get("length", 12), "length", 6, 64)
        use_upper = "upper" in form
        use_lower = "lower" in form
        use_digits = "digits" in form
        use_symbols = "symbols" in form
        no_ambiguous = "no_ambiguous" in form
        if not any((use_upper, use_lower, use_digits, use_symbols)):
            raise HTTPException(
                status_code=422,
                detail="select at least one character type",
            )

        for _ in range(count):
            pwd, pool_size = generate_password(
                length, use_upper, use_lower, use_digits, use_symbols, no_ambiguous
            )
            entropy = calculate_entropy(pwd, pool_size)
            strength, color, badge = get_strength(entropy)
            passwords.append({
                "password": pwd,
                "strength": strength,
                "color": color,
                "badge": badge,
                "entropy": f"{entropy:.1f}",
            })

    return {"passwords": passwords}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
import secrets
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from passphrases import BUILTIN_WORDLIST, calculate_passphrase_entropy
from passwords import calculate_password_entropy, generate_password

app = FastAPI(title="Password Generator")

TEMPLATE_PATH = Path(__file__).parent / "templates" / "index.html"

DEFAULT_WORDLIST = BUILTIN_WORDLIST


def get_strength(entropy: float) -> tuple[str, str, str]:
    if entropy < 25:
        return "Weak", "red", "danger"
    elif entropy < 45:
        return "Fair", "yellow", "warning"
    elif entropy < 60:
        return "Good", "cyan", "info"
    else:
        return "Strong", "green", "success"


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
        passphrase += f"{secrets.randbelow(100):02d}"
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
            form.get("word_count", 6),
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
            entropy = calculate_passphrase_entropy(
                word_count,
                pool_size,
                number_choices=100 if include_number else 1,
            )
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

        entropy = calculate_password_entropy(
            length,
            use_upper,
            use_lower,
            use_digits,
            use_symbols,
            no_ambiguous,
        )
        for _ in range(count):
            pwd, _ = generate_password(
                length, use_upper, use_lower, use_digits, use_symbols, no_ambiguous
            )
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
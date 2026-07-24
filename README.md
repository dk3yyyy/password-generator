# PassGen - Secure Password Generator

A powerful, secure, and feature-rich password generator built with Python. Features a beautiful CLI with rich formatting and a modern web interface.

![Python](https://img.shields.io/badge/python-3.14+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-passing-success)

## Features

### CLI Features
- **Random Password Generation** - Generate secure passwords with customizable character sets
- **Passphrase Generation** - Create memorable passwords from wordlists
- **Interactive Mode** - User-friendly prompts for password creation
- **Opt-in History** - Save generated passwords only when explicitly requested
- **Config Management** - Save and load preferred settings
- **Export** - Export passwords to JSON or CSV
- **Categories** - Organize passwords by type (wifi, email, social, etc.)
- **Custom Wordlists** - Create and use custom wordlists for passphrases
- **Copy to Clipboard** - Cross-platform clipboard support
- **Strength Analysis** - Entropy calculation and strength detection
- **Pattern Detection** - Warns about repeated/sequential characters

### Web Interface
- Responsive, accessible interface for desktop and mobile
- Random password and passphrase modes
- Clear strength and entropy indicators
- One-click copy with inline validation feedback

## Installation

```bash
# Clone the repository
git clone https://github.com/dk3yyyy/password-generator.git
cd password-generator

# Install dependencies
uv sync

# Install dev dependencies for testing
uv sync --all-extras
```

## Usage

### CLI

```bash
# Run the CLI (starts in interactive mode by default)
uv run python main.py

# Generate a random password
uv run python main.py --length 20 --upper --lower --digits --symbols

# Generate a passphrase
uv run python main.py --passphrase --words 4 --capitalize

# Quick generate (16-char with all character types + copy)
uv run python main.py --quick

# Save your preferred settings
uv run python main.py --save-config

# Load saved config
uv run python main.py --config

# View history
uv run python main.py --history

# Explicitly save a generated password to history
uv run python main.py --length 20 --upper --lower --digits --symbols --save-history

# Export history
uv run python main.py --export json

# Clear history
uv run python main.py --clear-history

# Copy to clipboard
uv run python main.py --length 16 --copy

# View version
uv run python main.py --version
```

### Web Interface

```bash
# Start the web server
uv run python web.py
```

Then open http://127.0.0.1:8000 in your browser.

## Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `--length N` | Password length | 12 |
| `--upper` | Include uppercase letters | False |
| `--lower` | Include lowercase letters | False |
| `--digits` | Include digits | False |
| `--symbols` | Include special symbols | False |
| `--no-ambiguous` | Exclude ambiguous chars (0, O, l, 1, I) | False |
| `--exclude CHARS` | Characters to exclude | "" |
| `--count N` | Number of passwords to generate | 1 |
| `--copy` | Copy password to clipboard | False |
| `--passphrase` | Generate passphrase instead | False |
| `--words N` | Number of words for passphrase | 4 |
| `--separator SEP` | Separator for passphrase words | "-" |
| `--capitalize` | Capitalize passphrase words | False |
| `--add-number` | Append number to passphrase | False |
| `--category CAT` | Category for password | "" |
| `--wordlist NAME` | Custom wordlist for passphrase | "" |
| `--history` | Show password history | False |
| `--save-history` | Explicitly save generated passwords to local history | False |
| `--clear-history` | Clear all history | False |
| `--export FORMAT` | Export history (json/csv) | - |
| `--save-config` | Save current options as defaults | False |
| `--config` | Load saved config as defaults | False |
| `--quick` | Quick: 20-char password with copy | False |
| `--version` | Show version | - |
| `--interactive` | Force interactive mode | False |

## Project Structure

```
password-generator/
├── main.py           # CLI application
├── web.py            # Web interface (FastAPI)
├── pyproject.toml    # Project configuration
├── README.md         # This file
├── tests/            # Unit tests
│   └── test_main.py
└── templates/        # Web templates
    └── index.html
```

## Security Features

- Uses Python's `secrets` module for cryptographically secure random generation
- Does not persist generated passwords unless `--save-history` is supplied
- Protects history and export files with owner-only permissions on POSIX systems
- Calculates password entropy for strength assessment
- Detects common weak passwords
- Warns about patterns (repeated chars, sequences, keyboard patterns)

## Development

### Running Tests

```bash
uv run pytest tests/ -v
```

### Code Quality

The project follows Python best practices with:
- Type hints
- Docstrings
- Modular design

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
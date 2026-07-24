from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


class AssetParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []
        self.stylesheets = []
        self.meta = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "script" and values.get("src"):
            self.scripts.append(values["src"])
        if tag == "link" and values.get("rel") == "stylesheet":
            self.stylesheets.append(values.get("href"))
        if tag == "meta":
            self.meta.append(values)


def test_static_page_uses_only_same_origin_runtime_assets():
    parser = AssetParser()
    parser.feed((DOCS / "index.html").read_text(encoding="utf-8"))

    assert parser.scripts == ["./app.mjs"]
    assert parser.stylesheets == ["./styles.css"]
    assert all(asset.startswith("./") for asset in parser.scripts + parser.stylesheets)


def test_static_page_has_restrictive_content_security_policy():
    parser = AssetParser()
    parser.feed((DOCS / "index.html").read_text(encoding="utf-8"))
    policies = [
        item["content"]
        for item in parser.meta
        if item.get("http-equiv") == "Content-Security-Policy"
    ]

    assert len(policies) == 1
    policy = policies[0]
    assert "default-src 'self'" in policy
    assert "script-src 'self'" in policy
    assert "connect-src 'self'" in policy
    assert "object-src 'none'" in policy
    assert "form-action 'none'" in policy


def test_static_app_does_not_use_insecure_randomness_storage_or_remote_generation():
    source = (DOCS / "app.mjs").read_text(encoding="utf-8")
    generator = (DOCS / "generator.mjs").read_text(encoding="utf-8")
    combined = source + generator

    assert "Math.random" not in combined
    assert "localStorage" not in combined
    assert "sessionStorage" not in combined
    assert "innerHTML" not in combined
    assert "document.write" not in combined
    assert "method: 'POST'" not in source
    assert ".style." not in source
    assert "fetch('./eff_large_wordlist.txt'" in source
    assert "getRandomValues" in generator


def test_static_wordlist_is_an_exact_copy_of_validated_python_wordlist():
    assert (DOCS / "eff_large_wordlist.txt").read_bytes() == (
        ROOT / "wordlists" / "eff_large_wordlist.txt"
    ).read_bytes()

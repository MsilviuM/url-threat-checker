"""Turn a raw URL into numbers the machine-learning model can understand."""

from dataclasses import asdict, dataclass
from ipaddress import ip_address
from math import log2
from pathlib import PurePosixPath
from urllib.parse import parse_qsl, quote, unquote, urlparse, urlunparse

import tldextract

FEATURE_EXTRACTOR_VERSION = "2026-05-09-trusted-context-v2"

SUSPICIOUS_KEYWORDS = {
    "account",
    "auth",
    "bank",
    "billing",
    "confirm",
    "login",
    "password",
    "paypal",
    "secure",
    "signin",
    "update",
    "verify",
    "wallet",
}

WHITELISTED_DOMAINS = {
    "apple.com",
    "emag.ro",
    "facebook.com",
    "github.com",
    "google.com",
    "microsoft.com",
    "wikipedia.org",
    "youtube.com",
}

URL_SHORTENERS = {
    "bit.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "s.id",
    "tinyurl.com",
    "t.co",
    "v.gd",
    "youtu.be",
}

RISKY_EXTENSIONS = {
    ".apk",
    ".bat",
    ".cmd",
    ".com",
    ".dll",
    ".dmg",
    ".exe",
    ".iso",
    ".jar",
    ".js",
    ".msi",
    ".ps1",
    ".scr",
    ".vbs",
    ".zip",
}

_extractor = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


@dataclass(frozen=True)
class ParsedUrl:
    original_url: str
    normalized_url: str
    defanged_url: str
    scheme: str
    domain: str
    registered_domain: str
    subdomain: str
    path: str
    query: str
    scheme_missing: bool


@dataclass(frozen=True)
class UrlFeatureSet:
    url_length: int
    normalized_url_length: int
    domain_length: int
    domain_dot_count: int
    subdomain_count: int
    has_https: int
    has_http: int
    scheme_missing: int
    digit_ratio: float
    query_param_count: int
    query_length: int
    path_length: int
    suspicious_keyword_count: int
    is_whitelisted: int
    is_trusted_root_or_www_homepage: int
    is_trusted_search_or_common_public_page: int
    is_trusted_user_generated_service: int
    has_ip_address: int
    has_at_symbol: int
    has_hyphen_in_domain: int
    has_punycode: int
    has_risky_extension: int
    uses_url_shortener: int
    url_entropy: float

    def to_dict(self) -> dict[str, int | float]:
        return asdict(self)


FEATURE_NAMES = list(UrlFeatureSet.__dataclass_fields__.keys())


class UrlParsingError(ValueError):
    pass


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    counts = {character: value.count(character) for character in set(value)}
    return -sum((count / length) * log2(count / length) for count in counts.values())


def _safe_domain(url: str) -> str:
    try:
        return urlparse(url).netloc
    except ValueError:
        return ""


def parse_url(raw_url: str) -> ParsedUrl:
    original_url = str(raw_url or "").strip()
    if not original_url:
        raise UrlParsingError("URL cannot be empty.")
    if any(character.isspace() for character in original_url):
        raise UrlParsingError("URL cannot contain whitespace.")

    decoded = unquote(original_url).strip()
    # urlparse only finds the domain if a scheme exists, so google.com is parsed as
    # http://google.com internally and then shown back without the temporary scheme.
    has_scheme = "://" in decoded
    parse_target = decoded if has_scheme else f"http://{decoded}"
    parsed = urlparse(parse_target)

    if not parsed.netloc:
        raise UrlParsingError("URL must include a domain.")

    domain = parsed.netloc.split("@")[-1].split(":")[0].strip(".").lower()
    if not domain:
        raise UrlParsingError("URL must include a domain.")

    extracted = _extractor(domain)
    registered_domain = extracted.top_domain_under_public_suffix or domain
    subdomain = extracted.subdomain or ""

    normalized_path = quote(parsed.path or "/", safe="/:@")
    normalized = urlunparse(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            normalized_path,
            "",
            parsed.query,
            "",
        )
    )
    if not has_scheme:
        normalized = normalized.removeprefix("http://")

    return ParsedUrl(
        original_url=original_url,
        normalized_url=normalized,
        defanged_url=defang_url(normalized),
        scheme=parsed.scheme.lower(),
        domain=domain,
        registered_domain=registered_domain.lower(),
        subdomain=subdomain.lower(),
        path=parsed.path or "",
        query=parsed.query or "",
        scheme_missing=not has_scheme,
    )


def defang_url(url: str) -> str:
    defanged = url.replace("https://", "hxxps://", 1).replace("http://", "hxxp://", 1)
    return defanged.replace(".", "[.]")


def is_whitelisted(parsed: ParsedUrl) -> bool:
    return parsed.registered_domain in WHITELISTED_DOMAINS


def _query_param_names(query: str) -> set[str]:
    return {name.lower() for name, _value in parse_qsl(query, keep_blank_values=True)}


def _path_segments(path: str) -> list[str]:
    return [segment for segment in path.strip("/").split("/") if segment]


def _is_homepage_path(path: str) -> bool:
    return path in {"", "/"}


def _is_root_or_www_host(parsed: ParsedUrl) -> bool:
    return parsed.domain in {parsed.registered_domain, f"www.{parsed.registered_domain}"}


def is_trusted_root_or_www_homepage(parsed: ParsedUrl) -> bool:
    return (
        is_whitelisted(parsed)
        and _is_root_or_www_host(parsed)
        and _is_homepage_path(parsed.path)
        and not parsed.query
    )


def is_trusted_search_or_common_public_page(parsed: ParsedUrl) -> bool:
    segments = _path_segments(parsed.path)
    first_segment = segments[0].lower() if segments else ""
    query_names = _query_param_names(parsed.query)

    if (
        parsed.registered_domain == "google.com"
        and parsed.domain in {"google.com", "www.google.com"}
        and parsed.path.rstrip("/") == "/search"
        and "q" in query_names
    ):
        return True

    if (
        parsed.registered_domain == "youtube.com"
        and parsed.domain in {"youtube.com", "www.youtube.com"}
        and parsed.path.rstrip("/") == "/watch"
        and "v" in query_names
    ):
        return True

    if (
        parsed.registered_domain == "github.com"
        and parsed.domain in {"github.com", "www.github.com"}
        and len(segments) >= 2
    ):
        return True

    if parsed.registered_domain == "wikipedia.org" and parsed.path.startswith("/wiki/"):
        return True

    if parsed.registered_domain == "apple.com" and parsed.domain == "support.apple.com":
        return bool(segments)

    if parsed.registered_domain == "microsoft.com":
        if parsed.domain in {"learn.microsoft.com", "support.microsoft.com"}:
            return bool(segments)
        if parsed.domain in {"microsoft.com", "www.microsoft.com"} and first_segment in {
            "en-us",
            "ro-ro",
            "security",
            "support",
            "windows",
        }:
            return True

    if parsed.registered_domain == "emag.ro" and parsed.domain in {"emag.ro", "www.emag.ro"}:
        return _is_homepage_path(parsed.path) or first_segment in {
            "search",
            "laptopuri",
            "telefoane-mobile",
            "carti",
            "electrocasnice",
            "fashion",
        }

    if parsed.registered_domain == "facebook.com" and parsed.domain in {
        "facebook.com",
        "www.facebook.com",
    }:
        return first_segment in {"business", "help", "pages", "privacy"}

    return False


def is_trusted_user_generated_service(parsed: ParsedUrl) -> bool:
    if parsed.domain in {
        "docs.google.com",
        "drive.google.com",
        "forms.gle",
        "groups.google.com",
        "sites.google.com",
        "spreadsheets.google.com",
    }:
        return True

    if parsed.domain.endswith(".sites.google.com"):
        return True

    if parsed.registered_domain == "facebook.com":
        first_segment = (_path_segments(parsed.path) or [""])[0].lower()
        if parsed.domain == "apps.facebook.com" or first_segment in {
            "dialog",
            "plugins",
            "share.php",
            "sharer",
        }:
            return True

    return (
        parsed.registered_domain == "youtube.com"
        and parsed.domain in {"youtube.com", "www.youtube.com"}
        and parsed.path.rstrip("/") == "/redirect"
    )


def _has_ip_address(domain: str) -> bool:
    try:
        ip_address(domain.strip("[]"))
        return True
    except ValueError:
        return False


def extract_features(raw_url: str) -> tuple[ParsedUrl, UrlFeatureSet]:
    """Return the parsed URL and the numeric feature row used by the model."""

    parsed = parse_url(raw_url)
    searchable = f"{parsed.normalized_url} {parsed.domain}".lower()
    digit_count = sum(character.isdigit() for character in parsed.normalized_url)
    query_params = parse_qsl(parsed.query, keep_blank_values=True)
    path_suffix = PurePosixPath(parsed.path).suffix.lower()
    suspicious_words = {word for word in SUSPICIOUS_KEYWORDS if word in searchable}

    features = UrlFeatureSet(
        url_length=len(parsed.original_url),
        normalized_url_length=len(parsed.normalized_url),
        domain_length=len(parsed.domain),
        domain_dot_count=parsed.domain.count("."),
        subdomain_count=0 if not parsed.subdomain else parsed.subdomain.count(".") + 1,
        has_https=1 if parsed.scheme == "https" and not parsed.scheme_missing else 0,
        has_http=1 if parsed.scheme == "http" and not parsed.scheme_missing else 0,
        scheme_missing=1 if parsed.scheme_missing else 0,
        digit_ratio=digit_count / len(parsed.normalized_url) if parsed.normalized_url else 0.0,
        query_param_count=len(query_params),
        query_length=len(parsed.query),
        path_length=len(parsed.path),
        suspicious_keyword_count=len(suspicious_words),
        is_whitelisted=1 if is_whitelisted(parsed) else 0,
        is_trusted_root_or_www_homepage=1 if is_trusted_root_or_www_homepage(parsed) else 0,
        is_trusted_search_or_common_public_page=(
            1 if is_trusted_search_or_common_public_page(parsed) else 0
        ),
        is_trusted_user_generated_service=1 if is_trusted_user_generated_service(parsed) else 0,
        has_ip_address=1 if _has_ip_address(parsed.domain) else 0,
        has_at_symbol=1 if "@" in parsed.original_url else 0,
        has_hyphen_in_domain=1 if "-" in parsed.domain else 0,
        has_punycode=1 if "xn--" in parsed.domain else 0,
        has_risky_extension=1 if path_suffix in RISKY_EXTENSIONS else 0,
        uses_url_shortener=1 if parsed.registered_domain in URL_SHORTENERS else 0,
        url_entropy=round(_entropy(parsed.normalized_url), 6),
    )
    return parsed, features

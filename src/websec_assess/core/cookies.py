"""Parses a raw Set-Cookie header into its flags. httpx's parsed cookie jar
drops the attributes (Secure/HttpOnly/SameSite/...) that the vuln-assessment
cookie checks actually care about, so this works off the raw header text."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ParsedCookie:
    name: str
    value: str
    secure: bool = False
    httponly: bool = False
    samesite: str | None = None
    domain: str | None = None
    path: str | None = None
    expires: str | None = None
    raw: str = ""
    flags: dict[str, str] = field(default_factory=dict)


def parse_set_cookie(raw: str) -> ParsedCookie:
    parts = [p.strip() for p in raw.split(";")]
    name, _, value = parts[0].partition("=")
    cookie = ParsedCookie(name=name.strip(), value=value.strip(), raw=raw)
    for part in parts[1:]:
        if "=" in part:
            key, _, val = part.partition("=")
            key = key.strip().lower()
            val = val.strip()
            cookie.flags[key] = val
            if key == "samesite":
                cookie.samesite = val
            elif key == "domain":
                cookie.domain = val
            elif key == "path":
                cookie.path = val
            elif key == "expires":
                cookie.expires = val
        else:
            key = part.strip().lower()
            if key == "secure":
                cookie.secure = True
            elif key == "httponly":
                cookie.httponly = True
    return cookie


def parse_all(set_cookie_headers: list[str]) -> list[ParsedCookie]:
    return [parse_set_cookie(h) for h in set_cookie_headers if h]


SESSION_NAME_MARKERS = (
    "session", "sess", "sid", "auth", "token", "jwt",
    "phpsessid", "jsessionid", "laravel_session", "connect.sid",
)


def looks_like_session(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in SESSION_NAME_MARKERS)

"""Minimal HTML link/form extraction on stdlib html.parser -- a regex or a
bs4 dependency would both be more code/weight for the same result here."""
from __future__ import annotations

from html.parser import HTMLParser


class LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []
        self.srcs: list[str] = []
        self.forms: list[dict] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_d = {k: v for k, v in attrs if v is not None}
        if tag == "a" and "href" in attrs_d:
            self.hrefs.append(attrs_d["href"])
        elif tag in ("script", "img") and "src" in attrs_d:
            self.srcs.append(attrs_d["src"])
        elif tag == "form":
            self._current_form = {
                "action": attrs_d.get("action", ""),
                "method": attrs_d.get("method", "get").lower(),
                "inputs": [],
            }
            self.forms.append(self._current_form)
        elif tag == "input" and self._current_form is not None:
            name = attrs_d.get("name")
            if name:
                self._current_form["inputs"].append({"name": name, "type": attrs_d.get("type", "text")})

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current_form = None


def extract(html: str) -> LinkExtractor:
    parser = LinkExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser

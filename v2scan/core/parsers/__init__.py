"""Link parsers registry.

>>> cfg = parse_link("trojan://pw@example.com:443?sni=example.com#demo")
>>> (cfg.protocol, cfg.address, cfg.port, cfg.remark)
('trojan', 'example.com', 443, 'demo')
"""

from __future__ import annotations

from ..config import ALL_PREFIXES
from ..models import ProxyConfig
from .base import BaseParser, ParseError, split_url
from .hysteria2 import Hysteria2Parser
from .shadowsocks import ShadowsocksParser
from .trojan import TrojanParser
from .vless import VlessParser
from .vmess import VmessParser

PARSERS: tuple[BaseParser, ...] = (
    VlessParser(),
    VmessParser(),
    TrojanParser(),
    ShadowsocksParser(),
    Hysteria2Parser(),
)

__all__ = [
    "BaseParser",
    "ParseError",
    "PARSERS",
    "extract_host",
    "extract_proxy_links",
    "get_parser",
    "get_protocol",
    "is_proxy_link",
    "parse_link",
    "set_remark",
]


def is_proxy_link(link: str) -> bool:
    """True if ``link`` starts with a supported proxy scheme."""
    return link.strip().lower().startswith(ALL_PREFIXES)


def get_parser(link: str) -> BaseParser | None:
    """Return the parser handling ``link``'s scheme, or ``None``."""
    for parser in PARSERS:
        if parser.matches(link.strip()):
            return parser
    return None


def get_protocol(link: str) -> str:
    """Canonical protocol name (``vless``, ``vmess``, ``trojan``, ``ss``, ``hysteria2``) or ``unknown``."""
    parser = get_parser(link)
    return parser.protocol if parser else "unknown"


def parse_link(link: str) -> ProxyConfig:
    """Parse any supported link. Raises :class:`ParseError` on failure."""
    parser = get_parser(link)
    if parser is None:
        raise ParseError("unsupported scheme")
    return parser.parse(link)


def set_remark(link: str, remark: str) -> str:
    """Replace the link's display name; unsupported links are returned unchanged."""
    parser = get_parser(link)
    return parser.with_remark(link, remark) if parser else link


def extract_proxy_links(text: str) -> list[str]:
    """Lines of ``text`` that look like supported proxy links, stripped."""
    return [line.strip() for line in text.splitlines() if is_proxy_link(line)]


def extract_host(link: str) -> str | None:
    """Server host of a link, or ``None`` if it cannot be determined."""
    try:
        return parse_link(link).address or None
    except ParseError:
        pass
    # base64-only forms carry no readable host
    if "@" not in link.partition("#")[0]:
        return None
    try:  # parse failed (e.g. unsupported transport) but the host may still be readable
        return split_url(link).host or None
    except ParseError:
        return None

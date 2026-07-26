from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import unquote_plus
import re
import sqlite3


@dataclass(frozen=True)
class PiholeSummary:
    core_version: str | None
    web_version: str | None
    ftl_version: str | None
    groups: int
    clients: int
    enabled_adlists: int
    domainlist_entries: int
    gravity_domains: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class QueryEvent:
    id: int
    timestamp: int
    client_ip: str
    domain: str
    query_type: str
    status: str
    blocked: bool
    service: str
    category: str
    headline: str
    detail: str
    search_query: str | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


QUERY_TYPE_NAMES = {
    1: "A",
    2: "AAAA",
    3: "ANY",
    4: "SRV",
    5: "SOA",
    6: "PTR",
    7: "TXT",
    8: "NAPTR",
    9: "MX",
    10: "DS",
    11: "RRSIG",
    12: "DNSKEY",
    13: "NS",
    14: "OTHER",
    15: "SVCB",
    16: "HTTPS",
}

BLOCKED_STATUSES = frozenset({1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16})

STATUS_LABELS = {
    0: "unknown",
    1: "blocked",
    2: "allowed",
    3: "cached",
    4: "blocked",
    5: "blocked",
    6: "blocked",
    7: "blocked",
    8: "blocked",
    9: "blocked",
    10: "blocked",
    11: "blocked",
    12: "retried",
    13: "retried",
    14: "allowed",
    15: "blocked",
    16: "blocked",
    17: "cached",
}

# Domain suffix / substring hints for common apps and services (DNS-level only).
# More specific patterns must come before broader ones (e.g. youtube before google).
# Broad household service map (DNS-level). Inspired by Sniffnet's wide service coverage,
# tuned for family appliances rather than trojan/malware signatures.
SERVICE_HINTS: tuple[tuple[str, str, str], ...] = (
    ("youtube.", "YouTube", "video"),
    ("youtu.be", "YouTube", "video"),
    ("googlevideo.", "YouTube", "video"),
    ("ytimg.", "YouTube", "video"),
    ("netflix.", "Netflix", "video"),
    ("nflx", "Netflix", "video"),
    ("disney", "Disney+", "video"),
    ("hulu.", "Hulu", "video"),
    ("primevideo.", "Prime Video", "video"),
    ("aiv-cdn.", "Prime Video", "video"),
    ("max.com", "Max", "video"),
    ("hbomax.", "Max", "video"),
    ("paramount.", "Paramount+", "video"),
    ("peacocktv.", "Peacock", "video"),
    ("crunchyroll.", "Crunchyroll", "video"),
    ("tiktok.", "TikTok", "social"),
    ("musical.ly", "TikTok", "social"),
    ("byteoversea.", "TikTok", "social"),
    ("instagram.", "Instagram", "social"),
    ("cdninstagram.", "Instagram", "social"),
    ("facebook.", "Facebook", "social"),
    ("fbcdn.", "Facebook", "social"),
    ("whatsapp.", "WhatsApp", "messaging"),
    ("snapchat.", "Snapchat", "social"),
    ("twitter.", "X / Twitter", "social"),
    ("twimg.", "X / Twitter", "social"),
    ("x.com", "X / Twitter", "social"),
    ("reddit.", "Reddit", "social"),
    ("redd.it", "Reddit", "social"),
    ("pinterest.", "Pinterest", "social"),
    ("linkedin.", "LinkedIn", "social"),
    ("twitch.", "Twitch", "video"),
    ("ttvnw.", "Twitch", "video"),
    ("spotify.", "Spotify", "music"),
    ("scdn.co", "Spotify", "music"),
    ("pandora.", "Pandora", "music"),
    ("soundcloud.", "SoundCloud", "music"),
    ("apple-music", "Apple Music", "music"),
    ("music.apple.", "Apple Music", "music"),
    ("duckduckgo.", "DuckDuckGo", "search"),
    ("bing.com", "Bing", "search"),
    ("search.yahoo.", "Yahoo", "search"),
    ("apple.com", "Apple", "system"),
    ("icloud.", "iCloud", "system"),
    ("mzstatic.", "Apple", "system"),
    ("push.apple.", "Apple Push", "system"),
    ("googleapis.", "Google services", "system"),
    ("gstatic.", "Google services", "system"),
    ("googleusercontent.", "Google services", "system"),
    ("1e100.net", "Google services", "system"),
    ("google.", "Google", "search"),
    ("microsoft.", "Microsoft", "system"),
    ("windows.com", "Microsoft", "system"),
    ("office.com", "Microsoft 365", "productivity"),
    ("office.net", "Microsoft 365", "productivity"),
    ("outlook.", "Outlook", "productivity"),
    ("live.com", "Microsoft", "system"),
    ("xbox.", "Xbox", "games"),
    ("playstation.", "PlayStation", "games"),
    ("sonyentertainmentnetwork.", "PlayStation", "games"),
    ("nintendo.", "Nintendo", "games"),
    ("steam", "Steam", "games"),
    ("steampowered.", "Steam", "games"),
    ("steamcontent.", "Steam", "games"),
    ("epicgames.", "Epic Games", "games"),
    ("roblox.", "Roblox", "games"),
    ("minecraft.", "Minecraft", "games"),
    ("mojang.", "Minecraft", "games"),
    ("fortnite", "Fortnite", "games"),
    ("activision.", "Activision", "games"),
    ("ea.com", "EA", "games"),
    ("origin.com", "EA", "games"),
    ("amazon.", "Amazon", "shopping"),
    ("aws.", "Amazon Web Services", "cloud"),
    ("cloudfront.", "Amazon CloudFront", "cloud"),
    ("shopify.", "Shopify", "shopping"),
    ("ebay.", "eBay", "shopping"),
    ("etsy.", "Etsy", "shopping"),
    ("walmart.", "Walmart", "shopping"),
    ("target.", "Target", "shopping"),
    ("akamai", "Akamai CDN", "cdn"),
    ("cloudflare.", "Cloudflare", "cdn"),
    ("fastly.", "Fastly CDN", "cdn"),
    ("zoom.us", "Zoom", "meetings"),
    ("teams.microsoft.", "Microsoft Teams", "meetings"),
    ("webex.", "Webex", "meetings"),
    ("slack.com", "Slack", "messaging"),
    ("discord.", "Discord", "messaging"),
    ("telegram.", "Telegram", "messaging"),
    ("signal.org", "Signal", "messaging"),
    ("messenger.", "Messenger", "messaging"),
    ("icloud-content.", "iCloud", "cloud"),
    ("dropbox.", "Dropbox", "cloud"),
    ("box.com", "Box", "cloud"),
    ("onedrive.", "OneDrive", "cloud"),
    ("github.", "GitHub", "productivity"),
    ("gitlab.", "GitLab", "productivity"),
    ("notion.", "Notion", "productivity"),
    ("figma.", "Figma", "productivity"),
    ("openai.", "OpenAI", "ai"),
    ("chatgpt.", "ChatGPT", "ai"),
    ("anthropic.", "Anthropic", "ai"),
    ("claude.ai", "Claude", "ai"),
    ("copilot.", "Copilot", "ai"),
    ("ring.com", "Ring", "iot"),
    ("nest.", "Google Nest", "iot"),
    ("hue.", "Philips Hue", "iot"),
    ("smartthings.", "SmartThings", "iot"),
    ("tplink.", "TP-Link", "iot"),
    ("roku.", "Roku", "tv"),
    ("samsungcloud.", "Samsung", "tv"),
    ("nflximg.", "Netflix", "video"),
)

SEARCH_QUERY_PATTERNS = (
    re.compile(r"[?&](?:q|p|query|search_query|text|wd)=([^&]+)", re.I),
    re.compile(r"/search/([^/?#]+)", re.I),
    re.compile(r"/search\?[^#]*[?&]q=([^&]+)", re.I),
)

CATEGORY_VERBS = {
    "video": "Watching",
    "social": "Using",
    "messaging": "Messaging on",
    "music": "Listening on",
    "games": "Playing",
    "shopping": "Shopping on",
    "meetings": "In a call on",
    "productivity": "Working in",
    "cdn": "Loading content from",
    "cloud": "Using",
    "system": "Using",
    "website": "Visiting",
    "search": "Searching",
    "ai": "Using",
    "iot": "Talking to",
    "tv": "Streaming on",
    "other": "Using",
}


class PiholeStateReader:
    def __init__(self, gravity_db: Path, pihole_dir: Path) -> None:
        self.gravity_db = gravity_db
        self.pihole_dir = pihole_dir

    def summary(self) -> PiholeSummary:
        versions = self._read_versions()
        counts = self._read_counts()
        return PiholeSummary(
            core_version=versions.get("CORE_VERSION"),
            web_version=versions.get("WEB_VERSION"),
            ftl_version=versions.get("FTL_VERSION"),
            groups=counts.get("groups", 0),
            clients=counts.get("clients", 0),
            enabled_adlists=counts.get("enabled_adlists", 0),
            domainlist_entries=counts.get("domainlist_entries", 0),
            gravity_domains=counts.get("gravity_domains", 0),
        )

    def _read_versions(self) -> dict[str, str]:
        versions_file = self.pihole_dir / "versions"
        if not versions_file.exists():
            return {}
        versions: dict[str, str] = {}
        for line in versions_file.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            versions[key.strip()] = value.strip()
        return versions

    def _read_counts(self) -> dict[str, int]:
        if not self.gravity_db.exists():
            return {}
        conn = sqlite3.connect(f"file:{self.gravity_db}?mode=ro", uri=True)
        try:
            rows = conn.execute(
                """
                SELECT 'groups' AS key, count(*) AS value FROM [group]
                UNION ALL SELECT 'clients', count(*) FROM client
                UNION ALL SELECT 'enabled_adlists', count(*) FROM adlist WHERE enabled = 1
                UNION ALL SELECT 'domainlist_entries', count(*) FROM domainlist
                UNION ALL SELECT 'gravity_domains', count(*) FROM gravity
                """
            ).fetchall()
        finally:
            conn.close()
        return {str(key): int(value) for key, value in rows}


class PiholeQueryReader:
    """Read recent DNS query activity from pihole-FTL.db (read-only)."""

    def __init__(self, ftl_db: Path) -> None:
        self.ftl_db = ftl_db

    def recent_queries(
        self,
        *,
        client_ip: str | None = None,
        limit: int = 80,
        since_id: int = 0,
    ) -> list[QueryEvent]:
        if not self.ftl_db.exists():
            return []
        limit = max(1, min(int(limit), 250))
        since_id = max(0, int(since_id))
        conn = sqlite3.connect(f"file:{self.ftl_db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            if client_ip:
                rows = conn.execute(
                    """
                    SELECT id, timestamp, type, status, domain, client
                    FROM queries
                    WHERE id > ? AND client = ?
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (since_id, client_ip, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT id, timestamp, type, status, domain, client
                    FROM queries
                    WHERE id > ?
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (since_id, limit),
                ).fetchall()
        except sqlite3.Error:
            return []
        finally:
            conn.close()

        events = [_row_to_event(row) for row in rows]
        events.reverse()
        return events


def infer_service(domain: str) -> tuple[str, str]:
    lowered = (domain or "").lower().strip(".")
    if not lowered:
        return ("Unknown", "other")
    if _is_search_engine_host(lowered):
        if "bing." in lowered or lowered.endswith("bing.com"):
            return ("Bing", "search")
        if "duckduckgo." in lowered:
            return ("DuckDuckGo", "search")
        if "yahoo." in lowered:
            return ("Yahoo", "search")
        return ("Google", "search")
    for needle, service, category in SERVICE_HINTS:
        if needle in lowered:
            return (service, category)
    labels = [part for part in lowered.split(".") if part and part != "www"]
    if len(labels) >= 2:
        return (labels[-2].capitalize(), "website")
    return (lowered.capitalize(), "website")


def extract_search_query(domain: str) -> str | None:
    """Pull a search phrase out of a domain/URL-like DNS string when present."""
    raw = unquote_plus(domain or "")
    for pattern in SEARCH_QUERY_PATTERNS:
        match = pattern.search(raw)
        if not match:
            continue
        cleaned = _clean_search_text(match.group(1))
        if cleaned:
            return cleaned
    return None


def describe_activity(domain: str, service: str, category: str) -> tuple[str, str, str | None]:
    """Return (headline, detail, search_query) for a user-friendly live feed."""
    search_query = extract_search_query(domain)
    if search_query:
        return (f"[searched: {search_query}]", f"on {service}", search_query)

    lowered = (domain or "").lower().strip(".")
    if category == "search" or _is_search_engine_host(lowered):
        return (f"[searching: {service}]", _friendly_host(lowered), None)

    if category == "video" and service == "YouTube":
        return ("Watching YouTube", _friendly_host(lowered), None)
    if category == "cdn":
        return (f"Loading {service}", _friendly_host(lowered), None)

    verb = CATEGORY_VERBS.get(category, "Using")
    if category == "website":
        return (f"Visiting {service}", _friendly_host(lowered), None)
    return (f"{verb} {service}", _friendly_host(lowered), None)


def _is_search_engine_host(domain: str) -> bool:
    lowered = domain.lower().strip(".")
    if any(
        token in lowered
        for token in (
            "googleapis.",
            "gstatic.",
            "googleusercontent.",
            "googlevideo.",
            "youtube.",
            "ytimg.",
            "1e100.net",
            "doubleclick.",
            "app-measurement.",
        )
    ):
        return False
    search_hosts = (
        "google.com",
        "www.google.com",
        "google.co.",
        "www.google.co.",
        "bing.com",
        "www.bing.com",
        "duckduckgo.com",
        "www.duckduckgo.com",
        "search.yahoo.com",
    )
    if lowered in search_hosts or lowered.startswith("www.google.") or lowered.startswith("google.co."):
        return True
    labels = lowered.split(".")
    if len(labels) == 2 and labels[0] == "google" and labels[1] in {"com", "net", "org"}:
        return True
    return False


def _friendly_host(domain: str) -> str:
    lowered = (domain or "").lower().strip(".")
    if lowered.startswith("www."):
        return lowered[4:]
    return lowered or "unknown host"


def _clean_search_text(value: str) -> str:
    text = unquote_plus(value or "").replace("+", " ").strip()
    text = re.sub(r"\s+", " ", text)
    if len(text) < 2 or len(text) > 80:
        return ""
    if re.fullmatch(r"[0-9a-f]{16,}", text, re.I):
        return ""
    return text


def _row_to_event(row: sqlite3.Row) -> QueryEvent:
    status_code = int(row["status"] or 0)
    domain = str(row["domain"] or "")
    service, category = infer_service(domain)
    headline, detail, search_query = describe_activity(domain, service, category)
    return QueryEvent(
        id=int(row["id"]),
        timestamp=int(row["timestamp"] or 0),
        client_ip=str(row["client"] or ""),
        domain=domain,
        query_type=QUERY_TYPE_NAMES.get(int(row["type"] or 0), f"TYPE{row['type']}"),
        status=STATUS_LABELS.get(status_code, "unknown"),
        blocked=status_code in BLOCKED_STATUSES,
        service=service,
        category=category,
        headline=headline,
        detail=detail,
        search_query=search_query,
    )

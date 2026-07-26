from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import sqlite3
import subprocess
import time


# Exact domains that enable DNS bypass or common commercial telemetry/spyware SDKs.
# Intentionally avoids core Google/YouTube/Facebook app APIs so phones keep working.
DOH_EXACT_DOMAINS = (
    "chrome.cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "cloudflare-dns.com",
    "dns.cloudflare.com",
    "one.one.one.one",
    "1dot1dot1dot1.cloudflare-dns.com",
    "dns.google",
    "dns.google.com",
    "dns64.dns.google",
    "dns.quad9.net",
    "dns9.quad9.net",
    "dns10.quad9.net",
    "dns11.quad9.net",
    "doh.opendns.com",
    "doh.familyshield.opendns.com",
    "doh.sandbox.google",
    "dns.nextdns.io",
    "dns.adguard.com",
    "dns-family.adguard.com",
    "dns-unfiltered.adguard.com",
    "doh.dns.sb",
    "doh.pub",
    "dns.alidns.com",
    "doh.cleanbrowsing.org",
    "family-filter-dns.cleanbrowsing.org",
    "security-filter-dns.cleanbrowsing.org",
    "mask.icloud.com",
    "mask-h2.icloud.com",
    "use-application-dns.net",
    "dooh.default.prod.fastly.net",
)

TELEMETRY_EXACT_DOMAINS = (
    "app-measurement.com",
    "www.app-measurement.com",
    "region1.app-measurement.com",
    "firebaselogging-pa.googleapis.com",
    "firebaselogging.googleapis.com",
    "crashlyticsreports-pa.googleapis.com",
    "e.crashlytics.com",
    "reports.crashlytics.com",
    "settings.crashlytics.com",
    "firebase-settings.crashlytics.com",
    "ssl.google-analytics.com",
    "www.google-analytics.com",
    "analytics.google.com",
    "advertise.bingads.microsoft.com",
    "bat.bing.com",
    "adservice.google.com",
    "pagead2.googlesyndication.com",
    "googleadservices.com",
    "www.googleadservices.com",
    "doubleclick.net",
    "ad.doubleclick.net",
    "googleads.g.doubleclick.net",
    "stats.g.doubleclick.net",
    "securepubads.g.doubleclick.net",
    "graph.facebook.com",  # heavy tracking endpoint; Messenger/FB may degrade
    "pixel.facebook.com",
    "an.facebook.com",
    "adjust.com",
    "app.adjust.com",
    "appsflyer.com",
    "launches.appsflyer.com",
    "conversions.appsflyer.com",
    "api2.branch.io",
    "api.branch.io",
    "cdn.branch.io",
    "api.amplitude.com",
    "api2.amplitude.com",
    "api.mixpanel.com",
    "decide.mixpanel.com",
    "api.segment.io",
    "cdn.segment.com",
    "ingest.sentry.io",
    "browser.sentry-cdn.com",
    "api.bugsnag.com",
    "sessions.bugsnag.com",
    "notify.bugsnag.com",
    "api.telemetry.mozilla.org",
    "incoming.telemetry.mozilla.org",
    "telemetry.microsoft.com",
    "vortex.data.microsoft.com",
    "mobile.pipe.aria.microsoft.com",
    "self.events.data.microsoft.com",
)

# Regex blacklist entries (Pi-hole domainlist type=3).
TELEMETRY_REGEXES = (
    r"(^|\.)app-measurement\.com$",
    r"(^|\.)google-analytics\.com$",
    r"(^|\.)googletagmanager\.com$",
    r"(^|\.)googlesyndication\.com$",
    r"(^|\.)doubleclick\.net$",
    r"(^|\.)crashlytics\.com$",
    r"(^|\.)scorecardresearch\.com$",
    r"(^|\.)hotjar\.com$",
    r"(^|\.)fullstory\.com$",
    r"(^|\.)appsflyer\.com$",
    r"(^|\.)adjust\.com$",
    r"(^|\.)branch\.io$",
    r"(^|\.)amplitude\.com$",
    r"(^|\.)mixpanel\.com$",
    r"(^|\.)bugsnag\.com$",
    r"^chrome\.cloudflare-dns\.com$",
    r"(^|\.)cloudflare-dns\.com$",
    r"^dns\.google$",
    r"^dns\.google\.com$",
    r"(^|\.)quad9\.net$",
    r"(^|\.)nextdns\.io$",
)

# Safer core list applied by default (DoH + clear trackers). Omits graph.facebook.com
# and android.clients.google.com to reduce breakage; strict mode adds them.
SAFE_EXACT_DOMAINS = tuple(
    d for d in (*DOH_EXACT_DOMAINS, *TELEMETRY_EXACT_DOMAINS) if d != "graph.facebook.com"
)

STRICT_EXTRA_DOMAINS = (
    "graph.facebook.com",
    "android.clients.google.com",
    "device-provisioning.googleapis.com",
    "xgapromomanager-pa.googleapis.com",
    "proactivebackend-pa.googleapis.com",
    "searchnotifications-pa.googleapis.com",
)

COMMENT_TAG = "pi-circle-privacy-shield"


@dataclass(frozen=True)
class ShieldSyncResult:
    exact_upserted: int
    regex_upserted: int
    reloaded: bool
    detail: str


def classify_privacy_hit(domain: str) -> str | None:
    """Return risk class for a DNS name, or None if not in the shield catalog."""
    host = domain.strip(".").lower()
    if not host:
        return None
    if host in DOH_EXACT_DOMAINS or host.endswith(".cloudflare-dns.com") or host in {
        "dns.google",
        "dns.google.com",
    }:
        return "doh_bypass"
    if host in TELEMETRY_EXACT_DOMAINS or host in STRICT_EXTRA_DOMAINS:
        return "telemetry"
    for pattern in TELEMETRY_REGEXES:
        if re.search(pattern, host, flags=re.IGNORECASE):
            if "dns" in pattern or "cloudflare-dns" in pattern or "quad9" in pattern or "nextdns" in pattern:
                return "doh_bypass"
            return "telemetry"
    return None


def sync_pihole_denylist(
    gravity_db: Path,
    *,
    strict: bool = False,
    reload: bool = True,
) -> ShieldSyncResult:
    """Upsert Pi-Circle denylist into Pi-hole gravity domainlist."""
    if not gravity_db.exists():
        return ShieldSyncResult(0, 0, False, "gravity.db missing")

    exact = list(SAFE_EXACT_DOMAINS)
    if strict:
        exact.extend(STRICT_EXTRA_DOMAINS)
    # Dedupe preserve order
    seen: set[str] = set()
    exact_domains = []
    for domain in exact:
        if domain not in seen:
            seen.add(domain)
            exact_domains.append(domain)

    exact_count = 0
    regex_count = 0
    conn = sqlite3.connect(gravity_db)
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        for domain in exact_domains:
            exact_count += _upsert_domainlist(conn, domain_type=1, domain=domain)
        for pattern in TELEMETRY_REGEXES:
            regex_count += _upsert_domainlist(conn, domain_type=3, domain=pattern)
        conn.commit()
    finally:
        conn.close()

    reloaded = False
    detail = f"exact={exact_count} regex={regex_count}"
    if reload and (exact_count or regex_count):
        reloaded = _reload_pihole_lists()
        detail += "; reload=" + ("ok" if reloaded else "skipped")
    return ShieldSyncResult(exact_count, regex_count, reloaded, detail)


def scan_recent_privacy_hits(
    ftl_db: Path,
    *,
    window_seconds: int = 600,
    client_ip: str | None = None,
) -> list[dict[str, object]]:
    """Find recent DNS queries that match the privacy shield catalog."""
    if not ftl_db.exists():
        return []
    start = time.time() - max(60, int(window_seconds))
    conn = sqlite3.connect(f"file:{ftl_db}?mode=ro", uri=True)
    try:
        if client_ip:
            rows = conn.execute(
                """
                SELECT client, domain, COUNT(*) AS hits
                FROM queries
                WHERE timestamp >= ? AND client = ?
                GROUP BY client, domain
                """,
                (start, client_ip),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT client, domain, COUNT(*) AS hits
                FROM queries
                WHERE timestamp >= ?
                GROUP BY client, domain
                """,
                (start,),
            ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()

    hits: list[dict[str, object]] = []
    for client, domain, count in rows:
        kind = classify_privacy_hit(str(domain))
        if not kind:
            continue
        hits.append(
            {
                "client": str(client),
                "domain": str(domain),
                "hits": int(count or 0),
                "kind": kind,
            }
        )
    hits.sort(key=lambda item: (-int(item["hits"]), str(item["domain"])))
    return hits


def _upsert_domainlist(conn: sqlite3.Connection, *, domain_type: int, domain: str) -> int:
    existing = conn.execute(
        "SELECT id, enabled, comment FROM domainlist WHERE type = ? AND domain = ?",
        (domain_type, domain),
    ).fetchone()
    if existing:
        row_id, enabled, comment = existing
        comment_text = str(comment or "")
        if enabled and COMMENT_TAG in comment_text:
            return 0
        conn.execute(
            "UPDATE domainlist SET enabled = 1, comment = ? WHERE id = ?",
            (COMMENT_TAG if not comment_text else f"{comment_text}; {COMMENT_TAG}", row_id),
        )
        return 1
    conn.execute(
        """
        INSERT INTO domainlist(type, domain, enabled, date_added, date_modified, comment)
        VALUES(?, ?, 1, ?, ?, ?)
        """,
        (domain_type, domain, int(time.time()), int(time.time()), COMMENT_TAG),
    )
    return 1


def _reload_pihole_lists() -> bool:
    for args in (
        ["pihole", "reloadlists"],
        ["pihole", "restartdns", "reload-lists"],
        ["pihole", "reloaddns"],
    ):
        try:
            proc = subprocess.run(args, check=False, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0:
            return True
    return False

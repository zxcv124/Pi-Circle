from __future__ import annotations

import argparse
from datetime import datetime
import signal
import sys
import time

from .alerts import deliver_webhook, evaluate_alerts
from .audit import AuditEvent, AuditLogger
from .bandwidth import ensure_conntrack_accounting, sample_device_bandwidth
from .config import ConfigError, DEFAULT_CONFIG_PATH, load_settings
from .discovery_service import auto_link_androids, run_nmap_identification
from .enrollment import reconcile_enrolled_targets
from .inventory import sync_device_inventory
from .network import NetworkController
from .policy import blocked_ips_from_states, evaluate_all_policies
from .privacy_shield import sync_pihole_denylist
from .storage import Store
from .system import CommandRunner


class Agent:
    def __init__(self, config_path=DEFAULT_CONFIG_PATH, interval_seconds: int = 5) -> None:
        self.config_path = config_path
        self.interval_seconds = interval_seconds
        self._stopping = False
        self._previous_present: set[str] | None = None
        self._last_privacy_sync = 0.0
        self._nmap_scanned: dict[str, float] = {}
        self._last_nmap_pass = 0.0

    def run_forever(self) -> int:
        signal.signal(signal.SIGTERM, self._request_stop)
        signal.signal(signal.SIGINT, self._request_stop)

        settings = load_settings(self.config_path)
        store = Store(settings.paths.database)
        store.initialize()
        audit = AuditLogger(settings.paths.audit_log)
        controller = NetworkController(CommandRunner(), audit)
        ensure_conntrack_accounting()
        self._sync_privacy_shield(settings, audit, force=True)
        audit.write(AuditEvent("agent.started", "system", "success", "agent process started"))

        while not self._stopping:
            try:
                settings = load_settings(self.config_path)
                self._sync_privacy_shield(settings, audit, force=False)
                observed_ips = sync_device_inventory(settings, store, probe=True, full_scan=False)

                if settings.discovery.use_nmap and time.time() - self._last_nmap_pass >= 60:
                    nmap_result = run_nmap_identification(
                        store,
                        observed_ips,
                        recently_scanned=self._nmap_scanned,
                        max_hosts=settings.discovery.nmap_max_hosts,
                        min_interval_seconds=settings.discovery.nmap_interval_seconds,
                    )
                    self._last_nmap_pass = time.time()
                    if nmap_result.get("scanned"):
                        audit.write(
                            AuditEvent(
                                "discovery.nmap",
                                "agent",
                                "success",
                                f"nmap scanned {len(nmap_result['scanned'])} host(s), updated {nmap_result.get('updated', 0)}",
                            )
                        )

                linked_androids = auto_link_androids(settings, store, observed_ips)
                if linked_androids:
                    audit.write(
                        AuditEvent(
                            "enrollment.android_auto",
                            "agent",
                            "success",
                            f"Auto-linked Android device(s): {', '.join(linked_androids)}",
                        )
                    )

                changed = reconcile_enrolled_targets(
                    store,
                    [str(target) for target in settings.network.arp_assisted_targets],
                    observed_ips,
                )
                if changed is not None:
                    settings = load_settings(self.config_path)
                    audit.write(
                        AuditEvent(
                            "enrollment.reconciled",
                            "agent",
                            "success",
                            f"ARP targets synced to {len(changed)} enrolled device(s)",
                        )
                    )

                now = datetime.now().astimezone()
                linked_ips = {str(target) for target in settings.network.arp_assisted_targets}
                self._tick_usage(store, observed_ips, linked_ips, now)
                states = evaluate_all_policies(store, linked_ips=linked_ips, now=now)
                blocked = blocked_ips_from_states(states)

                health = controller.apply(settings.network, blocked_ips=blocked)
                store.set_network_health(settings.network.mode, health.healthy, health.summary)
                if linked_ips:
                    for sample in sample_device_bandwidth(linked_ips).values():
                        store.record_bandwidth_sample(
                            sample.ip_address,
                            bytes_total=sample.bytes_total,
                            packets_total=sample.packets_total,
                            connections=sample.connections,
                            source=sample.source,
                            sampled_at=sample.sampled_at,
                        )

                known_before = self._previous_present if self._previous_present is not None else set(observed_ips)
                for draft in evaluate_alerts(
                    store,
                    ftl_db=settings.pihole.ftl_db,
                    present_ips=observed_ips,
                    known_ips_before=known_before,
                    now=now,
                ):
                    if draft.alert_type in {"doh_bypass", "telemetry"} and not settings.privacy.alert_on_hits:
                        continue
                    alert = store.add_alert(
                        alert_type=draft.alert_type,
                        severity=draft.severity,
                        title=draft.title,
                        detail=draft.detail,
                        subject=draft.subject,
                    )
                    if settings.security.alert_webhook_url:
                        deliver_webhook(settings.security.alert_webhook_url, alert)
                self._previous_present = set(observed_ips)
            except Exception as exc:
                store.set_network_health("unknown", False, str(exc))
                audit.write(AuditEvent("agent.loop.failed", "agent", "failure", str(exc)))
            time.sleep(self.interval_seconds)

        controller.stop_arp_assisted("system", "agent stopping")
        audit.write(AuditEvent("agent.stopped", "system", "success", "agent process stopped"))
        return 0

    def _sync_privacy_shield(self, settings, audit: AuditLogger, *, force: bool) -> None:
        if not settings.privacy.enabled or not settings.privacy.sync_pihole_denylist:
            return
        now = time.time()
        if not force and now - self._last_privacy_sync < 3600:
            return
        result = sync_pihole_denylist(
            settings.pihole.gravity_db,
            strict=settings.privacy.strict,
            reload=True,
        )
        self._last_privacy_sync = now
        audit.write(
            AuditEvent(
                "privacy.shield.synced",
                "agent",
                "success" if result.exact_upserted or result.regex_upserted or result.reloaded else "noop",
                result.detail,
            )
        )

    def _tick_usage(self, store: Store, observed_ips: set[str], linked_ips: set[str], now: datetime) -> None:
        """Count online minutes toward daily budgets when not paused/in bedtime."""
        day = now.strftime("%Y-%m-%d")
        profiles = {profile.id: profile for profile in store.list_profiles()}
        increment = max(self.interval_seconds, 1) / 60.0
        for device in store.list_devices():
            if device.ip_address not in observed_ips:
                continue
            if device.ip_address not in linked_ips and not (device.managed or device.transparent_control):
                continue
            if device.paused:
                continue
            profile = profiles.get(device.profile_id) if device.profile_id else None
            if profile is None or not profile.daily_minutes:
                continue
            from .policy import is_bedtime_active

            if is_bedtime_active(profile.bedtime_start, profile.bedtime_end, now=now):
                continue
            store.add_usage_minutes(device.ip_address, day, increment)

    def _request_stop(self, _signum, _frame) -> None:
        self._stopping = True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Pi-Circle appliance agent")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    parser.add_argument("--interval", type=int, default=5)
    args = parser.parse_args(argv)
    try:
        return Agent(args.config, args.interval).run_forever()
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

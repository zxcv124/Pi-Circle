from __future__ import annotations

import argparse
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
import json
import os
import subprocess
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import uvicorn

from .api_response import failure as api_failure
from .api_response import success as api_success
from .analytics import QueryAnalytics
from .bandwidth import list_active_connections, sample_device_bandwidth, summarize_flows
from .config import DEFAULT_CONFIG_PATH, load_settings
from .discovery_service import auto_link_androids, run_nmap_identification
from .history import HistoryReader
from .inventory import sync_device_inventory
from .pihole import PiholeQueryReader, PiholeStateReader
from . import pihole_control
from .policy import evaluate_all_policies, evaluate_device_policy
from .protection_db import ProtectionDatabaseReader
from .reports import ReportBuilder, ReportRequest
from .setup_health import evaluate_setup
from .system_health import capability_report, system_health
from .storage import DEVICE_TYPES, Store


SOURCE_ROOT = Path(__file__).resolve().parents[2]
WEB_DIR = Path(os.environ.get("PI_CIRCLE_WEB_DIR", SOURCE_ROOT / "web"))
ARP_TARGET_HELPER = Path("/usr/local/sbin/pi-circle-set-arp-assisted-targets")
EMERGENCY_DNS_ONLY_HELPER = Path("/usr/local/sbin/pi-circle-emergency-dns-only")
NETWORK_FLAGS_HELPER = Path("/usr/local/sbin/pi-circle-set-network-flags")


class DeviceControlRequest(BaseModel):
    enabled: bool


class TargetSetRequest(BaseModel):
    targets: list[str] = Field(default_factory=list, max_length=64)


class DeviceIdentityRequest(BaseModel):
    display_name: str | None = Field(default=None, max_length=80)
    device_type: str = "unknown"


class DeviceProfileRequest(BaseModel):
    profile_id: int | None = None


class ProfileCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=48)
    description: str = Field(default="", max_length=160)


class DeviceRefreshRequest(BaseModel):
    full: bool = False


class ProfileUpdateRequest(BaseModel):
    description: str | None = Field(default=None, max_length=160)
    bedtime_start: str | None = Field(default=None, max_length=5)
    bedtime_end: str | None = Field(default=None, max_length=5)
    daily_minutes: int | None = Field(default=None, ge=0, le=1440)
    clear_bedtime: bool = False
    clear_daily_minutes: bool = False


class PiholeDisableRequest(BaseModel):
    duration: str | None = Field(default=None, max_length=8)


class PiholeDomainRequest(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    action: str = Field(default="add", max_length=16)


class PiholeGravityRequest(BaseModel):
    force: bool = False


class ProtectionLookupRequest(BaseModel):
    domain: str = Field(min_length=1, max_length=253)


class AccessRequestCreateRequest(BaseModel):
    device_ip: str = Field(min_length=7, max_length=45)
    domain: str = Field(min_length=1, max_length=253)
    service: str | None = Field(default=None, max_length=80)
    reason: str = Field(default="", max_length=240)


class AccessRequestDecisionRequest(BaseModel):
    decision: str = Field(min_length=3, max_length=32)


class CommunitySettingsRequest(BaseModel):
    mode: str = Field(min_length=3, max_length=32)
    organization_name: str = Field(default="", max_length=80)


class NetworkSettingsRequest(BaseModel):
    force_ipv4: bool = True
    force_pi_dns: bool = True


class RetentionSettingsRequest(BaseModel):
    detailed_activity_days: int | None = Field(default=None, ge=1, le=3650)
    alert_days: int | None = Field(default=None, ge=1, le=3650)
    health_history_days: int | None = Field(default=None, ge=1, le=3650)
    audit_log_days: int | None = Field(default=None, ge=1, le=3650)
    report_days: int | None = Field(default=None, ge=1, le=3650)


def create_app(config_path: Path = DEFAULT_CONFIG_PATH) -> FastAPI:
    settings = load_settings(config_path)
    store = Store(settings.paths.database)
    store.initialize()

    app = FastAPI(title="Pi-Circle Dashboard", version="0.1.0")
    app.state.config_path = config_path
    app.state.store = store
    app.state.cache = {}

    static_dir = WEB_DIR / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        index_path = WEB_DIR / "templates" / "index.html"
        if not index_path.exists():
            raise HTTPException(status_code=500, detail="Dashboard template missing")
        return index_path.read_text(encoding="utf-8")

    @app.head("/", response_class=HTMLResponse)
    def index_head() -> str:
        return ""

    @app.get("/api/health")
    def health() -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        health_state = app.state.store.get_network_health()
        return {
            "appliance": "pi-circle",
            "mode": current_settings.network.mode,
            "interface": current_settings.network.interface,
            "lanCidr": str(current_settings.network.lan_cidr),
            "gatewayIp": str(current_settings.network.gateway_ip),
            "network": health_state,
        }

    @app.get("/api/devices")
    def devices(request: Request, scan: bool = True) -> list[dict[str, object]]:
        current_settings = load_settings(app.state.config_path)
        # Light active probe so reconnecting phones reappear without a manual full scan.
        present_ips = sync_device_inventory(current_settings, app.state.store, probe=scan, full_scan=False)
        return _serialize_devices(app.state.store, present_ips)

    @app.get("/api/profiles")
    def profiles() -> list[dict[str, object]]:
        return [profile.__dict__ for profile in app.state.store.list_profiles()]

    @app.post("/api/profiles")
    def create_profile(payload: ProfileCreateRequest, request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        try:
            profile = app.state.store.create_profile(payload.name, payload.description)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"profile": profile.__dict__}

    @app.post("/api/devices/refresh")
    def refresh_devices(request: Request, payload: DeviceRefreshRequest = DeviceRefreshRequest()) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        full = bool(payload.full)
        present_ips = sync_device_inventory(
            current_settings,
            app.state.store,
            probe=True,
            full_scan=full,
        )
        labeled = app.state.store.relabel_discovered_devices(gateway_ip=str(current_settings.network.gateway_ip))
        return {
            "devices": _serialize_devices(app.state.store, present_ips),
            "autoLabeled": labeled,
            "presentCount": len(present_ips),
            "fullScan": full,
        }

    @app.post("/api/devices/identify")
    def identify_devices(request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        present_ips = sync_device_inventory(current_settings, app.state.store, probe=True, full_scan=True)
        labeled = app.state.store.relabel_discovered_devices(gateway_ip=str(current_settings.network.gateway_ip))
        nmap_result: dict[str, object] = {"available": False, "scanned": [], "updated": 0}
        if current_settings.discovery.use_nmap:
            # Force a fresh nmap pass over currently present hosts (Relabel button).
            cache: dict[str, float] = {}
            nmap_result = run_nmap_identification(
                app.state.store,
                present_ips,
                recently_scanned=cache,
                max_hosts=current_settings.discovery.nmap_max_hosts,
                min_interval_seconds=0,
                force_ips=present_ips,
            )
        linked = auto_link_androids(current_settings, app.state.store, present_ips)
        return {
            "autoLabeled": labeled,
            "nmap": nmap_result,
            "autoLinkedAndroid": linked,
            "devices": _serialize_devices(app.state.store, present_ips),
            "presentCount": len(present_ips),
        }

    @app.get("/api/devices/{device_ip}/page")
    def device_page(device_ip: str, request: Request, limit: int = 80) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        target = _validate_lan_ip(device_ip, current_settings)
        sync_device_inventory(current_settings, app.state.store, probe=True, full_scan=False)
        device = app.state.store.get_device(target)
        if device is None:
            raise HTTPException(status_code=404, detail=f"Device not found: {target}")
        reader = PiholeQueryReader(current_settings.pihole.ftl_db)
        analytics = QueryAnalytics(current_settings.pihole.ftl_db)
        events = reader.recent_queries(client_ip=target, limit=max(1, min(limit, 200)))
        names = _device_display_names(app.state.store)
        payload = []
        searches = []
        service_counts: dict[str, int] = {}
        for event in events:
            item = event.to_dict()
            item["device_name"] = names.get(event.client_ip) or event.client_ip
            payload.append(item)
            service_counts[event.service] = service_counts.get(event.service, 0) + 1
            if event.search_query or event.category == "search":
                searches.append(item)
        top_services = sorted(
            [{"service": name, "count": count} for name, count in service_counts.items()],
            key=lambda row: (-int(row["count"]), str(row["service"])),
        )[:8]
        linked = target in {str(value) for value in current_settings.network.arp_assisted_targets}
        bandwidth = app.state.store.bandwidth_rates({target}).get(target)
        if linked and bandwidth is None:
            sample = sample_device_bandwidth({target}).get(target)
            bandwidth = sample.to_dict() if sample else None
        connections = list_active_connections(target, limit=32, resolve_hosts=True) if linked else []
        exclude_remotes = _flow_exclude_remotes(current_settings, target)
        flow_summary = (
            summarize_flows(connections, top_limit=8, exclude_remotes=exclude_remotes)
            if linked
            else {"protocols": [], "topRemotes": [], "flowCount": 0}
        )
        bandwidth_series = (
            app.state.store.bandwidth_series(target, window_seconds=600, bucket_seconds=15) if linked else []
        )
        series = [bucket.to_dict() for bucket in analytics.traffic_series(window_seconds=600, bucket_seconds=10, client_ip=target)]
        live = payload[-60:]
        last_dns_at = live[-1]["timestamp"] if live else None
        dns_age = None if last_dns_at is None else max(0, int(time.time()) - int(last_dns_at))
        policy = _policy_for_device(app.state.store, device, linked=linked)
        history = HistoryReader(current_settings.pihole.ftl_db).timeline(window="24h", client_ip=target)
        return {
            "device": device.__dict__,
            "linked": linked,
            "policy": policy.to_dict(),
            "live": live,
            "searches": searches[-40:],
            "topServices": top_services,
            "stats": analytics.overview(window_seconds=3600, client_ip=target, top_limit=8),
            "series": series,
            "history": history,
            "bandwidth": bandwidth,
            "bandwidthSeries": bandwidth_series,
            "connections": connections,
            "protocols": flow_summary["protocols"],
            "topRemotes": flow_summary["topRemotes"],
            "flowCount": flow_summary["flowCount"],
            "lastDnsAt": last_dns_at,
            "dnsAgeSeconds": dns_age,
            "dnsSilent": dns_age is None or dns_age > 90,
            "note": "Pause/bedtime apply to linked devices via the agent within a few seconds.",
        }

    @app.post("/api/devices/{device_ip}/pause")
    def set_device_pause(device_ip: str, payload: DeviceControlRequest, request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        target = _validate_lan_ip(device_ip, current_settings)
        try:
            device = app.state.store.set_device_paused(target, payload.enabled)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=f"Device not found: {target}") from exc
        linked = target in {str(value) for value in current_settings.network.arp_assisted_targets} or bool(
            device.transparent_control or device.managed
        )
        policy = _policy_for_device(app.state.store, device, linked=linked)
        return {
            "device": device.__dict__,
            "policy": policy.to_dict(),
            "message": (
                "Paused — internet will cut for this linked device shortly."
                if payload.enabled and linked
                else "Pause saved. Link this device to enforce the block."
                if payload.enabled
                else "Resumed — internet will restore shortly if linked."
            ),
        }

    @app.post("/api/devices/{device_ip}/arp-assisted")
    def set_device_arp_assisted(device_ip: str, payload: DeviceControlRequest, request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        target = _validate_target(device_ip, current_settings)
        present_ips = sync_device_inventory(current_settings, app.state.store, probe=True, full_scan=False)
        try:
            app.state.store.set_device_enrollment(target, payload.enabled)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=f"Device not found: {target}") from exc
        targets = {
            device.ip_address
            for device in app.state.store.list_devices()
            if device.transparent_control and (device.ip_address in present_ips or payload.enabled)
        }
        if payload.enabled:
            targets.add(target)
        else:
            targets.discard(target)
        _set_arp_targets(sorted(targets, key=_ipv4_sort_key))
        return _control_response(app)

    @app.post("/api/devices/{device_ip}/identity")
    def set_device_identity(device_ip: str, payload: DeviceIdentityRequest, request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        target = _validate_lan_ip(device_ip, current_settings)
        if payload.device_type not in DEVICE_TYPES:
            raise HTTPException(status_code=400, detail=f"Unsupported device type: {payload.device_type}")
        try:
            device = app.state.store.update_device_identity(target, payload.display_name, payload.device_type)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"device": device.__dict__}

    @app.post("/api/devices/{device_ip}/profile")
    def set_device_profile(device_ip: str, payload: DeviceProfileRequest, request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        target = _validate_lan_ip(device_ip, current_settings)
        try:
            device = app.state.store.assign_device_profile(target, payload.profile_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        linked = target in {str(value) for value in current_settings.network.arp_assisted_targets} or bool(
            device.transparent_control or device.managed
        )
        return {
            "device": device.__dict__,
            "policy": _policy_for_device(app.state.store, device, linked=linked).to_dict(),
        }

    @app.patch("/api/profiles/{profile_id}")
    def update_profile(profile_id: int, payload: ProfileUpdateRequest, request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        try:
            profile = app.state.store.update_profile(
                profile_id,
                description=payload.description,
                bedtime_start=payload.bedtime_start,
                bedtime_end=payload.bedtime_end,
                daily_minutes=payload.daily_minutes,
                clear_bedtime=payload.clear_bedtime,
                clear_daily_minutes=payload.clear_daily_minutes,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=f"Unknown profile: {profile_id}") from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"profile": profile.__dict__}

    @app.get("/api/policy")
    def policy_overview(request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        linked = {str(target) for target in current_settings.network.arp_assisted_targets}
        states = evaluate_all_policies(app.state.store, linked_ips=linked)
        return {
            "generatedAt": datetime.now().astimezone().isoformat(),
            "devices": [state.to_dict() for state in states],
            "blockedCount": sum(1 for state in states if state.blocked),
        }

    @app.get("/api/history")
    def history(request: Request, window: str = "24h", client: str | None = None) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        client_ip = _validate_lan_ip(client, current_settings) if client else None
        if window not in {"1h", "24h", "7d"}:
            raise HTTPException(status_code=400, detail="window must be 1h, 24h, or 7d")
        reader = HistoryReader(current_settings.pihole.ftl_db)
        return reader.timeline(window=window, client_ip=client_ip)

    @app.get("/api/alerts")
    def alerts(request: Request, include_acked: bool = False, limit: int = 50) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        items = app.state.store.list_alerts(include_acked=include_acked, limit=limit)
        return {
            "alerts": items,
            "unackedCount": sum(1 for item in app.state.store.list_alerts(include_acked=False, limit=200) if not item["acked"]),
        }

    @app.post("/api/alerts/{alert_id}/ack")
    def ack_alert(alert_id: int, request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        if not app.state.store.ack_alert(alert_id):
            raise HTTPException(status_code=404, detail="Alert not found")
        return {"ok": True, "id": alert_id}

    @app.post("/api/alerts/ack-all")
    def ack_all_alerts(request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        count = app.state.store.ack_all_alerts()
        return {"ok": True, "acked": count}

    @app.get("/api/setup")
    def setup_status(request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        present_ips = sync_device_inventory(current_settings, app.state.store, probe=False, full_scan=False)
        return evaluate_setup(current_settings, app.state.store, present_count=len(present_ips))

    @app.get("/api/setup/capabilities")
    def setup_capabilities(request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        return _cached(app, "setup-capabilities", 10, lambda: _capability_payload(app, current_settings))

    @app.post("/api/arp-assisted/targets")
    def set_arp_assisted_targets(payload: TargetSetRequest, request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        targets = sorted({_validate_target(target, current_settings) for target in payload.targets}, key=_ipv4_sort_key)
        _set_arp_targets(targets)
        return _control_response(app)

    @app.post("/api/network/rollback")
    def rollback_network(request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        for device in app.state.store.list_devices():
            if device.transparent_control:
                app.state.store.set_device_enrollment(device.ip_address, False)
        _set_arp_targets([])
        return _control_response(app)

    @app.post("/api/network/emergency-dns-only")
    def emergency_dns_only(request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        cleared = app.state.store.clear_device_enrollments()
        result = _emergency_dns_only()
        app.state.store.set_network_health("dns_only", True, "Emergency DNS-only recovery applied")
        return {
            "ok": True,
            "clearedEnrollments": cleared,
            "result": result,
            "control": _control_response(app),
        }

    @app.get("/api/config-summary")
    def config_summary(request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        client_host = request.client.host if request.client else None
        return {
            "adminSource": client_host,
            "dashboard": {
                "host": current_settings.dashboard.host,
                "port": current_settings.dashboard.port,
            },
            "security": {
                "requireLanAdmin": current_settings.security.require_lan_admin,
                "sessionMinutes": current_settings.security.session_minutes,
            },
            "transparentControl": {
                "enabled": current_settings.network.arp_assisted_enabled,
                "targetCount": len(current_settings.network.arp_assisted_targets),
                "targets": [str(target) for target in current_settings.network.arp_assisted_targets],
                "dnsRedirect": current_settings.network.dns_redirect_port_53,
                "forceIpv4": current_settings.network.force_ipv4,
            },
        }

    @app.get("/api/network/settings")
    def network_settings(request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        return _network_settings_payload(current_settings)

    @app.patch("/api/network/settings")
    def update_network_settings(payload: NetworkSettingsRequest, request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        _set_network_flags(force_ipv4=bool(payload.force_ipv4), force_pi_dns=bool(payload.force_pi_dns))
        updated = load_settings(app.state.config_path)
        return _network_settings_payload(updated)

    @app.get("/api/pihole")
    def pihole_summary() -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        reader = PiholeStateReader(current_settings.pihole.gravity_db, current_settings.paths.pihole_dir)
        summary = reader.summary().to_dict()
        control = pihole_control.read_status(pihole_dir=current_settings.paths.pihole_dir)
        summary.update(
            {
                "installed": control.installed,
                "blocking_enabled": control.blocking_enabled,
                "ftl_listening": control.ftl_listening,
                "status_raw": control.raw,
                "gravity_update": control.gravity_update,
                "engine": "Pi-hole",
                "credit": "DNS engine by Pi-hole (https://pi-hole.net/)",
            }
        )
        return summary

    @app.get("/api/pihole/status")
    def pihole_status(request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        return pihole_control.read_status(pihole_dir=current_settings.paths.pihole_dir).to_dict()

    @app.get("/api/alerts/evidence")
    def alert_evidence(
        request: Request,
        client: str,
        window: int = 300,
        until: int | None = None,
        focus: str = "blocked",
        limit: int = 40,
    ) -> dict[str, object]:
        """Domains involved in an alert window for a device (for the alert report UI)."""
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        client_ip = _validate_lan_ip(client, current_settings)
        analytics = QueryAnalytics(current_settings.pihole.ftl_db)
        evidence = analytics.domain_evidence(
            client_ip=client_ip,
            window_seconds=window,
            until_ts=until,
            focus=focus,
            limit=limit,
        )
        evidence["deviceName"] = _device_display_names(app.state.store).get(client_ip) or client_ip
        return evidence

    @app.get("/api/protection/database")
    def protection_database(request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        return _cached(
            app,
            "protection-database",
            30,
            lambda: {"summary": ProtectionDatabaseReader(current_settings.pihole.gravity_db).summary().to_dict()},
        )

    @app.get("/api/protection/blocklists")
    def protection_blocklists(request: Request, limit: int = 100) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        safe_limit = max(1, min(int(limit), 500))
        return _cached(
            app,
            f"protection-blocklists:{safe_limit}",
            30,
            lambda: {"blocklists": ProtectionDatabaseReader(current_settings.pihole.gravity_db).blocklists(limit=safe_limit)},
        )

    @app.post("/api/protection/lookup")
    def protection_lookup(request: Request, payload: ProtectionLookupRequest) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        try:
            domain = pihole_control.validate_domain(payload.domain)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        reader = ProtectionDatabaseReader(current_settings.pihole.gravity_db)
        return {"lookup": reader.lookup(domain)}

    @app.get("/api/access-requests")
    def access_requests(request: Request, include_decided: bool = True, limit: int = 50) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        return {
            "requests": app.state.store.list_access_requests(include_decided=include_decided, limit=limit),
            "deviceNames": _device_display_names(app.state.store),
        }

    @app.post("/api/access-requests")
    def create_access_request(payload: AccessRequestCreateRequest, request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        device_ip = _validate_lan_ip(payload.device_ip, current_settings)
        try:
            domain = pihole_control.validate_domain(payload.domain)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            item = app.state.store.create_access_request(
                device_ip=device_ip,
                domain=domain,
                service=payload.service,
                reason=payload.reason,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"request": item}

    @app.post("/api/access-requests/{request_id}/decision")
    def decide_access_request(request_id: int, payload: AccessRequestDecisionRequest, request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        decision = payload.decision.strip().lower()
        if decision in {"allow_once", "allow_15m", "allow_1h"}:
            raise HTTPException(
                status_code=501,
                detail=(
                    "Temporary access requires an expiry worker before Pi-Circle can safely add and remove "
                    "global Pi-hole allow rules."
                ),
            )
        item = app.state.store.get_access_request(request_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Access request not found")
        result = None
        if decision == "always_allow":
            try:
                result = pihole_control.allow_domains([str(item["domain"])])
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            if not result.ok:
                raise HTTPException(status_code=500, detail=result.stderr or result.stdout or "Allowlist update failed")
        elif decision != "deny":
            raise HTTPException(status_code=400, detail="Unsupported access request decision")
        try:
            updated = app.state.store.decide_access_request(request_id, decision=decision)
        except (LookupError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"request": updated, "result": result.to_dict() if result else None}

    @app.get("/api/reports")
    def report_summary(request: Request, period: str = "daily", privacy_level: str = "family") -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        return _cached(
            app,
            f"report:{period}:{privacy_level}",
            15,
            lambda: _report_payload(current_settings, app.state.store, period, privacy_level),
        )

    @app.get("/api/reports/export.csv")
    def report_csv(request: Request, period: str = "daily", privacy_level: str = "family") -> Response:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        report_request = ReportRequest(period=period, privacy_level=privacy_level)
        csv_text = ReportBuilder(current_settings.pihole.ftl_db, app.state.store).csv(report_request)
        filename = f"pi-circle-{report_request.period}-{report_request.privacy_level}.csv"
        return Response(
            csv_text,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/api/system/health")
    def system_health_endpoint(request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        return _cached(app, "system-health", 5, lambda: {"health": system_health(current_settings)})

    @app.get("/api/security/status")
    def security_status(request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        return _security_payload(current_settings)

    @app.get("/api/audit")
    def audit_events(request: Request, limit: int = 40) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        return {"events": _read_audit_events(current_settings.paths.audit_log, limit=limit)}

    @app.get("/api/community")
    def community_settings(request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        settings_payload = app.state.store.get_community_settings()
        return {"settings": settings_payload, "preview": _community_preview(settings_payload)}

    @app.patch("/api/community")
    def update_community_settings(payload: CommunitySettingsRequest, request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        try:
            settings_payload = app.state.store.update_community_settings(
                mode=payload.mode,
                organization_name=payload.organization_name,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"settings": settings_payload, "preview": _community_preview(settings_payload)}

    @app.get("/api/retention")
    def retention_settings(request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        return app.state.store.retention_summary()

    @app.patch("/api/retention")
    def update_retention_settings(payload: RetentionSettingsRequest, request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        try:
            app.state.store.update_retention_settings(
                detailed_activity_days=payload.detailed_activity_days,
                alert_days=payload.alert_days,
                health_history_days=payload.health_history_days,
                audit_log_days=payload.audit_log_days,
                report_days=payload.report_days,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return app.state.store.retention_summary()

    @app.get("/api/v1/dashboard/summary")
    def v1_dashboard_summary(request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        health_payload = _cached(app, "system-health", 5, lambda: {"health": system_health(current_settings)})
        capabilities_payload = _cached(app, "setup-capabilities", 10, lambda: _capability_payload(app, current_settings))
        return api_success(
            {
                "health": health_payload["health"],
                "capabilities": capabilities_payload.get("capabilities", []),
                "retention": app.state.store.retention_summary(),
            }
        )

    @app.get("/api/v1/system/health")
    def v1_system_health(request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        return api_success(_cached(app, "system-health", 5, lambda: {"health": system_health(current_settings)})["health"])

    @app.get("/api/v1/reports")
    def v1_reports(request: Request, period: str = "daily", privacy_level: str = "family") -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        try:
            payload = _cached(
                app,
                f"report:{period}:{privacy_level}",
                15,
                lambda: _report_payload(current_settings, app.state.store, period, privacy_level),
            )
        except ValueError as exc:
            return api_failure("INVALID_REPORT_REQUEST", str(exc))
        return api_success(payload["report"])

    @app.get("/api/v1/security/status")
    def v1_security_status(request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        return api_success(_security_payload(current_settings)["security"])

    @app.get("/api/v1/retention")
    def v1_retention(request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        return api_success(app.state.store.retention_summary())

    @app.post("/api/pihole/enable")
    def pihole_enable(request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        result = pihole_control.enable_blocking()
        if not result.ok:
            raise HTTPException(status_code=500, detail=result.stderr or result.stdout or "Enable failed")
        status = pihole_control.read_status(pihole_dir=current_settings.paths.pihole_dir)
        return {"result": result.to_dict(), "status": status.to_dict()}

    @app.post("/api/pihole/disable")
    def pihole_disable(request: Request, payload: PiholeDisableRequest) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        try:
            result = pihole_control.disable_blocking(payload.duration)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not result.ok:
            raise HTTPException(status_code=500, detail=result.stderr or result.stdout or "Disable failed")
        status = pihole_control.read_status(pihole_dir=current_settings.paths.pihole_dir)
        return {"result": result.to_dict(), "status": status.to_dict()}

    @app.post("/api/pihole/gravity")
    def pihole_gravity(request: Request, payload: PiholeGravityRequest) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        result = pihole_control.update_gravity(force=payload.force)
        if not result.ok:
            raise HTTPException(status_code=500, detail=result.stderr or result.stdout or "Gravity update failed")
        reader = PiholeStateReader(current_settings.pihole.gravity_db, current_settings.paths.pihole_dir)
        return {"result": result.to_dict(), "summary": reader.summary().to_dict()}

    @app.post("/api/pihole/reload")
    def pihole_reload(request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        result = pihole_control.reload_dns()
        if not result.ok:
            raise HTTPException(status_code=500, detail=result.stderr or result.stdout or "Reload failed")
        return {"result": result.to_dict()}

    @app.post("/api/pihole/flush")
    def pihole_flush(request: Request) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        result = pihole_control.flush_log()
        if not result.ok:
            raise HTTPException(status_code=500, detail=result.stderr or result.stdout or "Flush failed")
        return {"result": result.to_dict()}

    @app.post("/api/pihole/allow")
    def pihole_allow(request: Request, payload: PiholeDomainRequest) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        try:
            if payload.action == "remove":
                result = pihole_control.remove_allow_domains([payload.domain])
            else:
                result = pihole_control.allow_domains([payload.domain])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not result.ok:
            raise HTTPException(status_code=500, detail=result.stderr or result.stdout or "Allowlist update failed")
        return {"result": result.to_dict()}

    @app.post("/api/pihole/deny")
    def pihole_deny(request: Request, payload: PiholeDomainRequest) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        try:
            if payload.action == "remove":
                result = pihole_control.remove_deny_domains([payload.domain])
            else:
                result = pihole_control.deny_domains([payload.domain])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not result.ok:
            raise HTTPException(status_code=500, detail=result.stderr or result.stdout or "Denylist update failed")
        return {"result": result.to_dict()}

    @app.get("/api/activity/live")
    def live_activity(
        request: Request,
        client: str | None = None,
        limit: int = 80,
        since_id: int = 0,
        category: str | None = None,
        service: str | None = None,
        status: str | None = None,
        q: str | None = None,
    ) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        client_ip = None
        if client:
            client_ip = _validate_lan_ip(client, current_settings)
        reader = PiholeQueryReader(current_settings.pihole.ftl_db)
        # Over-fetch when filters are active so the UI still feels dense.
        fetch_limit = max(1, min(limit * 4 if any([category, service, status, q]) else limit, 250))
        events = reader.recent_queries(client_ip=client_ip, limit=fetch_limit, since_id=since_id)
        names = _device_display_names(app.state.store)
        needle = (q or "").strip().lower()
        payload = []
        for event in events:
            if category and event.category != category:
                continue
            if service and service.lower() not in event.service.lower():
                continue
            if status == "blocked" and not event.blocked:
                continue
            if status in {"allowed", "cached"} and event.status != status:
                continue
            if needle and needle not in " ".join(
                [event.headline, event.detail, event.domain, event.service, event.client_ip, names.get(event.client_ip, "")]
            ).lower():
                continue
            item = event.to_dict()
            item["device_name"] = names.get(event.client_ip) or event.client_ip
            payload.append(item)
            if len(payload) >= max(1, min(limit, 250)):
                break
        return {
            "source": "pihole-dns",
            "note": "Household live view from Pi-hole DNS — richer than packet volume alone: searches, apps, and blocked ads.",
            "events": payload,
            "latestId": payload[-1]["id"] if payload else since_id,
            "filters": {
                "client": client_ip,
                "category": category,
                "service": service,
                "status": status,
                "q": q,
            },
        }

    @app.get("/api/analytics/overview")
    def analytics_overview(
        request: Request,
        window: int = 3600,
        client: str | None = None,
    ) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        client_ip = _validate_lan_ip(client, current_settings) if client else None
        analytics = QueryAnalytics(current_settings.pihole.ftl_db)
        overview = analytics.overview(window_seconds=window, client_ip=client_ip, top_limit=10)
        series = analytics.traffic_series(window_seconds=min(window, 1800), bucket_seconds=10 if window <= 900 else 30, client_ip=client_ip)
        names = _device_display_names(app.state.store)
        for row in overview.get("topClients", []):
            ip = str(row.get("ip"))
            row["name"] = names.get(ip) or ip
        linked = [str(target) for target in current_settings.network.arp_assisted_targets]
        bandwidth = app.state.store.bandwidth_rates(set(linked)) if linked else {}
        return {
            "overview": overview,
            "series": [bucket.to_dict() for bucket in series],
            "bandwidth": list(bandwidth.values()),
            "linkedTargets": linked,
        }

    @app.get("/api/analytics/traffic")
    def analytics_traffic(
        request: Request,
        window: int = 600,
        bucket: int = 10,
        client: str | None = None,
    ) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        client_ip = _validate_lan_ip(client, current_settings) if client else None
        analytics = QueryAnalytics(current_settings.pihole.ftl_db)
        series = analytics.traffic_series(window_seconds=window, bucket_seconds=bucket, client_ip=client_ip)
        return {
            "client": client_ip,
            "windowSeconds": window,
            "bucketSeconds": bucket,
            "series": [item.to_dict() for item in series],
        }

    @app.get("/api/connections")
    def connections_overview(request: Request, limit: int = 40) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        names = _device_display_names(app.state.store)
        linked = [str(target) for target in current_settings.network.arp_assisted_targets]
        devices = []
        for ip in linked:
            flows = list_active_connections(ip, limit=max(1, min(limit, 100)), resolve_hosts=True)
            summary = summarize_flows(
                flows,
                top_limit=6,
                exclude_remotes=_flow_exclude_remotes(current_settings, ip),
            )
            devices.append(
                {
                    "ip": ip,
                    "name": names.get(ip) or ip,
                    "connections": flows,
                    "bandwidth": app.state.store.bandwidth_rates({ip}).get(ip),
                    "protocols": summary["protocols"],
                    "topRemotes": summary["topRemotes"],
                    "flowCount": summary["flowCount"],
                }
            )
        return {
            "note": "Active L4 flows for linked devices (on-path via Pi-Circle). DNS-only devices appear in Activity instead.",
            "devices": devices,
        }

    @app.get("/api/devices/{device_ip}/connections")
    def device_connections(device_ip: str, request: Request, limit: int = 40) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        target = _validate_lan_ip(device_ip, current_settings)
        linked = target in {str(value) for value in current_settings.network.arp_assisted_targets}
        flows = list_active_connections(target, limit=max(1, min(limit, 100)), resolve_hosts=True) if linked else []
        summary = summarize_flows(
            flows,
            top_limit=8,
            exclude_remotes=_flow_exclude_remotes(current_settings, target),
        )
        return {
            "ip": target,
            "linked": linked,
            "connections": flows,
            "protocols": summary["protocols"],
            "topRemotes": summary["topRemotes"],
            "flowCount": summary["flowCount"],
            "bandwidth": app.state.store.bandwidth_rates({target}).get(target),
            "bandwidthSeries": (
                app.state.store.bandwidth_series(target, window_seconds=600, bucket_seconds=15) if linked else []
            ),
        }

    @app.get("/api/devices/{device_ip}/activity")
    def device_activity(device_ip: str, request: Request, limit: int = 40) -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        _require_lan_admin(request, current_settings)
        target = _validate_lan_ip(device_ip, current_settings)
        reader = PiholeQueryReader(current_settings.pihole.ftl_db)
        events = reader.recent_queries(client_ip=target, limit=limit)
        names = _device_display_names(app.state.store)
        payload = []
        for event in events:
            item = event.to_dict()
            item["device_name"] = names.get(event.client_ip) or event.client_ip
            payload.append(item)
        return {
            "client": target,
            "device_name": names.get(target) or target,
            "events": payload,
        }

    return app


def _flow_exclude_remotes(settings, device_ip: str) -> set[str]:
    """Hide gateway/self/Pi addresses from top-remote rollups (DNS/NAT noise)."""
    excluded = {str(settings.network.gateway_ip), str(device_ip)}
    try:
        completed = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "dev", settings.network.interface],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return excluded
    if completed.returncode != 0:
        return excluded
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        raw = parts[3].split("/", 1)[0]
        try:
            excluded.add(str(ip_address(raw)))
        except ValueError:
            continue
    return excluded


def _serialize_devices(store: Store, present_ips: set[str]) -> list[dict[str, object]]:
    devices = store.list_devices(present_ips=present_ips, include_enrolled_offline=True)
    payload: list[dict[str, object]] = []
    for device in devices:
        item = dict(device.__dict__)
        item["online"] = device.ip_address in present_ips
        linked = bool(device.transparent_control or device.managed)
        item["policy"] = _policy_for_device(store, device, linked=linked).to_dict()
        payload.append(item)
    # Online first, then linked, then name/IP.
    payload.sort(
        key=lambda row: (
            0 if row.get("online") else 1,
            0 if row.get("transparent_control") or row.get("managed") else 1,
            str(row.get("display_name") or row.get("hostname") or row.get("ip_address") or ""),
        )
    )
    return payload


def _policy_for_device(store: Store, device, *, linked: bool):
    profiles = {profile.id: profile for profile in store.list_profiles()}
    profile = profiles.get(device.profile_id) if device.profile_id else None
    day = datetime.now().astimezone().strftime("%Y-%m-%d")
    used = store.get_usage_minutes(device.ip_address, day)
    return evaluate_device_policy(device, profile, linked=linked, used_minutes=used)


def _device_display_names(store: Store) -> dict[str, str]:
    names: dict[str, str] = {}
    for device in store.list_devices():
        label = device.display_name or device.hostname or device.ip_address
        names[device.ip_address] = label
    return names


def _read_audit_events(path: Path, *, limit: int) -> list[dict[str, object]]:
    limit = max(1, min(int(limit), 100))
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]
    except OSError:
        return []
    events: list[dict[str, object]] = []
    for line in reversed(lines):
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        events.append(_redact_audit_event(payload))
    return events


def _redact_audit_event(payload: dict[str, object]) -> dict[str, object]:
    redacted = {}
    sensitive_words = ("password", "token", "secret", "key", "authorization", "cookie")
    for key, value in payload.items():
        lowered = str(key).lower()
        if any(word in lowered for word in sensitive_words):
            redacted[key] = "[redacted]"
        else:
            redacted[key] = value
    return redacted


def _community_preview(settings_payload: dict[str, object]) -> dict[str, object]:
    mode = str(settings_payload.get("mode") or "private")
    enabled = mode != "private"
    shared = (
        [
            {"field": "confirmedMaliciousDomain", "example": "malware-domain.example", "included": True},
            {"field": "categoryCorrection", "example": {"domain": "example.test", "category": "phishing"}, "included": True},
            {"field": "falsePositiveReport", "example": {"domain": "safe.example", "reason": "parent confirmed"}, "included": True},
            {"field": "effectivenessStats", "example": {"blockedMalware": 12, "falsePositiveReports": 1}, "included": True},
        ]
        if enabled
        else []
    )
    never = [
        "device names",
        "MAC addresses",
        "local IP addresses",
        "user identities",
        "complete DNS histories",
        "private network topology",
        "administrator details",
        "unredacted logs",
    ]
    return {
        "enabled": enabled,
        "mode": mode,
        "destination": "none: no cloud endpoint is configured",
        "transport": "not active",
        "sharedFields": shared,
        "neverShare": never,
        "samplePayload": {"mode": mode, "events": shared} if enabled else {"mode": "private", "events": []},
    }


def _require_lan_admin(request: Request, settings) -> None:
    if not settings.security.require_lan_admin:
        return
    client_host = request.client.host if request.client else ""
    try:
        client_ip = ip_address(client_host)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail="Admin request source is not a valid IP address") from exc
    if client_ip.is_loopback:
        return
    if client_ip.version == 4 and client_ip in settings.network.lan_cidr:
        return
    raise HTTPException(status_code=403, detail="Admin actions are restricted to the configured LAN")


def _validate_target(raw_target: str, settings) -> str:
    target = _validate_lan_ip(raw_target, settings)
    parsed = ip_address(target)
    if parsed == settings.network.gateway_ip:
        raise HTTPException(status_code=400, detail="The gateway cannot be targeted")
    if parsed in settings.network.unmanaged_ips:
        raise HTTPException(status_code=400, detail=f"{target} is marked unmanaged")
    return target


def _validate_lan_ip(raw_target: str, settings) -> str:
    try:
        target = ip_address(raw_target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"{raw_target} is not a valid IP address") from exc
    if target.version != 4:
        raise HTTPException(status_code=400, detail=f"{raw_target} is not IPv4")
    if target not in settings.network.lan_cidr:
        raise HTTPException(status_code=400, detail=f"{raw_target} is outside {settings.network.lan_cidr}")
    return str(target)


def _set_arp_targets(targets: list[str]) -> None:
    if not ARP_TARGET_HELPER.exists():
        raise HTTPException(status_code=500, detail=f"Missing helper: {ARP_TARGET_HELPER}")
    try:
        completed = subprocess.run(
            ["sudo", "-n", str(ARP_TARGET_HELPER), "--no-restart", *targets],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=504, detail="Timed out applying ARP-assisted target changes") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "Failed to apply ARP-assisted target changes"
        raise HTTPException(status_code=400, detail=detail)


def _emergency_dns_only() -> dict[str, object]:
    if not EMERGENCY_DNS_ONLY_HELPER.exists():
        raise HTTPException(status_code=500, detail=f"Missing helper: {EMERGENCY_DNS_ONLY_HELPER}")
    try:
        completed = subprocess.run(
            ["sudo", "-n", str(EMERGENCY_DNS_ONLY_HELPER)],
            check=False,
            capture_output=True,
            text=True,
            timeout=8,
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=504, detail="Timed out applying emergency DNS-only recovery") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "Emergency DNS-only recovery failed"
        raise HTTPException(status_code=500, detail=detail)
    return {"stdout": completed.stdout.strip(), "stderr": completed.stderr.strip(), "returncode": completed.returncode}


def _set_network_flags(*, force_ipv4: bool, force_pi_dns: bool) -> None:
    if not NETWORK_FLAGS_HELPER.exists():
        raise HTTPException(status_code=500, detail=f"Missing helper: {NETWORK_FLAGS_HELPER}")
    try:
        completed = subprocess.run(
            [
                "sudo",
                "-n",
                str(NETWORK_FLAGS_HELPER),
                "--force-ipv4",
                "true" if force_ipv4 else "false",
                "--force-pi-dns",
                "true" if force_pi_dns else "false",
                "--no-restart",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=90,
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=504, detail="Timed out applying network settings") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "Failed to apply network settings"
        raise HTTPException(status_code=400, detail=detail)


def _network_settings_payload(settings) -> dict[str, object]:
    return {
        "settings": {
            "forceIpv4": bool(settings.network.force_ipv4),
            "forcePiDns": bool(getattr(settings.network, "force_pi_dns", True)),
            "mode": settings.network.mode,
            "arpAssistedEnabled": bool(settings.network.arp_assisted_enabled),
            "linkedTargets": [str(target) for target in settings.network.arp_assisted_targets],
            "dnsRedirect": bool(settings.network.dns_redirect_port_53),
            "blockQuicForLinked": bool(settings.network.block_quic_for_linked),
        },
        "detail": (
            "Force Pi DNS works like Circle: linked phones keep whatever DNS they show, but the Pi hijacks port 53 and blocks Secure DNS / DoH automatically — no settings on the kid's phone."
            if getattr(settings.network, "force_pi_dns", True)
            else "Force Pi DNS is off. Linked phones may keep using the router or encrypted DNS."
        ),
    }


def _cached(app: FastAPI, key: str, ttl_seconds: int, producer) -> dict[str, object]:
    now = time.monotonic()
    cache = app.state.cache
    cached = cache.get(key)
    if cached and now - cached["stored_at"] < ttl_seconds:
        return cached["value"]
    value = producer()
    cache[key] = {"stored_at": now, "value": value}
    return value


def _report_payload(settings, store: Store, period: str, privacy_level: str) -> dict[str, object]:
    report_request = ReportRequest(period=period, privacy_level=privacy_level)
    return {"report": ReportBuilder(settings.pihole.ftl_db, store).build(report_request)}


def _capability_payload(app: FastAPI, settings) -> dict[str, object]:
    present_ips = sync_device_inventory(settings, app.state.store, probe=False, full_scan=False)
    setup = evaluate_setup(settings, app.state.store, present_count=len(present_ips))
    return capability_report(settings, setup)


def _security_payload(settings) -> dict[str, object]:
    return {
        "security": {
            "lanAdminRequired": settings.security.require_lan_admin,
            "sessionMinutes": settings.security.session_minutes,
            "auditRetentionDays": settings.security.audit_retention_days,
            "webhookConfigured": bool(settings.security.alert_webhook_url),
            "adminRoles": "local LAN administrator gate only",
            "knownGaps": [
                "Password-based local administrator login is not configured yet.",
                "Read-only viewer role is not configured yet.",
                "CSRF tokens are not configured yet; LAN-admin source restriction is currently the active browser-side guard.",
            ],
        }
    }


def _control_response(app: FastAPI) -> dict[str, object]:
    current_settings = load_settings(app.state.config_path)
    return {
        "health": {
            "mode": current_settings.network.mode,
            "targets": [str(target) for target in current_settings.network.arp_assisted_targets],
            "network": app.state.store.get_network_health(),
        },
        "transparentControl": {
            "enabled": current_settings.network.arp_assisted_enabled,
            "targetCount": len(current_settings.network.arp_assisted_targets),
            "targets": [str(target) for target in current_settings.network.arp_assisted_targets],
            "dnsRedirect": current_settings.network.dns_redirect_port_53,
        },
    }


def _ipv4_sort_key(value: str) -> tuple[int, int, int, int]:
    return tuple(int(part) for part in value.split("."))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Pi-Circle dashboard")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    args = parser.parse_args(argv)
    settings = load_settings(Path(args.config))
    uvicorn.run(create_app(Path(args.config)), host=settings.dashboard.host, port=settings.dashboard.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
import os
import subprocess
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import uvicorn

from .analytics import QueryAnalytics
from .bandwidth import list_active_connections, sample_device_bandwidth, summarize_flows
from .config import DEFAULT_CONFIG_PATH, load_settings
from .discovery_service import auto_link_androids, run_nmap_identification
from .history import HistoryReader
from .inventory import sync_device_inventory
from .pihole import PiholeQueryReader, PiholeStateReader
from .policy import evaluate_all_policies, evaluate_device_policy
from .setup_health import evaluate_setup
from .storage import DEVICE_TYPES, Store


SOURCE_ROOT = Path(__file__).resolve().parents[2]
WEB_DIR = Path(os.environ.get("PI_CIRCLE_WEB_DIR", SOURCE_ROOT / "web"))
ARP_TARGET_HELPER = Path("/usr/local/sbin/pi-circle-set-arp-assisted-targets")


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


def create_app(config_path: Path = DEFAULT_CONFIG_PATH) -> FastAPI:
    settings = load_settings(config_path)
    store = Store(settings.paths.database)
    store.initialize()

    app = FastAPI(title="Pi-Circle Dashboard", version="0.1.0")
    app.state.config_path = config_path
    app.state.store = store

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
            },
        }

    @app.get("/api/pihole")
    def pihole_summary() -> dict[str, object]:
        current_settings = load_settings(app.state.config_path)
        reader = PiholeStateReader(current_settings.pihole.gravity_db, current_settings.paths.pihole_dir)
        return reader.summary().to_dict()

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
            ["sudo", "-n", str(ARP_TARGET_HELPER), *targets],
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

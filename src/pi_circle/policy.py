from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, time
import re

from .storage import Device, Profile, Store


_TIME_RE = re.compile(r"^(\d{1,2}):(\d{2})$")


@dataclass(frozen=True)
class DevicePolicyState:
    ip_address: str
    paused: bool
    bedtime_active: bool
    over_budget: bool
    blocked: bool
    block_reason: str | None
    requires_link: bool
    linked: bool
    daily_minutes: int | None
    used_minutes: int
    bedtime_start: str | None
    bedtime_end: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "ip_address": self.ip_address,
            "paused": self.paused,
            "bedtimeActive": self.bedtime_active,
            "overBudget": self.over_budget,
            "blocked": self.blocked,
            "blockReason": self.block_reason,
            "requiresLink": self.requires_link,
            "linked": self.linked,
            "dailyMinutes": self.daily_minutes,
            "usedMinutes": self.used_minutes,
            "bedtimeStart": self.bedtime_start,
            "bedtimeEnd": self.bedtime_end,
        }


def parse_hhmm(value: str | None) -> time | None:
    if not value:
        return None
    match = _TIME_RE.match(value.strip())
    if not match:
        return None
    hour = int(match.group(1))
    minute = int(match.group(2))
    if hour > 23 or minute > 59:
        return None
    return time(hour=hour, minute=minute)


def format_hhmm(value: time | None) -> str | None:
    if value is None:
        return None
    return f"{value.hour:02d}:{value.minute:02d}"


def is_bedtime_active(bedtime_start: str | None, bedtime_end: str | None, now: datetime | None = None) -> bool:
    start = parse_hhmm(bedtime_start)
    end = parse_hhmm(bedtime_end)
    if start is None or end is None:
        return False
    current = (now or datetime.now().astimezone()).timetz().replace(tzinfo=None)
    if start == end:
        return False
    if start < end:
        return start <= current < end
    # Overnight window, e.g. 21:00 → 07:00
    return current >= start or current < end


def evaluate_device_policy(
    device: Device,
    profile: Profile | None,
    *,
    linked: bool,
    used_minutes: int = 0,
    now: datetime | None = None,
) -> DevicePolicyState:
    bedtime_start = profile.bedtime_start if profile else None
    bedtime_end = profile.bedtime_end if profile else None
    daily_minutes = profile.daily_minutes if profile else None
    bedtime_active = is_bedtime_active(bedtime_start, bedtime_end, now=now)
    over_budget = bool(daily_minutes and daily_minutes > 0 and used_minutes >= daily_minutes)
    wants_block = bool(device.paused or bedtime_active or over_budget)
    requires_link = wants_block and not linked
    blocked = wants_block and linked

    reason = None
    if device.paused:
        reason = "paused"
    elif bedtime_active:
        reason = "bedtime"
    elif over_budget:
        reason = "daily_limit"

    return DevicePolicyState(
        ip_address=device.ip_address,
        paused=device.paused,
        bedtime_active=bedtime_active,
        over_budget=over_budget,
        blocked=blocked,
        block_reason=reason if wants_block else None,
        requires_link=requires_link,
        linked=linked,
        daily_minutes=daily_minutes,
        used_minutes=used_minutes,
        bedtime_start=bedtime_start,
        bedtime_end=bedtime_end,
    )


def evaluate_all_policies(
    store: Store,
    *,
    linked_ips: set[str],
    now: datetime | None = None,
) -> list[DevicePolicyState]:
    current = now or datetime.now().astimezone()
    profiles = {profile.id: profile for profile in store.list_profiles()}
    day_key = current.strftime("%Y-%m-%d")
    states: list[DevicePolicyState] = []
    for device in store.list_devices():
        profile = profiles.get(device.profile_id) if device.profile_id else None
        used = store.get_usage_minutes(device.ip_address, day_key)
        states.append(
            evaluate_device_policy(
                device,
                profile,
                linked=device.ip_address in linked_ips,
                used_minutes=used,
                now=current,
            )
        )
    return states


def blocked_ips_from_states(states: list[DevicePolicyState]) -> list[str]:
    return sorted({state.ip_address for state in states if state.blocked})

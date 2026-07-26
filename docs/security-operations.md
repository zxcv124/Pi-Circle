# Security And Operations

## Threat Model

Assets:

- Pi-hole configuration and databases.
- Device inventory and household profile data.
- Admin credentials and sessions.
- Network-control privileges.
- Audit logs.

Primary threats:

- Unauthorized dashboard access.
- Malicious policy changes.
- LAN attacker abusing the appliance as a traffic choke point.
- Accidental outage from bad routing or ARP-assisted control.
- DNS bypass through encrypted DNS, IPv6, VPN, or hardcoded resolvers.
- SD card failure.
- Sensitive data leakage through logs or backups.

## Security Controls

Authentication:

- Strong local admin credentials.
- Password hashing with modern KDF.
- Session rotation after login.
- Secure, HTTP-only cookies.
- CSRF protection.
- Rate limiting and brute-force protection.

Authorization:

- Admin role for system settings.
- Caregiver role for device/profile policy.
- Read-only role for monitoring.
- Every policy change writes an audit event.

Network:

- Dashboard bound to LAN/admin interface only by default.
- No public internet exposure by default.
- Firewall permits only required inbound ports.
- Privileged agent API bound to localhost or Unix socket.
- Remote administration requires explicit setup, TLS, MFA, and allowlisted origins.

Data:

- Local SQLite databases with strict file permissions.
- Backups protected with owner-only permissions.
- Secrets stored outside source code.
- Logs avoid full URLs, credentials, tokens, and request payloads.

System:

- Dedicated Unix users for services.
- systemd hardening where compatible.
- Minimal Linux capabilities.
- Regular update path for OS, Pi-hole, and Pi-Circle packages.
- Health checks and watchdog behavior.

## UAE Access Restriction Readiness

If the appliance later gains cloud access or remote administration, production requirements include UAE-only access enforcement at CDN, reverse proxy, API gateway, backend, authentication, and admin portal layers.

For the local-only appliance phase:

- Do not expose the dashboard outside the LAN.
- Record remote-access attempts if remote access is enabled later.
- Prepare policy hooks for country, IP reputation, VPN, proxy, TOR, and datacenter detection.
- Display this message when blocked:

```text
This platform is currently available only to users accessing from within the United Arab Emirates.
```

## Logging

Use structured JSON logs.

Event classes:

- `auth.login.success`
- `auth.login.failure`
- `policy.changed`
- `device.assigned`
- `device.paused`
- `device.resumed`
- `network.mode.enabled`
- `network.mode.disabled`
- `network.health.failed`
- `rollback.executed`
- `backup.completed`
- `backup.failed`

Fields:

- Timestamp.
- Actor.
- Event type.
- Device or profile ID.
- Source IP.
- User agent for dashboard events.
- Result.
- Reason.

## Monitoring

Local dashboard alerts:

- Pi-hole unavailable.
- DNS latency high.
- Gateway unreachable.
- Internet unreachable.
- Transparent control degraded.
- IPv6 bypass risk.
- Disk space low.
- SD card write pressure high.
- Backup overdue.

Export options for later:

- Prometheus metrics endpoint on localhost.
- Syslog forwarding.
- OpenTelemetry collector integration.

## Backup Strategy

Frequency:

- Pi-hole state daily.
- Pi-Circle state daily.
- Audit logs weekly rotation.
- Pre-upgrade backup before every package or config migration.

Retention:

- Keep at least 7 daily backups locally if disk permits.
- Support export to encrypted external storage.

Restore acceptance:

- Pi-hole starts.
- Existing lists and groups are present.
- Pi-Circle dashboard starts.
- Policies match backup.
- DNS-only mode works before restoring transparent control.

## Disaster Recovery

Emergency procedures:

- Stop `pi-circle-agent`.
- Flush Pi-Circle-owned `nftables` chains.
- Reboot Pi if network state is unknown.
- Point router DNS back to a public or ISP resolver if Pi-hole is unavailable.
- Restore `/etc/pihole` from latest known-good backup.

Production packaging must include a single documented emergency command after the service names and owned firewall tables are finalized.

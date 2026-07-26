# Resource Index

Research date: 2026-07-18.

## Verified References

- Pi-hole overview: Pi-hole is a DNS sinkhole, has a responsive web dashboard, can optionally act as DHCP, and supports IPv4 and IPv6. Source: https://docs.pi-hole.net/
- Pi-hole v6 API: the API is REST-oriented, JSON-based, uses standard HTTP verbs/status codes, and the installed Pi-hole serves version-matched docs at `http://pi.hole/api/docs`. Source: https://docs.pi-hole.net/api/
- Pi-hole v6 configuration: persistent FTL configuration is normally managed through `/etc/pihole/pihole.toml`; using the web UI, API, or CLI is preferred because they validate changes. Source: https://docs.pi-hole.net/ftldns/configfile/
- Pi-hole group management: clients, lists, and domains can be associated with groups, and newly added clients/domains start in the default group. Source: https://docs.pi-hole.net/database/domain-database/groups/
- Pi-hole per-client blocking: per-client policy can be modeled through groups, and list reloads are required after direct database modifications. Source: https://docs.pi-hole.net/group_management/example/
- nftables NAT: stateful NAT is the recommended approach for ordinary routing/NAT use, and masquerading is designed for dynamic outgoing interface addresses. Source: https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_%28NAT%29
- Red Hat nftables NAT guide: `nftables` supports masquerading, SNAT, DNAT, and redirect; masquerading dynamically uses the outgoing interface IP. Source: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/security_guide/sec-configuring_nat_using_nftables

## Local Documentation Targets

When we reach implementation, verify these on the actual Pi:

- `http://pi.hole/api/docs`
- `/etc/pihole/pihole.toml`
- `/etc/pihole/gravity.db`
- `/etc/pihole/pihole-FTL.db`
- `/etc/dhcpcd.conf` on legacy installs
- NetworkManager profiles under `/etc/NetworkManager/system-connections/` on Bookworm-based installs
- `/etc/nftables.conf`
- `systemctl status pihole-FTL nftables NetworkManager`

## Dependency Candidates

- Backend appliance service: Go or Rust for a small privileged networking daemon; TypeScript/Node for API/UI integration if the dashboard is separate.
- Packet/routing layer: Linux IP forwarding, policy routing, `nftables`, `conntrack`, `iproute2`.
- Device discovery: passive ARP/neighbor table reads, DHCP lease parsing, mDNS/NetBIOS host naming where available.
- Dashboard: React or Svelte with Three.js for the device map; Pi-hole v6 REST API for DNS policy integration.
- Persistence: SQLite on-device for appliance policy and audit state; do not overload Pi-hole internal databases for product state.

## Resource Gaps To Resolve On Device

- Exact Pi-hole API schema from the installed version.
- Whether the installed OS uses NetworkManager, `dhcpcd`, or Docker networking.
- Whether the router supports DHCP option changes, static routes, DNS rebinding controls, or client isolation.
- IPv6 router advertisement behavior, since ARP is IPv4-only and IPv6 requires separate neighbor discovery and RA strategy.

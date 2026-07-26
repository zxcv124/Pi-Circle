from __future__ import annotations

import argparse
from pathlib import Path

from .config import DEFAULT_CONFIG_PATH, load_settings
from .network import NetworkController
from .audit import AuditLogger
from .storage import Store
from .system import CommandRunner


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Operate Pi-Circle locally")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("health", help="Print network health state")
    subparsers.add_parser("devices", help="Print discovered devices")
    subparsers.add_parser("rollback-network", help="Stop ARP-assisted control and remove Pi-Circle nftables rules")
    args = parser.parse_args(argv)

    settings = load_settings(Path(args.config))
    store = Store(settings.paths.database)
    store.initialize()

    if args.command == "health":
        print(store.get_network_health())
        return 0
    if args.command == "devices":
        for device in store.list_devices():
            print(device)
        return 0
    if args.command == "rollback-network":
        controller = NetworkController(CommandRunner(), AuditLogger(settings.paths.audit_log))
        controller.stop_arp_assisted("operator", "manual rollback")
        controller.flush_nftables()
        store.set_network_health("dns_only", True, "Manual rollback executed")
        print("Network rollback executed. Pi-hole DNS-only mode remains available.")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())

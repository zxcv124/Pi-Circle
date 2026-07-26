# SD Card Wi-Fi Boot Hook

Date: 2026-07-18.

The SD card boot partition was updated to auto-configure Wi-Fi on the next Pi boot.

Files changed on `/Volumes/bootfs`:

- `cmdline.txt`
- `pi-circle-wifi-firstboot.sh`

Behavior:

- `cmdline.txt` runs `/boot/firmware/pi-circle-wifi-firstboot.sh` once through systemd.
- The script creates a NetworkManager connection for SSID `ETI95BCF0-2.4G`.
- The connection uses `wlan0`, DHCP, `autoconnect=true`, and priority `100`.
- The created connection file on the Pi is `/etc/NetworkManager/system-connections/ETI95BCF0-2.4G.nmconnection`.
- The Pi-side connection file is set to `0600` and owned by `root:root`.
- After creating the connection, the script removes its `systemd.run` boot hook from `/boot/firmware/cmdline.txt`.
- The script removes itself from `/boot/firmware`.
- `systemd.run_success_action=reboot` reboots the Pi after successful configuration so NetworkManager starts normally with the new connection.

The Wi-Fi password is intentionally not recorded in this repository document.

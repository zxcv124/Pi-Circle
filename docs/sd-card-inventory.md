# SD Card Inventory

Inspection date: 2026-07-18.

## Mounted Card

- Whole device: `/dev/disk5`
- Media: external USB storage device
- Size: 31.9 GB
- Partition table: MBR / FDisk
- Boot partition: `/dev/disk5s1`
- Boot mount: `/Volumes/bootfs`
- Boot filesystem: FAT32
- Boot size: 536.9 MB
- Root partition: `/dev/disk5s2`
- Root filesystem: ext4, inferred from `/Volumes/bootfs/cmdline.txt`
- Root size: 31.4 GB
- Root mount: not mounted by macOS

## Boot Image Metadata

`/Volumes/bootfs/issue.txt`:

```text
Raspberry Pi reference 2025-05-13
Generated using pi-gen, https://github.com/RPi-Distro/pi-gen, 5dabc7dc940059dfbc46af5d97b60a1e812523dd, stage4
```

`/Volumes/bootfs/cmdline.txt`:

```text
console=tty1 root=PARTUUID=a078212d-02 rootfstype=ext4 fsck.repair=yes rootwait quiet splash plymouth.ignore-serial-consoles cfg80211.ieee80211_regdom=AE
```

Key observations:

- Root partition is `PARTUUID=a078212d-02`.
- Root filesystem is ext4.
- The image is configured for 64-bit boot through `arm_64bit=1` in `config.txt`.
- Wi-Fi regulatory domain is already configured as `AE`.
- The boot partition includes device tree files for Raspberry Pi 2, 3, 4, 5, Compute Module variants, Zero 2, Pi 400, and Pi 500; the actual target board is not yet proven from the mounted card alone.

## Boot Configuration

Relevant active settings from `/Volumes/bootfs/config.txt`:

```text
dtparam=audio=on
camera_auto_detect=1
display_auto_detect=1
auto_initramfs=1
dtoverlay=vc4-kms-v3d
max_framebuffers=2
disable_fw_kms_setup=1
arm_64bit=1
disable_overscan=1
arm_boost=1
```

Conditional settings:

```text
[cm4]
otg_mode=1

[cm5]
dtoverlay=dwc2,dr_mode=host
```

## Access Status

Current Mac environment:

- `/Volumes/bootfs` is readable and writable.
- `/dev/disk5s2` is not mounted by macOS.
- macOS does not natively mount ext4.
- Docker Desktop is installed but was not usable during inspection.
- Homebrew `e2fsprogs` was installed locally during inspection so `debugfs` and `dumpe2fs` can read ext4 metadata.
- Rootfs was inspected read-only through `/usr/local/opt/e2fsprogs/sbin/debugfs`.

## Rootfs Inspection Results

Artifact directory:

```text
/Users/zer0/Documents/Pi-Circle/artifacts/sd-card-rootfs-inspection-20260718T155302Z
```

This directory is intentionally ignored by Git because it contains copied Pi-hole databases and local security-sensitive material.

Filesystem:

- Volume name: `rootfs`
- Filesystem UUID: `d6ecfcd5-2703-41bf-9301-10c403b6fb0c`
- Filesystem state: `clean`
- Block size: 4096
- Free blocks: 5,778,797
- Last mounted: 2026-03-21 21:17:01
- Last write: 2026-04-04 01:02:23
- Lifetime writes: 84 GB

Operating system:

- Debian version: `12.12`
- Hostname: `pi`

Pi-hole versions:

- Core: `v6.1.4`
- Web: `v6.2.1`
- FTL: `v6.2.3`

Pi-hole configuration summary:

- Upstream DNS servers: OpenDNS `208.67.222.222`, `208.67.220.220`
- DNS interface: `wlan0`
- Listening mode: `LOCAL`
- Local domain: `lan`
- DNSSEC: disabled
- Query logging: enabled
- DHCP: disabled
- Pi-hole web domain: `pi.hole`
- Web ports: `80o,443os,[::]:80o,[::]:443os`
- Theme: `lcars`

Pi-hole database summary:

- Groups: 1
- Configured clients: 0
- Enabled adlists: 52
- Domain list entries: 1
- Gravity domains: 3,816,110
- Network inventory rows: 65
- Query rows: 4,694,794
- Message rows: 54
- `gravity.db`: 256,270,336 bytes
- `pihole-FTL.db`: 286,736,384 bytes
- `/etc/pihole` copied artifact size: included in 923 MB rootfs inspection artifact

## Recommended Next Access Path

Use one of these paths before transformation:

1. Boot the Pi from this SD card and run:

   ```bash
   sudo bash ops/pi-circle-preflight.sh
   sudo bash ops/pi-hole-state-backup.sh
   ```

2. Mount the root partition read-only on a Linux machine and provide the mount path.

3. Continue using `ops/mac-sd-rootfs-inspect.sh` for Mac-side read-only rootfs inspection.

No SD-card modifications should be made until a full card backup exists.

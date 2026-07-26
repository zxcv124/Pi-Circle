# SD Card SSH User Boot Hook

Date: 2026-07-18.

The SD card boot partition was updated to create a dedicated SSH admin user on the next Pi boot.

Files changed on `/Volumes/bootfs`:

- `cmdline.txt`
- `pi-circle-user-firstboot.sh`

Generated local SSH keypair:

```text
/Users/zer0/Documents/Pi-Circle/artifacts/ssh-access/pi_circle_ed25519
/Users/zer0/Documents/Pi-Circle/artifacts/ssh-access/pi_circle_ed25519.pub
```

Public key fingerprint:

```text
256 SHA256:B0K6kwDVYb5zOLBsz+QCdS1KerdaFSgGA5FaKenvhOs pi-circle-admin-20260718 (ED25519)
```

Next boot behavior:

- Create user `picircle`.
- Create `/home/picircle/.ssh/authorized_keys`.
- Install the generated public key.
- Lock password login for `picircle`.
- Add `picircle` to the `sudo` group.
- Add `/etc/sudoers.d/010_picircle` with passwordless sudo for installation work.
- Enable and restart SSH.
- Remove the `systemd.run` boot hook from `/boot/firmware/cmdline.txt`.
- Remove `/boot/firmware/pi-circle-user-firstboot.sh`.
- Reboot once automatically.

After the Pi finishes its one-time reboot:

```bash
ssh -i /Users/zer0/Documents/Pi-Circle/artifacts/ssh-access/pi_circle_ed25519 picircle@192.168.1.106
```

Security note:

`picircle` has passwordless sudo so the Pi-Circle installation can run unattended. Remove `/etc/sudoers.d/010_picircle` or tighten it after installation if long-term passwordless sudo is not desired.

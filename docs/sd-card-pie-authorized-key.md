# SD Card `pie` Authorized Key

Date: 2026-07-18.

The SD card root filesystem was edited directly with `debugfs -w` to add an SSH public key for the existing `pie` user.

Target:

```text
/home/pie/.ssh/authorized_keys
```

Installed public key fingerprint:

```text
256 SHA256:B0K6kwDVYb5zOLBsz+QCdS1KerdaFSgGA5FaKenvhOs pi-circle-admin-20260718 (ED25519)
```

Private key material is kept outside this repository (local operator secrets only).

Rootfs metadata applied:

- `/home/pie/.ssh`: UID `1000`, GID `1000`, mode `0700`
- `/home/pie/.ssh/authorized_keys`: UID `1000`, GID `1000`, mode `0600`

Login after boot uses the matching local private key for the public key above.

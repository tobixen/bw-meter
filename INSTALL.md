# Installation

bw-meter has two distinct parts:

* **Collectors** — `ptcpdump` instances that capture raw traffic per network interface.
  These run as root (they require raw-socket / eBPF access).
* **CLI** — `bw-meter` itself, used to query the resulting SQLite database.
  Reading the database does *not* require root, but the distiller (which writes the
  database from root-owned pcapng files) currently runs as root as well.

## Prerequisites

| Dependency | Why | Install (Arch) | Install (Debian/Ubuntu) |
|------------|-----|----------------|-------------------------|
| `ptcpdump` | Captures packets with per-process metadata via eBPF | [release binary](https://github.com/mozillazg/ptcpdump/releases) | same |
| `tshark`   | Used by the distiller to parse pcapng files | `pacman -S wireshark-cli` | `apt install tshark` |
| Python ≥ 3.10 | Runtime | `pacman -S python` | `apt install python3` |

`ptcpdump` is not yet in most distribution package repositories; install a release
binary into `/usr/bin/ptcpdump` (or adjust the `ExecStart=` path in
`systemd/ptcpdump@.service` to match wherever you put it).

## System-wide install (recommended, as root)

```sh
sudo make install
```

This will:

1. Create a Python virtual environment at `/usr/local/lib/bw-meter/`.
2. Install the `bw-meter` package and its dependencies into that venv.
3. Symlink `/usr/local/bin/bw-meter` → the venv binary.
4. Install the three systemd unit files into `/etc/systemd/system/`.
5. Run `systemctl daemon-reload`.

### Enable capture

Enable one `ptcpdump@` instance per interface you want to monitor:

```sh
systemctl enable --now ptcpdump@wlan0.service
# repeat for other interfaces, e.g. ptcpdump@wg0.service
```

Check it is running:

```sh
systemctl status ptcpdump@wlan0.service
ls /var/lib/bw-meter/wlan0/
```

### Enable the distiller timer

```sh
systemctl enable --now bw-meter-distill.timer
```

The distiller runs every 15 minutes, processes any closed pcapng files, and writes
aggregated data to the SQLite database.

## User install (no root, CLI only)

If you just want the `bw-meter` CLI and already have a database populated by a
root-managed system elsewhere, install as a normal user:

```sh
# with uv (recommended)
uv tool install .

# with pipx
pipx install .

# fallback
make install   # will auto-detect uv / pipx or fall back to pip --user
```

## Configuration

Create `~/.config/bw-meter/config.toml` (or `/etc/bw-meter/config.toml` for system-wide
defaults) to declare which interfaces count against your data cap:

```toml
[interfaces]
metered = ["wlan0"]   # traffic on these interfaces is shown in reports by default

[collection]
bucket_secs    = 60   # aggregation granularity written to DB
rotate_minutes = 15   # how often ptcpdump rolls over to a new pcapng file
keep_raw_hours = 1    # delete raw pcapng files after N hours
```

## Adjusting the ptcpdump binary path

If `ptcpdump` is not at `/usr/bin/ptcpdump`, edit the `ExecStart=` line in
`/etc/systemd/system/ptcpdump@.service` and run `systemctl daemon-reload`.

## Uninstall

```sh
systemctl disable --now 'ptcpdump@*.service' bw-meter-distill.timer bw-meter-distill.service
rm /etc/systemd/system/ptcpdump@.service \
   /etc/systemd/system/bw-meter-distill.service \
   /etc/systemd/system/bw-meter-distill.timer
systemctl daemon-reload
rm -rf /usr/local/lib/bw-meter /usr/local/bin/bw-meter
# optionally remove captured data:
rm -rf /var/lib/bw-meter
```

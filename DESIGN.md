# bw-meter Design

## Overview

A two-phase system:

1. **Collector** — one `ptcpdump` instance per interface, managed by a systemd template unit,
   which writes rolling pcapng files.
2. **Distiller** — a systemd timer that periodically processes finished pcapng files into a
   compact SQLite database and discards the raws.
3. **CLI** — a query/report tool that reads the database.

The design prioritises correctness for metered mobile connections over real-time monitoring.
The focus is *accumulated spending* and *drill-down*, not live graphs.

---

## Capture strategy

### Why ptcpdump

`ptcpdump` writes standard pcapng files with process information embedded as pcapng packet
comments.  Each tagged packet gets a list of comment blocks:

```
PID: <pid>
Cmd: <full path to executable>
Args: <argv[0] + arguments>
UserId: <uid>
ParentPID: <ppid>
ParentCmd: <full path>
ParentArgs: <parent argv>
```

Both inbound and outbound packets are tagged.  The only packets that are NOT tagged are those
handled by kernel code with no associated socket/process — in practice this means:

- **WireGuard traffic on the physical interface**: the WireGuard kernel module forwards UDP
  packets without a userspace process.
- A small number of other kernel-generated packets (ARP, ICMP, DHCP, etc.).

### Multi-interface capture

A systemd template unit (`ptcpdump@.service`) is instantiated once per interface of interest:

```
systemctl enable --now ptcpdump@wlan0.service
systemctl enable --now ptcpdump@wg0.service
```

Each instance captures its interface to a rolling sequence of pcapng files under
`/var/lib/bw-meter/<interface>/`.  The distiller picks up any file that has been closed
(i.e. the capture has rolled over to the next file) and is not still being written to.

Which interfaces are *metered* (i.e. count against a data cap) is a configuration concern,
not a capture concern.  Capture everything; mark interfaces metered in the config.

Merging data across interfaces (e.g. attributing untagged WireGuard bytes on `wlan0` to
processes visible in the `wg0` capture) is a **future improvement** — see TODO list.

### Overhead

ptcpdump uses eBPF and is low overhead compared to userspace sniffers.  Running it
continuously is feasible.  However, the raw pcapng files are large (~150 MB/hour on a
moderately active machine).  The distiller should process and discard raw captures on a
rolling basis (default: keep raws for 1 hour) rather than accumulate them indefinitely.

---

## Data pipeline

```
ptcpdump (pcapng) ──► distiller ──► SQLite ──► CLI
```

### Distiller

Runs on a schedule (e.g. every 15 minutes via systemd timer).  For each closed pcapng file:

1. **Build hostname map** from the capture itself:
   - DNS A/AAAA responses: `dns.flags.response == 1` → map `ip → hostname`
   - TLS ClientHello SNI: `tls.handshake.type == 1` → map `dst_ip → sni`
   - DNS from capture takes precedence over SNI (DNS reveals the name the application
     actually looked up, which is more meaningful than the name the TLS stack used).

2. **Parse packets** (streaming, not load-all-into-memory):
   - Extract: `frame.time_epoch`, `frame.len`, `ip.src/dst`, `ipv6.src/dst`,
     `frame.comment` (process info).
   - Derive direction (inbound / outbound) from local IP addresses.
   - Derive process name (see *Process naming* below).
   - Resolve remote IP to hostname using the map from step 1.

3. **Aggregate** into fixed time buckets (default: 1 minute) and write to SQLite.

**Backend**: `tshark` subprocess with `-T fields` output, streamed line by line.  Pure-Python
pcapng parsing is not used — no maintained library handles ptcpdump's comment blocks well,
and tshark is already a dependency of ptcpdump workflows.

### Process naming

`Cmd` gives the full executable path; `Args` gives `argv[0]` and the rest of the argument
list.

Preferred display name derivation:
1. `basename(Args[0])` — usually the most human-readable (e.g. `claude`, `chromium`,
   `deltachat-rpc-server`).
2. Fall back to `basename(Cmd)` if `Args` is empty or if `Args[0]` is a full path rather
   than a bare name.
3. Strip common suffixes: `(deleted)` (seen on chromium and other executables replaced
   while running).

Edge cases observed in the wild:
- `claude` lives under a versioned path (`~/.local/share/claude/versions/2.1.81/`) —
  `Args[0]` is simply `claude`. ✓
- `chromium` network service worker carries `--type=utility` in Args — still named
  `chromium`. ✓

The full `Cmd`, `Args`, `ParentCmd`, `ParentArgs`, and `uid` are all stored in the database
for future enrichment (e.g. correlating with systemd unit, grouping Chromium sub-processes,
atop data).  The derived display name is used only for reporting.

---

## Database schema

SQLite with a data-warehouse-style fact table and dimension tables.

SQLite has no native timestamp type.  The conventional choices are `INTEGER` (Unix epoch
seconds) or `TEXT` (ISO 8601).  This schema uses `INTEGER` because it is compact, sorts
correctly, and arithmetic (bucketing, rollup) is simple.

```sql
CREATE TABLE process (
    id          INTEGER PRIMARY KEY,
    cmd         TEXT NOT NULL,          -- full executable path
    name        TEXT NOT NULL,          -- derived display name, e.g. chromium
    args        TEXT,                   -- argv[0] + args (may be long; truncate at import)
    parent_cmd  TEXT,
    parent_args TEXT,
    uid         INTEGER
);

CREATE TABLE host (
    id          INTEGER PRIMARY KEY,
    ip          TEXT NOT NULL,
    hostname    TEXT,                   -- from DNS/SNI in capture; NULL if unresolved
    UNIQUE(ip)
);

CREATE TABLE traffic (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,       -- Unix epoch, start of bucket (seconds)
    bucket_secs INTEGER NOT NULL,       -- bucket width; allows mixed-resolution rollup
    interface   TEXT NOT NULL,          -- e.g. wlan0, wg0
    process_id  INTEGER REFERENCES process(id),   -- NULL for untagged/kernel traffic
    host_id     INTEGER REFERENCES host(id),
    direction   TEXT NOT NULL CHECK(direction IN ('in', 'out')),
    protocol    TEXT,                   -- tcp, udp, icmp, wireguard, …
    bytes       INTEGER NOT NULL,
    packets     INTEGER NOT NULL
);

CREATE INDEX traffic_ts        ON traffic(ts);
CREATE INDEX traffic_process   ON traffic(process_id);
CREATE INDEX traffic_interface ON traffic(interface, ts);
```

Notes:
- `process_id IS NULL` means kernel-level / untagged traffic (primarily WireGuard on the
  physical interface, plus ARP/ICMP/DHCP).
- `bucket_secs` is stored per row so that older data can be rolled up to coarser buckets
  without a schema change.
- A separate `capture_file` table (not shown) can track which pcapng files have been
  ingested, to make the distiller idempotent.

---

## CLI interface

```
bw-meter [global options] <command> [options]
```

### Time arguments

All `--since` / `--until` options accept flexible input, using `python-dateutil` for parsing
(the same approach as `plann`):

- ISO 8601: `2026-03-21`, `2026-03-21T14:00`, `2026-03-21 14:00`
- Natural language via dateutil: `yesterday`, `Friday`, `13:00`
- Relative offsets: `now`, `-2h`, `-7d` (negative = in the past)
- Duration suffix on a start time: `2026-03-21+1d` (start + length)

All of `--since`, `--from`, `--after`, `--begin`, `--start` are accepted as aliases for the
start bound.  Likewise `--until`, `--to`, `--before`, `--end` for the end bound.  The user
should not need to remember which one this tool uses.

### Commands

`report` — total spending summary over a time range:
```
bw-meter report [--since DATE] [--until DATE] [--interface IFACE]
```
Shows total bytes by process, sorted descending.  Default range: current calendar month.

`top` — ranked table (most useful for "what spent the most today"):
```
bw-meter top [--since DATE] [--until DATE] [--by process|host|process+host] [--limit N]
```

`timeline` — time-series view, for identifying when spikes happened:
```
bw-meter timeline [--since DATE] [--until DATE] [--interval 5m]
                  [--process NAME] [--host HOSTNAME]
```

`hosts` — what hosts did a given process connect to:
```
bw-meter hosts --process deltachat-rpc-server [--since DATE] [--until DATE]
```

`processes` — what processes connected to a given host:
```
bw-meter processes --host api.anthropic.com [--since DATE] [--until DATE]
```

### Global options

- `--db PATH` — SQLite database path (default: `~/.local/share/bw-meter/bw-meter.db`)
- `--interface IFACE` — restrict to one interface (default: all interfaces marked metered
  in config)

### Output formats

Default: plain text table.  `--json` for machine-readable output.

---

## Configuration

`~/.config/bw-meter/config.toml`:

```toml
[interfaces]
# Interfaces whose traffic counts against the data cap.
# The distiller will import pcapng files from all captured interfaces,
# but reports default to filtering to these.
metered = ["wlan0"]

[collection]
bucket_secs    = 60    # aggregation granularity written to DB
rotate_minutes = 15    # how often ptcpdump rolls to a new pcapng file
keep_raw_hours = 1     # delete raw pcapng files after this many hours
```

---

## TODO (prioritised)

1. **Core distiller and CLI** — the basic pipeline described above.

2. **Systemd units** — `ptcpdump@.service` template + `bw-meter-distill.timer`.

3. **Rollup** — compact old 1-minute buckets into 10-minute buckets after 7 days to keep
   the database small.

4. **WireGuard/VPN merging** — attribute untagged WireGuard bytes on a physical interface
   to processes by proportional allocation from a simultaneously-captured VPN inner
   interface.  Requires the user to declare in config which interface pairs to merge.

5. **Alerts** — notify when a process exceeds N MB in a rolling window, or when total
   monthly usage crosses a threshold.

6. **Mobile data counter sync** — import the operator's own counter (e.g. from
   `ditt.phonero.no`) to cross-check accumulated totals and detect off-device usage
   (e.g. tethering by another person).

7. **atop integration** — correlate PID+timestamp with atop logs to surface CPU/memory
   context alongside traffic spikes.

8. **Browser tab attribution** — use a browser extension to log tab URLs with timestamps,
   then correlate with traffic by time window.  Would resolve the current limitation where
   all Chromium traffic is attributed to a single `chromium` process entry.

# Wazuh 4.14.4 — Custom Feature Documentation

> Build: `wazuh-manager_4.14.4-0_amd64_196d860.deb`  
> All features are production-ready and safety-audited.

---

## Table of Contents

1. [Feature 1 — `analysisd drop_buffer`](#1-analysisd-drop_buffer)
2. [Feature 2 — `remoted_drop_buffer`](#2-remoted_drop_buffer)
3. [Feature 3 — `agent_offline_tracker`](#3-agent_offline_tracker)
4. [Visibility & Monitoring](#4-visibility--monitoring)
5. [Modified Core Files](#5-modified-core-files)
6. [Directory Layout](#6-directory-layout)
7. [Testing Guide](#7-testing-guide)
8. [Security Audit Notes](#8-security-audit-notes)
9. [Known Bugs Fixed During Development](#9-known-bugs-fixed-during-development)

---

## 1. analysisd drop_buffer

### Problem

Wazuh's `analysisd` receives events from remoted through a Unix datagram socket and routes them into several bounded in-memory sub-queues (syscheck, rootcheck, event, syscollector, etc.).  When a sudden traffic spike causes any of those queues to become full, the event dispatcher (`ad_input_main`) would **silently discard** the event and increment the `events_dropped` counter.  The dropped event was gone permanently with no recovery path.

This affects all event types: SSH auth failures, Windows event log entries, rootcheck results, FIM changes, SCA results, etc.

### Solution

A two-thread persistence subsystem is inserted **between** the drop point and the bit-bucket:

```
ad_input_main (hot path)
    └─ queue_push_ex() returns -1  ← queue full
           └─ drop_buffer_persist(buffer, recv)
                  └─ malloc + non-blocking push onto db_write_queue  ← O(1), no I/O

w_drop_buffer_writer_thread  (background)
    └─ blocking pop from db_write_queue
           └─ evict oldest file if at 256 MB cap
           └─ write .msg file to queue/drop-buffer/
           └─ update atomic size counter

w_drop_buffer_reingest_thread  (background, 1-second cadence)
    └─ back-pressure check (EPS limit, event queue < 70% full)
    └─ read oldest 50 files
    └─ route each back into the correct sub-queue
    └─ unlink on success, update size counter
    └─ increment events_recovered counter
```

### Key Design Properties

| Property | Detail |
|---|---|
| **Zero latency on hot path** | `drop_buffer_persist()` only does `malloc` + non-blocking queue push. No disk I/O ever on the dispatcher thread. |
| **Bounded disk usage** | Max 256 MB. Oldest files evicted automatically when cap is approached. |
| **Back-pressure aware** | Reingest thread checks EPS limit and event queue fill level before re-feeding. Will not re-worsen an already-full queue. |
| **Ordered recovery** | Files named `<epoch_sec>_<nanosec>_<seq>.msg` — lexicographic sort = insertion order. Oldest events reingested first. |
| **Crash-safe** | Files survive manager restart. On startup, `drop_buffer_init()` scans the directory, seeds the size counter, and the reingest thread picks up where it left off. |
| **OOM-safe** | All `malloc`/`strdup` return values checked. On allocation failure, event is skipped (not retried), process continues. |

### Tunables (in `drop_buffer.c`)

| Constant | Default | Meaning |
|---|---|---|
| `DROP_BUFFER_MAX_MB` | `256` | Max disk usage for buffered events |
| `DROP_BUFFER_BATCH` | `50` | Files reingested per second |
| `DROP_BUFFER_SLEEP_S` | `1` | Reingest thread cadence (seconds) |
| `DROP_BUFFER_LOAD_THRESH` | `0.70` | Skip reingest if event queue ≥ 70% full |
| `DROP_BUFFER_QUEUE_SIZE` | `4096` | In-memory queue depth between persist() and writer thread |

### Files

| File | Role |
|---|---|
| `src/analysisd/drop_buffer.c` | Full implementation |
| `src/analysisd/drop_buffer.h` | Public API |
| `queue/drop-buffer/` | Storage directory (`wazuh:wazuh`, mode `0770`) |

---

## 2. remoted_drop_buffer

### Problem

`wazuh-remoted` forwards decoded agent events to `analysisd` via `SendMSG()` over a Unix datagram socket (`queue/sockets/queue`).  If `analysisd` is down, restarting, or its socket buffer is full, `SendMSG()` fails and the event is **permanently lost**.  This happens even during brief analysisd restarts (e.g. config reload, OOM kill, crash).

### Solution

When `SendMSG()` fails (even after a single reconnect attempt), the event is persisted to `queue/remoted-drop-buffer/` as a `.evt` file.  A background reingest thread retries forwarding with exponential backoff until analysisd is back:

```
HandleSecureMessage → secure.c (hot path)
    └─ SendMSG() fails after reconnect attempt
           └─ remoted_drop_buffer_persist(msg, srcmsg, mq_type)
                  └─ malloc rdb_entry_t + non-blocking push  ← O(1)

w_rdb_writer_thread  (background)
    └─ blocking pop
           └─ evict if at 64 MB cap
           └─ write 3-line .evt file: {mq_type}\n{srcmsg}\n{msg}\n
           └─ update size counter

w_rdb_reingest_thread  (background, 1-second cadence + exponential backoff)
    └─ read oldest 30 .evt files
    └─ call SendMSG(logr.m_queue, msg, srcmsg, mq_type)
    └─ on failure: open local tmp_q, retry once, close(tmp_q)
    └─ on success: unlink file
    └─ on repeated failure: backoff up to 30 seconds
```

### Key Design Properties

| Property | Detail |
|---|---|
| **Zero latency on hot path** | Only `malloc` + non-blocking push. |
| **Exponential backoff** | Starts at 1 s, doubles per failure up to 30 s max. Avoids hammering a down analysisd. |
| **No shared fd races** | Reingest thread uses its own local `tmp_q` fd; never modifies shared `logr.m_queue`. |
| **Crash-safe** | `.evt` files survive restarts; reingest picks them up on next start. |
| **File format** | 3-line plain text: line 1 = MQ type char, line 2 = srcmsg, line 3 = message body. Human-readable, easy to inspect with `cat`. |

### Tunables (in `remoted_drop_buffer.h`)

| Constant | Default | Meaning |
|---|---|---|
| `RDB_MAX_MB` | `64` | Max disk usage for buffered events |
| `RDB_BATCH` | `30` | Files reforwarded per reingest cycle |
| `RDB_SLEEP_S` | `1` | Base reingest cadence (seconds) |
| `RDB_BACKOFF_MAX_S` | `30` | Maximum backoff between retries |
| `RDB_QUEUE_SIZE` | `2048` | In-memory queue depth |

### Files

| File | Role |
|---|---|
| `src/remoted/remoted_drop_buffer.c` | Full implementation |
| `src/remoted/remoted_drop_buffer.h` | Public API + architecture docs |
| `src/remoted/secure.c` | Modified: triggers persist on SendMSG failure |
| `src/shared/mq_op.c` | Modified: `OS_SOCKBUSY` now returns `-1` (was `0`) |
| `queue/remoted-drop-buffer/` | Storage directory (`wazuh:wazuh`, mode `0770`) |

---

## 3. agent_offline_tracker

### Problem

When an agent goes offline (graceful shutdown, crash, or network outage), any endpoint activity during the offline window is **invisible to the manager**.  If the agent's internal event buffer (default 5000 events) overflows, those events are permanently lost.  The manager had no mechanism to:

- Know that an agent had been offline
- Measure how long the offline window was
- Alert operators so they could investigate or take action

### Solution

A lightweight per-agent disconnect/reconnect tracking system:

```
HC_SHUTDOWN received by manager.c
    └─ agent_offline_record_disconnect(agent_id, time(NULL))
           └─ write epoch timestamp to queue/agent-offline/<agent_id>

HC_STARTUP received by manager.c
    └─ agent_offline_check_reconnect(key)
           └─ read queue/agent-offline/<agent_id>  (if exists)
           └─ fallback: use key->rcvd (last packet time) for unexpected drops
           └─ compute gap = now - disconnect_ts
           └─ if gap >= 60s:
                  └─ mwarn() to ossec.log
                  └─ SendMSG() internal alert to analysisd
                  └─ rule 99950 fires → alert in alerts.log + dashboard
           └─ unlink queue/agent-offline/<agent_id>
```

### Alert Details

**ossec.log** (always, when gap ≥ 60 s):
```
WARNING: Agent 001 (testing) @ 192.168.1.10 reconnected after 155 second(s) offline
(disconnected: 2026-04-20T05:45:13Z, reconnected: 2026-04-20T05:47:48Z).
Log events during this offline window may be incomplete.
```

**alerts.log** (via rule 99950):
```json
{
  "rule": { "id": "99950", "level": 7, "description": "Agent testing reconnected after an offline window..." },
  "agent": { "id": "001", "name": "testing" },
  "groups": ["agent_offline", "visibility"]
}
```

### Fallback for Unexpected Disconnects

If the agent lost connectivity without sending HC_SHUTDOWN (TCP reset, power loss, network outage), there is no disconnect file.  The tracker falls back to `key->rcvd` — the timestamp of the last packet received from that agent.  This gives a reliable lower-bound on the disconnect time.

### Tunables (in `agent_offline_tracker.h`)

| Constant | Default | Meaning |
|---|---|---|
| `AGENT_OFFLINE_MIN_GAP_SECS` | `60` | Minimum gap before logging/alerting. Filters brief restarts. |

### Files

| File | Role |
|---|---|
| `src/remoted/agent_offline_tracker.c` | Full implementation |
| `src/remoted/agent_offline_tracker.h` | Public API + architecture docs |
| `src/remoted/manager.c` | Modified: calls record/check on HC_SHUTDOWN/HC_STARTUP |
| `src/remoted/main.c` | Modified: calls `agent_offline_tracker_init()` at startup |
| `ruleset/rules/0996-agent-offline-gap-rules.xml` | Rule 99950 — fires alert to dashboard |
| `queue/agent-offline/` | Storage directory (`wazuh:wazuh`, mode `0770`) |

---

## 4. Visibility & Monitoring

### analysisd.state fields (new)

```bash
sudo grep "events_dropped\|events_recovered" /var/ossec/var/run/wazuh-analysisd.state
```

```
events_dropped='168073'           # Total events dropped (queue full)
events_recovered='168073'         # Total events re-ingested from drop-buffer
```

The **gap** between `events_dropped` and `events_recovered` is the number of events still pending on disk.

### Live queue status

```bash
sudo grep "event_queue_usage\|events_dropped\|events_recovered" /var/ossec/var/run/wazuh-analysisd.state
```

### Drop buffer disk usage

```bash
# analysisd drop buffer
sudo ls /var/ossec/queue/drop-buffer/ | wc -l
sudo du -sh /var/ossec/queue/drop-buffer/

# remoted drop buffer
sudo ls /var/ossec/queue/remoted-drop-buffer/ | wc -l
sudo du -sh /var/ossec/queue/remoted-drop-buffer/
```

### Log messages to watch (ossec.log)

| Message | Meaning |
|---|---|
| `WARNING: Input queue is full.` | analysisd drop_buffer triggered |
| `INFO: drop_buffer: re-ingested N event(s) from disk.` | Events recovered from analysisd buffer |
| `WARNING: Socket busy, discarding message.` | remoted → analysisd socket saturated |
| `WARNING: remoted_drop_buffer: analysisd still not accepting events; backing off N second(s).` | analysisd down, remoted retrying |
| `WARNING: Agent X (name) @ ip reconnected after N second(s) offline` | Offline gap detected |

### Searching alerts.log for offline gaps

```bash
sudo grep "offline gap\|99950" /var/ossec/logs/alerts/alerts.log | tail -10
```

---

## 5. Modified Core Files

| File | Change |
|---|---|
| `src/remoted/secure.c` | Replaced infinite reconnect loop with single attempt; sets `logr.m_queue = -1` on failure to prevent stale-fd race; calls `remoted_drop_buffer_persist()` on failure |
| `src/shared/mq_op.c` | `OS_SOCKBUSY` case now returns `-1` (was `0`) so callers see failure when socket is full |
| `src/remoted/manager.c` | Calls `agent_offline_check_reconnect()` on HC_STARTUP; calls `agent_offline_record_disconnect()` on HC_SHUTDOWN |
| `src/remoted/main.c` | Calls `agent_offline_tracker_init()` and `remoted_drop_buffer_init()` at startup |
| `src/analysisd/analysisd.c` | Calls `drop_buffer_init()` at startup; calls `drop_buffer_persist()` at all 9 queue-full drop points |
| `src/analysisd/state.h` | Added `uint64_t events_recovered` field to `analysisd_state_t`; declared `w_inc_events_recovered()` |
| `src/analysisd/state.c` | Added `w_inc_events_recovered()` implementation; added `events_recovered` to `.state` file output |
| `src/init/inst-functions.sh` | Creates `queue/agent-offline`, `queue/remoted-drop-buffer`, `queue/drop-buffer` with `0770 wazuh:wazuh` on install |
| `packages/rpms/SPECS/wazuh-manager.spec` | Same 3 directories added for RPM installs |

---

## 6. Directory Layout

```
/var/ossec/
├── queue/
│   ├── agent-offline/             # agent_offline_tracker
│   │   └── 001                    # one file per agent, contains epoch timestamp
│   ├── remoted-drop-buffer/       # remoted_drop_buffer
│   │   └── *.evt                  # 3-line text: mq_type / srcmsg / message
│   └── drop-buffer/               # analysisd drop_buffer
│       └── *.msg                  # raw event bytes (binary-safe)
```

All directories: owner `wazuh:wazuh`, mode `0770`.

### .evt file format (remoted-drop-buffer)

```
4\n
[001] (testing) 192.168.1.10\n
wazuh-remoted: Failed password for root from 10.0.0.1 port 22\n
```

Inspect with: `sudo cat /var/ossec/queue/remoted-drop-buffer/<filename>`

---

## 7. Testing Guide

### Test 1 — analysisd drop_buffer

Reduce queue sizes temporarily and flood events locally:

```bash
# On manager: reduce queue sizes
sudo bash -c 'cat >> /var/ossec/etc/local_internal_options.conf << EOF
analysisd.decode_event_queue_size=128
analysisd.event_threads=1
EOF'
sudo systemctl restart wazuh-manager

# Flood the analysisd socket directly from the manager
sudo python3 -c "
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
msg = b'1:sshd:/var/log/auth.log:Failed password for root from 10.0.0.1 port 22 ssh2'
for i in range(200000):
    try: s.sendto(msg, '/var/ossec/queue/sockets/queue')
    except: break
s.close()
print('done')
"

# Verify
sudo grep "Input queue is full\|re-ingested" /var/ossec/logs/ossec.log | tail -5
sudo grep "events_dropped\|events_recovered" /var/ossec/var/run/wazuh-analysisd.state
sudo ls /var/ossec/queue/drop-buffer/ | wc -l

# Restore
sudo sed -i '/analysisd.decode_event_queue_size\|analysisd.event_threads/d' /var/ossec/etc/local_internal_options.conf
sudo systemctl restart wazuh-manager
```

**Expected results:**
- `WARNING: Input queue is full.` in ossec.log
- `.msg` files appear in `queue/drop-buffer/`
- `events_dropped > 0` in analysisd.state
- After load subsides: `INFO: drop_buffer: re-ingested N event(s) from disk.`
- `events_recovered` catches up to `events_dropped`

---

### Test 2 — remoted_drop_buffer

Stop analysisd while an agent sends events:

```bash
# Kill analysisd only (keep remoted running)
sudo kill $(sudo pgrep wazuh-analysisd)

# Immediately send events from the agent (172.17.14.76)
# On agent:
sudo bash -c 'for i in $(seq 1 200); do logger -p auth.info -t sshd "Failed password for root from 10.0.0.$i port 22"; done'

# On manager — check buffer filled
sudo ls /var/ossec/queue/remoted-drop-buffer/ | wc -l
sudo cat $(sudo ls /var/ossec/queue/remoted-drop-buffer/ | head -1 | xargs -I{} echo /var/ossec/queue/remoted-drop-buffer/{})

# Restart analysisd — watch reingest
sudo systemctl start wazuh-analysisd
sleep 5
sudo grep "re-forwarded\|remoted_drop_buffer" /var/ossec/logs/ossec.log | grep -v "initialized\|writer\|reingest thread" | tail -10
sudo ls /var/ossec/queue/remoted-drop-buffer/ | wc -l
```

**Expected results:**
- `.evt` files appear in `queue/remoted-drop-buffer/` while analysisd is down
- After analysisd restarts: `DEBUG: remoted_drop_buffer: re-forwarded N event(s) to analysisd.`
- Directory drains to 0 files

---

### Test 3 — agent_offline_tracker

Disconnect an agent and reconnect after > 60 seconds:

```bash
# Stop agent (on 172.17.14.76)
sudo systemctl stop wazuh-agent

# Wait at least 60 seconds
sleep 70

# Restart agent
sudo systemctl start wazuh-agent

# On manager — check for offline gap warning
sudo grep "reconnected after\|offline gap" /var/ossec/logs/ossec.log | tail -5

# Check alert in alerts.log
sudo grep "99950\|offline gap" /var/ossec/logs/alerts/alerts.log | tail -5
```

**Expected results:**
- `WARNING: Agent 001 (testing) @ <ip> reconnected after N second(s) offline (disconnected: ..., reconnected: ...).`
- Rule 99950 alert in alerts.log

---

## 8. Security Audit Notes

The following issues were identified and fixed during development:

| # | Location | Issue | Fix Applied |
|---|---|---|---|
| 1 | `drop_buffer.c` (9 sites) | `os_strdup()` calls `merror_exit()` on OOM — would kill analysisd | Replaced with `strdup()` + `NULL` check + `continue` |
| 2 | `remoted_drop_buffer.c` — `persist()` | Same `os_strdup()` OOM-kill risk | Replaced with `strdup()` + NULL check + `free_entry(); return` |
| 3 | `remoted_drop_buffer.c` — reingest thread | `INFINITE_OPENQ_ATTEMPTS` blocks reingest thread forever if analysisd is down | `StartMQ(DEFAULTQUEUE, WRITE, 1)` on local `tmp_q`; `close(tmp_q)` after use |
| 4 | `remoted_drop_buffer.c` — reingest thread | Reingest thread wrote to `logr.m_queue` (shared global) — data race with dispatcher threads | Local `tmp_q` only; shared `logr.m_queue` never touched from reingest thread |
| 5 | `agent_offline_tracker.c` | Same `INFINITE_OPENQ_ATTEMPTS` + `logr.m_queue` race | Local `tmp_q` with `StartMQ(..., 1)` + `close(tmp_q)` |
| 6 | `secure.c` | Infinite reconnect loop blocked dispatcher thread when analysisd was down | Replaced with single attempt; `logr.m_queue = -1` on failure |
| 7 | `mq_op.c` | `OS_SOCKBUSY` returned `0` (success) — callers couldn't detect socket-full condition | Returns `-1` on socket busy |

**Lock ordering** (no deadlock possible):
- `db_size_mutex` and `db_seq_mutex` in `drop_buffer.c` are never held simultaneously
- `rdb_size_mutex` and `rdb_seq_mutex` in `remoted_drop_buffer.c` are never held simultaneously
- `state_mutex` (in `state.c`) is independent of all drop buffer mutexes

---

## 9. Known Bugs Fixed During Development

| Bug | Root Cause | Symptom | Fix |
|---|---|---|---|
| analysisd drop_buffer never triggered | `OS_SOCKBUSY` in `mq_op.c` returned `0` | Buffer never filled despite socket busy | Return `-1` on `OS_SOCKBUSY` |
| remoted_drop_buffer never triggered | Infinite reconnect loop in `secure.c` blocked thread | No `.evt` files written | Single-attempt reconnect + fall through to persist |
| queue/agent-offline permission denied | `mkdir()` used mode `0750`, wazuh group couldn't write | Disconnect files never written | Changed to `0770`; added `chmod()` fallback for existing dirs |
| queue/drop-buffer permission denied at startup | `inst-functions.sh` didn't create the directory | analysisd logged `ERROR: Permission denied` | Added directory creation to install scripts and spec file |
| analysisd crashed with queue size 10 | `getDefine_Int` enforces minimum of 128 | `CRITICAL: Invalid definition` | Use 128 as minimum test value |
| events_recovered not visible | Counter only logged at `mdebug1` level | No production visibility | Raised to `minfo`; added to `.state` file output |

---

*Generated for Wazuh 4.14.4 custom build — commit `196d860`*

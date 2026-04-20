# wazuh-enrichment

Custom Wazuh Manager 4.14.4 with three production-ready enrichment modules that close critical observability and reliability gaps in the stock build.

> Build: `wazuh-manager_4.14.4-0_amd64_196d860.deb`  
> Base: [Wazuh](https://github.com/wazuh/wazuh) 4.14.4 (GPLv2)

---

## What this adds

| Module | Problem solved | Where |
|---|---|---|
| `analysisd drop_buffer` | Events silently discarded when analysisd sub-queues are full — gone permanently | `src/analysisd/drop_buffer.c` |
| `remoted_drop_buffer` | Agent events lost when analysisd is down or restarting | `src/remoted/remoted_drop_buffer.c` |
| `agent_offline_tracker` | No visibility into how long an agent was offline or how many events may be missing | `src/remoted/agent_offline_tracker.c` |

---

## 1. analysisd drop_buffer

When `analysisd`'s in-memory sub-queues fill up, the event dispatcher would silently drop the event. This module intercepts that drop point and writes the event to disk instead.

**How it works:**

```
ad_input_main  →  queue full  →  drop_buffer_persist()       [hot path, O(1) malloc only]
                                       ↓
                              w_drop_buffer_writer_thread     [background, writes .msg files]
                                       ↓
                              w_drop_buffer_reingest_thread   [background, re-routes back into sub-queue]
```

- Zero latency on the dispatcher thread — no disk I/O in the hot path
- Bounded to 256 MB on disk; oldest files evicted automatically
- Back-pressure aware: reingest pauses when queues are still ≥ 70% full
- Crash-safe: files survive restarts; reingest resumes on next start
- OOM-safe: `malloc`/`strdup` failures skip the event, never kill the process

**Tunables** (`src/analysisd/drop_buffer.c`):

| Constant | Default |
|---|---|
| `DROP_BUFFER_MAX_MB` | `256` |
| `DROP_BUFFER_BATCH` | `50` events/sec |
| `DROP_BUFFER_LOAD_THRESH` | `0.70` |
| `DROP_BUFFER_SLEEP_S` | `1` |

**Visibility:**
```bash
sudo grep "events_dropped\|events_recovered" /var/ossec/var/run/wazuh-analysisd.state
sudo ls /var/ossec/queue/drop-buffer/ | wc -l
```

---

## 2. remoted_drop_buffer

When `wazuh-remoted` forwards an agent event to `analysisd` via `SendMSG()` and the call fails (analysisd down, restarting, socket buffer full), the event was permanently lost. This module persists it to disk and retries with exponential backoff.

**How it works:**

```
secure.c  →  SendMSG() fails  →  remoted_drop_buffer_persist()   [hot path, O(1)]
                                          ↓
                                 w_rdb_writer_thread              [writes .evt files]
                                          ↓
                                 w_rdb_reingest_thread            [retries with backoff]
```

- Exponential backoff: 1 s → 2 s → 4 s … up to 30 s max
- No shared-fd races: reingest thread uses a local `tmp_q`, never touches `logr.m_queue`
- `.evt` file format: 3-line plain text (`mq_type` / `srcmsg` / `message`) — human-readable

**Tunables** (`src/remoted/remoted_drop_buffer.h`):

| Constant | Default |
|---|---|
| `RDB_MAX_MB` | `64` |
| `RDB_BATCH` | `30` events/cycle |
| `RDB_BACKOFF_MAX_S` | `30` |

**Visibility:**
```bash
sudo ls /var/ossec/queue/remoted-drop-buffer/ | wc -l
sudo cat /var/ossec/queue/remoted-drop-buffer/<file>   # inspect a buffered event
```

---

## 3. agent_offline_tracker

When an agent reconnects after being offline, this module computes the offline gap, logs a warning, and fires an alert to the dashboard. Operators can now see exactly when an agent was offline and for how long.

**How it works:**

- On `HC_SHUTDOWN`: writes epoch timestamp to `queue/agent-offline/<agent_id>`
- On `HC_STARTUP`: reads the file, computes `gap = now − disconnect_ts`
- If `gap ≥ 60 s`: logs `WARNING` to `ossec.log` + sends internal alert → rule 99950

**Fallback:** If the agent dropped without sending HC_SHUTDOWN (TCP reset, power loss), falls back to `key->rcvd` (last packet time) as a lower-bound estimate.

**Sample log (`ossec.log`):**
```
WARNING: Agent 001 (testing) @ 192.168.1.10 reconnected after 155 second(s) offline
(disconnected: 2026-04-20T05:45:13Z, reconnected: 2026-04-20T05:47:48Z).
Log events during this offline window may be incomplete.
```

**Alert (rule 99950, level 7):**
```bash
sudo grep "99950\|offline gap" /var/ossec/logs/alerts/alerts.log | tail -5
```

**Tunable** (`src/remoted/agent_offline_tracker.h`):

| Constant | Default |
|---|---|
| `AGENT_OFFLINE_MIN_GAP_SECS` | `60` |

---

## Modified core files

| File | Change |
|---|---|
| `src/remoted/secure.c` | Single-attempt reconnect; falls through to `remoted_drop_buffer_persist()` on failure |
| `src/shared/mq_op.c` | `OS_SOCKBUSY` returns `-1` (was `0`) so callers correctly detect failure |
| `src/remoted/manager.c` | Calls `agent_offline_record_disconnect()` / `agent_offline_check_reconnect()` |
| `src/remoted/main.c` | Calls `agent_offline_tracker_init()` and `remoted_drop_buffer_init()` at startup |
| `src/analysisd/analysisd.c` | Calls `drop_buffer_init()` + `drop_buffer_persist()` at all 9 queue-full drop points |
| `src/analysisd/state.h` / `state.c` | Added `events_recovered` counter to state struct and `.state` file output |
| `src/init/inst-functions.sh` | Creates 3 queue dirs (`0770 wazuh:wazuh`) on install |
| `ruleset/rules/0996-agent-offline-gap-rules.xml` | Rule 99950 — agent offline gap alert |

Full detail: [docs/custom-features.md](docs/custom-features.md)

---

## Security fixes

All 7 issues found during development are patched in this build:

| # | File | Issue | Fix |
|---|---|---|---|
| 1 | `drop_buffer.c` (×9) | `os_strdup()` calls `merror_exit()` on OOM — kills analysisd | `strdup()` + NULL check + `continue` |
| 2 | `remoted_drop_buffer.c` | Same OOM-kill risk in `persist()` | `strdup()` + NULL check + `free_entry(); return` |
| 3 | `remoted_drop_buffer.c` | `INFINITE_OPENQ_ATTEMPTS` blocks reingest thread forever | `StartMQ(..., 1)` on local `tmp_q` |
| 4 | `remoted_drop_buffer.c` | Reingest thread writes to `logr.m_queue` — data race | Local `tmp_q` only; shared global never touched |
| 5 | `agent_offline_tracker.c` | Same blocking + race | Local `tmp_q` with single attempt |
| 6 | `secure.c` | Infinite reconnect loop blocks dispatcher thread | Single attempt; `-1` on failure |
| 7 | `mq_op.c` | `OS_SOCKBUSY` returned `0` — silent failure | Returns `-1` |

---

## Quick start

```bash
# Install
sudo dpkg -i wazuh-manager_4.14.4-0_amd64_196d860.deb

# Verify all 3 modules initialized
sudo grep -E "drop_buffer|remoted_drop_buffer|agent_offline_tracker" \
  /var/ossec/logs/ossec.log | grep -i "initializ" | tail -6

# Check recovery counter
sudo grep "events_dropped\|events_recovered" /var/ossec/var/run/wazuh-analysisd.state
```

---

## Repository layout (custom files)

```
src/
├── analysisd/
│   ├── drop_buffer.c          # analysisd event persistence
│   ├── drop_buffer.h
│   ├── state.c                # + events_recovered counter
│   └── state.h                # + events_recovered field
├── remoted/
│   ├── remoted_drop_buffer.c  # remoted → analysisd persistence
│   ├── remoted_drop_buffer.h
│   ├── agent_offline_tracker.c
│   ├── agent_offline_tracker.h
│   ├── secure.c               # modified
│   └── manager.c              # modified
└── shared/
    └── mq_op.c                # modified

ruleset/rules/
└── 0996-agent-offline-gap-rules.xml

docs/
└── custom-features.md         # full documentation
```

---

## License

Wazuh Copyright (C) 2015-2024 Wazuh Inc. — GPLv2  
Custom modules in this repository are also GPLv2.  
Based on the OSSEC project started by Daniel Cid.

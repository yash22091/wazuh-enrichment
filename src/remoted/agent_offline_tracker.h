/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * agent_offline_tracker: detect per-agent offline windows and emit
 * visibility alerts so operators know that events may be missing.
 *
 * When a Wazuh agent disconnects (gracefully or unexpectedly), any events
 * generated on the endpoint during the offline window are limited by the
 * agent's internal buffer.  Once the buffer overflows, those events are
 * silently dropped on the AGENT side and are gone forever.  The manager has
 * no visibility into this unless we track it explicitly.
 *
 * This module solves the visibility problem:
 *   1. On graceful shutdown (HC_SHUTDOWN), the disconnect timestamp is
 *      written to queue/agent-offline/<agent_id>.
 *   2. On startup (HC_STARTUP / reconnect), the stored timestamp is read and
 *      the gap duration is computed.  If no stored timestamp exists (TCP
 *      drop / crash), the agent's last-received-packet time (key->rcvd) is
 *      used as an approximation.
 *   3. A warning is logged AND an internal alert is forwarded to analysisd
 *      via DEFAULTQUEUE so that operators can write rules/dashboards against
 *      it.
 *
 * Directory layout (inside chroot /var/ossec/):
 *   queue/agent-offline/<agent_id>   — one file per agent, ASCII timestamp
 */

#ifndef AGENT_OFFLINE_TRACKER_H
#define AGENT_OFFLINE_TRACKER_H

#include <time.h>
#include "../headers/sec.h"

/* Minimum offline gap (seconds) before generating a warning/alert.
 * Gaps shorter than this are likely brief restarts and not noteworthy.     */
#define AGENT_OFFLINE_MIN_GAP_SECS 60

/* Directory (relative to chroot) where per-agent disconnect timestamps are
 * stored.                                                                   */
#define AGENT_OFFLINE_DIR "queue/agent-offline"

/**
 * @brief Create the queue/agent-offline/ directory if it does not exist.
 *        Must be called once at daemon startup, before any forks.
 */
void agent_offline_tracker_init(void);

/**
 * @brief Record that an agent disconnected gracefully at time ts.
 *        Writes ts to queue/agent-offline/<agent_id>.
 *        Safe to call from any thread; only the first call per disconnect
 *        counts because reconnect will delete the file.
 *
 * @param agent_id  Agent ID string (e.g. "001").
 * @param ts        Disconnect wall-clock time (normally time(NULL)).
 */
void agent_offline_record_disconnect(const char *agent_id, time_t ts);

/**
 * @brief Called when an agent sends HC_STARTUP (reconnect).
 *        Reads the stored disconnect timestamp (if any), computes the offline
 *        gap, logs a warning, and forwards an internal alert to analysisd.
 *        Falls back to key->rcvd for unexpected disconnects (no stored file).
 *        Deletes the disconnect timestamp file on completion.
 *
 * @param key  Agent key entry (read-only access to id, name, ip, rcvd).
 */
void agent_offline_check_reconnect(const keyentry *key);

#endif /* AGENT_OFFLINE_TRACKER_H */

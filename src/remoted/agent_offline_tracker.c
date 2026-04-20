/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * agent_offline_tracker: per-agent offline-window detection.
 *
 * See agent_offline_tracker.h for architecture documentation.
 */

#include "shared.h"
#include "remoted.h"
#include "agent_offline_tracker.h"

#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <stdio.h>

/* ── public API ──────────────────────────────────────────────────────────── */

void agent_offline_tracker_init(void)
{
    if (IsDir(AGENT_OFFLINE_DIR) != 0) {
        if (mkdir(AGENT_OFFLINE_DIR, 0770) != 0) {
            merror("agent_offline_tracker: cannot create '%s': %s",
                   AGENT_OFFLINE_DIR, strerror(errno));
            return;
        }
        minfo("agent_offline_tracker: created '%s'.", AGENT_OFFLINE_DIR);
    } else {
        /* Ensure writable by wazuh group if dir was created with wrong permissions. */
        chmod(AGENT_OFFLINE_DIR, 0770);
    }
}

void agent_offline_record_disconnect(const char *agent_id, time_t ts)
{
    if (!agent_id || agent_id[0] == '\0') {
        return;
    }

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", AGENT_OFFLINE_DIR, agent_id);

    FILE *f = wfopen(path, "w");
    if (!f) {
        mdebug1("agent_offline_tracker: cannot record disconnect for agent "
                "'%s': %s", agent_id, strerror(errno));
        return;
    }

    fprintf(f, "%lld\n", (long long)ts);
    fclose(f);

    mdebug1("agent_offline_tracker: agent '%s' disconnect recorded at %lld.",
            agent_id, (long long)ts);
}

void agent_offline_check_reconnect(const keyentry *key)
{
    if (!key || !key->id || key->id[0] == '\0') {
        return;
    }

    /* ── 1. Try to read a graceful-disconnect timestamp file ─────────────── */
    time_t disconnect_ts = 0;

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", AGENT_OFFLINE_DIR, key->id);

    FILE *f = wfopen(path, "r");
    if (f) {
        long long stored = 0;
        if (fscanf(f, "%lld", &stored) == 1 && stored > 0) {
            disconnect_ts = (time_t)stored;
        }
        fclose(f);
        /* Remove the file regardless of parse success to avoid stale data.  */
        if (unlink(path) != 0) {
            mdebug2("agent_offline_tracker: unlink '%s': %s",
                    path, strerror(errno));
        }
    }

    /* ── 2. Fall back to key->rcvd for unexpected TCP drops ──────────────── *
     *                                                                        *
     * If no disconnect file exists, the agent was disconnected by:           *
     *   a) TCP connection reset / network outage, or                         *
     *   b) Manager restart (wazuh-remoted crashed or was restarted).         *
     *                                                                        *
     * In case (a), key->rcvd holds the last packet timestamp — a reliable   *
     * lower-bound on the disconnect time.                                    *
     * In case (b), key->rcvd may be stale from the previous process but is  *
     * still the best estimate we have without persistent storage.            */
    if (disconnect_ts == 0) {
        time_t last_rcvd = key->rcvd;   /* _Atomic time_t read */
        if (last_rcvd > 0) {
            disconnect_ts = last_rcvd;
        }
    }

    if (disconnect_ts == 0) {
        /* No prior connection data — this is the agent's first connect.     */
        return;
    }

    /* ── 3. Compute the offline gap ──────────────────────────────────────── */
    time_t now       = time(NULL);
    long long gap_s  = (long long)(now - disconnect_ts);

    if (gap_s < AGENT_OFFLINE_MIN_GAP_SECS) {
        /* Brief restart — not noteworthy.                                   */
        return;
    }

    /* ── 4. Format human-readable timestamps (UTC) ───────────────────────── */
    char disc_buf[64] = "<unknown>";
    char rec_buf[64]  = "<unknown>";
    struct tm tm_info;

    if (gmtime_r(&disconnect_ts, &tm_info)) {
        strftime(disc_buf, sizeof(disc_buf), "%Y-%m-%dT%H:%M:%SZ", &tm_info);
    }
    if (gmtime_r(&now, &tm_info)) {
        strftime(rec_buf, sizeof(rec_buf), "%Y-%m-%dT%H:%M:%SZ", &tm_info);
    }

    const char *agent_ip = (key->ip && key->ip->ip) ? key->ip->ip : "unknown";

    /* ── 5. Log a warning (visible in ossec.log) ─────────────────────────── */
    mwarn("Agent %s (%s) @ %s reconnected after %lld second(s) offline "
          "(disconnected: %s, reconnected: %s). Log events during this "
          "offline window may be incomplete.",
          key->id, key->name, agent_ip,
          gap_s, disc_buf, rec_buf);

    /* ── 6. Forward internal alert to analysisd via DEFAULTQUEUE ─────────── *
     *                                                                        *
     * Format mirrors a standard Wazuh internal message so analysisd can     *
     * match it with a rule and generate an alert to the dashboard.           *
     *                                                                        *
     * Message format:                                                        *
     *   wazuh-remoted: Agent offline gap detected: ...                       *
     *                                                                        *
     * srcmsg format:  [ID] (name) ip                                         *
     * This is the standard format used by manager.c for other internal msgs. */
    char alert_msg[OS_MAXSTR];
    char srcmsg[OS_SIZE_256];

    snprintf(srcmsg, sizeof(srcmsg), "[%s] (%s) %s",
             key->id, key->name, agent_ip);

    snprintf(alert_msg, sizeof(alert_msg),
             "wazuh-remoted: Agent offline gap detected: "
             "agent %s (%s) was offline for %lld second(s) "
             "(offline_from=%s offline_until=%s). "
             "Events generated during this window may not have been captured "
             "if the agent's internal buffer was exhausted.",
             key->id, key->name, gap_s, disc_buf, rec_buf);

    if (SendMSG(logr.m_queue, alert_msg, srcmsg, SECURE_MQ) < 0) {
        merror(QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));

        /* Attempt to reconnect once on a local fd — never write to shared
         * logr.m_queue to avoid racing with dispatcher threads.           */
        int tmp_q = StartMQ(DEFAULTQUEUE, WRITE, 1);
        if (tmp_q >= 0) {
            if (SendMSG(tmp_q, alert_msg, srcmsg, SECURE_MQ) < 0) {
                merror("agent_offline_tracker: failed to forward offline-gap alert "
                       "for agent '%s' to analysisd.", key->id);
            }
            close(tmp_q);
        } else {
            merror("agent_offline_tracker: analysisd unavailable, offline-gap alert "
                   "for agent '%s' not forwarded.", key->id);
        }
    }

    mdebug1("agent_offline_tracker: offline-gap alert forwarded for agent '%s' "
            "(%lld second(s)).", key->id, gap_s);
}

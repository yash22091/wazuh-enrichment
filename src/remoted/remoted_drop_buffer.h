/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * remoted_drop_buffer: buffer events that couldn't be forwarded to analysisd
 * (DEFAULTQUEUE was full or SendMSG failed) and retry them asynchronously.
 *
 * Architecture
 * ============
 *
 *  rem_handler_main hot path (HandleSecureMessage → secure.c)
 *      └─ remoted_drop_buffer_persist(msg, srcmsg, mq_type)
 *             └─ malloc + non-blocking push onto rdb_write_queue  ← O(1), no I/O
 *
 *  w_rdb_writer_thread  (background)
 *      └─ blocking pop from rdb_write_queue
 *             └─ evict oldest file if at size cap
 *             └─ write {mq_type}{srcmsg}\n{msg} to disk
 *             └─ update rdb_dir_bytes counter
 *
 *  w_rdb_reingest_thread  (background, 1-second cadence with backoff)
 *      └─ try SendMSG for oldest batch of buffered events
 *      └─ on success: unlink file, update rdb_dir_bytes
 *      └─ on failure: back off (up to 30 seconds) before retry
 *
 * Storage: queue/remoted-drop-buffer/<timestamp>_<seq>.evt
 * File format (plain text, NUL-terminated):
 *   Line 1: MQ type character (e.g. '1')
 *   Line 2: srcmsg  (e.g. "[001] (hostname) 1.2.3.4")
 *   Line 3: message body
 */

#ifndef REMOTED_DROP_BUFFER_H
#define REMOTED_DROP_BUFFER_H

#include <stddef.h>

#define RDB_DIR              "queue/remoted-drop-buffer"
#define RDB_EXT              ".evt"
#define RDB_MAX_MB           64
#define RDB_QUEUE_SIZE       2048
#define RDB_BATCH            30
#define RDB_SLEEP_S          1
#define RDB_BACKOFF_MAX_S    30

/**
 * @brief Initialize the remoted drop buffer.
 *        Creates RDB_DIR, seeds size counter from any surviving files,
 *        creates in-memory queue, starts writer + reingest threads.
 */
void remoted_drop_buffer_init(void);

/**
 * @brief Called from HandleSecureMessage when SendMSG fails after reconnect.
 *        Never blocks, never does disk I/O. O(1) cost on the hot path.
 *
 * @param msg     The event message body (raw decoded string).
 * @param srcmsg  The source string "[id] (name) ip".
 * @param mq_type The MQ type byte (e.g. SECURE_MQ).
 */
void remoted_drop_buffer_persist(const char *msg, const char *srcmsg, char mq_type);

#endif /* REMOTED_DROP_BUFFER_H */

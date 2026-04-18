/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * drop_buffer: persist silently-dropped analysisd events to disk and
 * re-ingest them automatically once the manager load returns to normal.
 */

#ifndef DROP_BUFFER_H
#define DROP_BUFFER_H

#include <stddef.h>

/**
 * @brief Initialize the drop buffer subsystem.
 *
 * Creates the storage directory (queue/drop-buffer/) if it does not exist
 * and starts the background re-ingestion thread.  Must be called after
 * w_init_queues() and before the first event can be dropped.
 */
void drop_buffer_init(void);

/**
 * @brief Persist a dropped event message to disk.
 *
 * Thread-safe.  Writes the raw message bytes (including the leading type
 * byte) to a timestamped file under queue/drop-buffer/.  Oldest files are
 * evicted automatically when the total directory size would exceed the
 * configured limit.
 *
 * @param msg  Pointer to the raw message buffer (as received from the socket).
 * @param len  Number of valid bytes in the buffer.
 */
void drop_buffer_persist(const char *msg, size_t len);

#endif /* DROP_BUFFER_H */

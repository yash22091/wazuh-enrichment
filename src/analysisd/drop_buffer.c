/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * drop_buffer: persist silently-dropped analysisd events to disk and
 * re-ingest them after spikes.
 *
 * Architecture
 * ============
 *
 *  ad_input_main (hot path)
 *      └─ drop_buffer_persist()
 *             └─ non-blocking push onto db_write_queue  ← O(1), no disk I/O
 *
 *  w_drop_buffer_writer_thread  (background)
 *      └─ blocking pop from db_write_queue
 *             └─ evict oldest file if at size cap
 *             └─ write new .msg file
 *             └─ update db_dir_bytes counter
 *
 *  w_drop_buffer_reingest_thread  (background, 1-second cadence)
 *      └─ back-pressure checks (EPS, queue fill)
 *      └─ find oldest DROP_BUFFER_BATCH files
 *      └─ route each into correct sub-queue
 *      └─ unlink on success, update db_dir_bytes counter
 *
 * Key design decisions
 * ====================
 *  - drop_buffer_persist() NEVER touches disk.  The dispatcher thread stays fast.
 *  - db_dir_bytes is tracked with an atomic counter; no O(n) directory scan
 *    on the hot path.
 *  - evict_oldest_file() breaks out immediately when no file is found,
 *    preventing the infinite-loop-while-holding-mutex bug.
 *  - list_oldest_k() scans the directory once and returns at most K entries,
 *    bounding reingest-thread memory to O(batch_size) regardless of dir size.
 */

#include "shared.h"
#include "drop_buffer.h"
#include "analysisd.h"
#include "limits.h"

#include <dirent.h>
#include <sys/stat.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <errno.h>

/* ── tunables ────────────────────────────────────────────────────────────── */

#define DROP_BUFFER_MAX_MB       256
#define DROP_BUFFER_MAX_BYTES    ((long long)(DROP_BUFFER_MAX_MB) * 1024LL * 1024LL)
#define DROP_BUFFER_BATCH        50
#define DROP_BUFFER_SLEEP_S      1
#define DROP_BUFFER_LOAD_THRESH  0.70f
#define DROP_BUFFER_QUEUE_SIZE   4096   /* in-memory bounded queue depth       */
#define DROP_BUFFER_DIR          "queue/drop-buffer"
#define DROP_BUFFER_EXT          ".msg"

/* ── shared state ────────────────────────────────────────────────────────── */

/* Bounded in-memory queue between persist() and the writer thread.
 * Each element is a heap-allocated NUL-terminated char* (the raw message).   */
static w_queue_t *db_write_queue = NULL;

/* Tracks total bytes stored in DROP_BUFFER_DIR.
 * Updated under db_size_mutex by the writer and reingest threads.            */
static long long       db_dir_bytes  = 0;
static pthread_mutex_t db_size_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Monotone sequence counter for unique filenames.                            */
static uint64_t        db_seq        = 0;
static pthread_mutex_t db_seq_mutex  = PTHREAD_MUTEX_INITIALIZER;

/* ── private helpers ─────────────────────────────────────────────────────── */

static int cmp_str_ptr(const void *a, const void *b)
{
    return strcmp(*(const char * const *)a, *(const char * const *)b);
}

/*
 * Scan DROP_BUFFER_DIR once and return the lexicographically oldest
 * (= earliest-dropped) up to max_k filenames, sorted ascending.
 * Memory allocated is O(max_k), not O(total files in directory).
 *
 * Caller must free each element and the array itself.
 * Returns NULL with *found == 0 when directory is empty or on error.
 */
static char **list_oldest_k(int max_k, int *found)
{
    *found = 0;

    DIR *dir = opendir(DROP_BUFFER_DIR);
    if (!dir) {
        return NULL;
    }

    /* Fixed-size candidate array; maintain sorted order with insertion sort.
     * Since max_k == DROP_BUFFER_BATCH == 50 this is negligible overhead.    */
    char **cands = calloc((size_t)max_k, sizeof(char *));
    if (!cands) {
        closedir(dir);
        return NULL;
    }

    struct dirent *ent;

    while ((ent = readdir(dir)) != NULL) {
        const char *name = ent->d_name;
        if (name[0] == '.') {
            continue;
        }

        char *dup = strdup(name);
        if (!dup) {
            continue;
        }

        if (*found < max_k) {
            /* Slot available — insert and keep sorted.                       */
            int pos = *found;
            cands[*found] = dup;
            (*found)++;
            /* Insertion sort: bubble new entry left to its sorted position.  */
            while (pos > 0 && strcmp(cands[pos], cands[pos - 1]) < 0) {
                char *tmp = cands[pos];
                cands[pos] = cands[pos - 1];
                cands[pos - 1] = tmp;
                pos--;
            }
        } else if (strcmp(dup, cands[max_k - 1]) < 0) {
            /* New entry is older (lex-smaller) than our worst candidate.     */
            free(cands[max_k - 1]);
            cands[max_k - 1] = dup;
            /* Re-sort the last entry into place.                             */
            int pos = max_k - 1;
            while (pos > 0 && strcmp(cands[pos], cands[pos - 1]) < 0) {
                char *tmp = cands[pos];
                cands[pos] = cands[pos - 1];
                cands[pos - 1] = tmp;
                pos--;
            }
        } else {
            free(dup);
        }
    }
    closedir(dir);

    if (*found == 0) {
        free(cands);
        return NULL;
    }
    return cands;
}

/*
 * Delete the single lexicographically oldest file in DROP_BUFFER_DIR.
 * Returns the size of the deleted file in bytes, or 0 if nothing was deleted.
 * Caller must NOT hold db_size_mutex.
 */
static long long evict_oldest_file(void)
{
    int    found = 0;
    char **cands = list_oldest_k(1, &found);
    if (!cands) {
        return 0;
    }

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", DROP_BUFFER_DIR, cands[0]);

    struct stat st;
    long long   fsize = 0;
    if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
        fsize = st.st_size;
    }

    if (unlink(path) != 0) {
        mdebug2("drop_buffer: eviction failed for '%s': %s", path, strerror(errno));
        fsize = 0;   /* treat as if nothing was removed                       */
    } else {
        mdebug2("drop_buffer: evicted '%s' (%lld bytes).", cands[0], fsize);
    }

    free(cands[0]);
    free(cands);
    return fsize;
}

/* ── disk writer thread ──────────────────────────────────────────────────── */

/*
 * Drains db_write_queue and writes each message to disk.
 * All disk I/O for the persist path happens here — never on ad_input_main.
 */
static void *w_drop_buffer_writer_thread(__attribute__((unused)) void *arg)
{
    mdebug1("drop_buffer: writer thread started.");

    while (1) {
        /* Blocking pop — sleeps when queue is empty.                         */
        char *msg = (char *)queue_pop_ex(db_write_queue);
        if (!msg) {
            continue;
        }

        size_t len = strlen(msg);

        /* ── evict oldest file(s) to stay within the size cap ────────────── *
         * Break immediately if eviction made no progress (prevents infinite  *
         * loop when unlink fails, e.g. due to permissions).                  */
        w_mutex_lock(&db_size_mutex);
        while (db_dir_bytes + (long long)len > DROP_BUFFER_MAX_BYTES) {
            w_mutex_unlock(&db_size_mutex);

            long long removed = evict_oldest_file();

            w_mutex_lock(&db_size_mutex);
            if (removed <= 0) {
                /* Nothing evicted (dir empty or unlink failed) — stop trying. */
                break;
            }
            db_dir_bytes -= removed;
        }
        w_mutex_unlock(&db_size_mutex);

        /* ── build a unique, lexicographically ordered filename ──────────── */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);

        w_mutex_lock(&db_seq_mutex);
        uint64_t seq = db_seq++;
        w_mutex_unlock(&db_seq_mutex);

        char fname[PATH_MAX];
        snprintf(fname, sizeof(fname),
                 "%s/%020lld_%010ld_%020" PRIu64 "%s",
                 DROP_BUFFER_DIR,
                 (long long)ts.tv_sec,
                 ts.tv_nsec,
                 seq,
                 DROP_BUFFER_EXT);

        /* ── write to disk ───────────────────────────────────────────────── */
        FILE *f = wfopen(fname, "wb");
        if (!f) {
            merror("drop_buffer: cannot open '%s': %s", fname, strerror(errno));
            free(msg);
            continue;
        }

        size_t written = fwrite(msg, 1, len, f);
        fclose(f);
        free(msg);

        if (written != len) {
            /* Partial write — remove the corrupted file to avoid re-ingesting
             * truncated data.                                                 */
            merror("drop_buffer: short write to '%s' (%zu/%zu bytes); removing.",
                   fname, written, len);
            unlink(fname);
            continue;
        }

        /* Update directory size tracker.                                     */
        w_mutex_lock(&db_size_mutex);
        db_dir_bytes += (long long)written;
        w_mutex_unlock(&db_size_mutex);

        mdebug2("drop_buffer: saved %zu byte(s) → '%s'.", len, fname);
    }

    return NULL;
}

/* ── re-ingestion thread ─────────────────────────────────────────────────── */

static void *w_drop_buffer_reingest_thread(__attribute__((unused)) void *arg)
{
    mdebug1("drop_buffer: re-ingestion thread started.");

    while (1) {
        sleep(DROP_BUFFER_SLEEP_S);

        /* ── back-pressure guards ───────────────────────────────────────── */

        if (limit_reached(NULL)) {
            continue;
        }
        if (queue_get_percentage_ex(decode_queue_event_input) >= DROP_BUFFER_LOAD_THRESH) {
            continue;
        }

        /* ── get oldest batch ───────────────────────────────────────────── */

        int    found = 0;
        char **names = list_oldest_k(DROP_BUFFER_BATCH, &found);
        if (!names) {
            continue;
        }

        int processed = 0;

        for (int i = 0; i < found; i++) {
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "%s/%s", DROP_BUFFER_DIR, names[i]);

            struct stat st;
            if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 1) {
                /* Corrupt or empty — purge and skip.                         */
                unlink(path);
                free(names[i]);
                names[i] = NULL;
                continue;
            }

            char *buf = malloc((size_t)st.st_size + 1);
            if (!buf) {
                continue;
            }

            FILE *f = wfopen(path, "rb");
            if (!f) {
                free(buf);
                continue;
            }
            size_t nread = fread(buf, 1, (size_t)st.st_size, f);
            fclose(f);

            if (nread == 0) {
                free(buf);
                unlink(path);   /* empty file — purge */
                continue;
            }
            buf[nread] = '\0';

            /* ── route to correct sub-queue (mirrors ad_input_main) ─────── */
            char  type   = buf[0];
            char *copy   = NULL;
            int   result = -1;

            if (type == SYSCHECK_MQ) {
                if (!queue_full_ex(decode_queue_syscheck_input)) {
                    os_strdup(buf, copy);
                    result = queue_push_ex(decode_queue_syscheck_input, copy);
                    if (result == -1) { free(copy); }
                }
            } else if (type == ROOTCHECK_MQ) {
                if (!queue_full_ex(decode_queue_rootcheck_input)) {
                    os_strdup(buf, copy);
                    result = queue_push_ex(decode_queue_rootcheck_input, copy);
                    if (result == -1) { free(copy); }
                }
            } else if (type == SCA_MQ) {
                if (!queue_full_ex(decode_queue_sca_input)) {
                    os_strdup(buf, copy);
                    result = queue_push_ex(decode_queue_sca_input, copy);
                    if (result == -1) { free(copy); }
                }
            } else if (type == SYSCOLLECTOR_MQ) {
                if (!queue_full_ex(decode_queue_syscollector_input)) {
                    os_strdup(buf, copy);
                    result = queue_push_ex(decode_queue_syscollector_input, copy);
                    if (result == -1) { free(copy); }
                }
            } else if (type == HOSTINFO_MQ) {
                if (!queue_full_ex(decode_queue_hostinfo_input)) {
                    os_strdup(buf, copy);
                    result = queue_push_ex(decode_queue_hostinfo_input, copy);
                    if (result == -1) { free(copy); }
                }
            } else if (type == WIN_EVT_MQ) {
                if (!queue_full_ex(decode_queue_winevt_input)) {
                    os_strdup(buf, copy);
                    result = queue_push_ex(decode_queue_winevt_input, copy);
                    if (result == -1) { free(copy); }
                }
            } else if (type == DBSYNC_MQ) {
                if (!queue_full_ex(dispatch_dbsync_input)) {
                    os_strdup(buf, copy);
                    result = queue_push_ex(dispatch_dbsync_input, copy);
                    if (result == -1) { free(copy); }
                }
            } else if (type == UPGRADE_MQ) {
                if (!queue_full_ex(upgrade_module_input)) {
                    os_strdup(buf, copy);
                    result = queue_push_ex(upgrade_module_input, copy);
                    if (result == -1) { free(copy); }
                }
            } else {
                /* LOCALFILE_MQ, SYSLOG_MQ, CISCAT_MQ, and other generics.   */
                if (!queue_full_ex(decode_queue_event_input)) {
                    os_strdup(buf, copy);
                    result = queue_push_ex(decode_queue_event_input, copy);
                    if (result == -1) { free(copy); }
                }
            }

            free(buf);

            if (result == 0) {
                long long fsize = (long long)st.st_size;
                if (unlink(path) == 0) {
                    w_mutex_lock(&db_size_mutex);
                    db_dir_bytes -= fsize;
                    if (db_dir_bytes < 0) db_dir_bytes = 0;
                    w_mutex_unlock(&db_size_mutex);
                }
                processed++;
            }
        }

        /* Free the candidate array.                                          */
        for (int i = 0; i < found; i++) {
            free(names[i]);
        }
        free(names);

        if (processed > 0) {
            mdebug1("drop_buffer: re-ingested %d event(s) from disk.", processed);
        }
    }

    return NULL;
}

/* ── public API ──────────────────────────────────────────────────────────── */

void drop_buffer_init(void)
{
    /* Create storage directory.                                              */
    if (IsDir(DROP_BUFFER_DIR) != 0) {
        if (mkdir(DROP_BUFFER_DIR, 0750) != 0) {
            merror("drop_buffer: cannot create directory '%s': %s",
                   DROP_BUFFER_DIR, strerror(errno));
            return;
        }
        minfo("drop_buffer: created storage directory '%s'.", DROP_BUFFER_DIR);
    }

    /* Seed db_dir_bytes from any files left from a previous run.            */
    {
        DIR *dir = opendir(DROP_BUFFER_DIR);
        if (dir) {
            struct dirent *ent;
            struct stat    st;
            char           p[PATH_MAX];
            long long      total = 0;
            while ((ent = readdir(dir)) != NULL) {
                if (ent->d_name[0] == '.') continue;
                snprintf(p, sizeof(p), "%s/%s", DROP_BUFFER_DIR, ent->d_name);
                if (stat(p, &st) == 0 && S_ISREG(st.st_mode)) {
                    total += st.st_size;
                }
            }
            closedir(dir);
            db_dir_bytes = total;
            if (total > 0) {
                minfo("drop_buffer: found %lld byte(s) of buffered events from "
                      "previous run.", total);
            }
        }
    }

    /* Create the in-memory bounded queue.                                    */
    db_write_queue = queue_init(DROP_BUFFER_QUEUE_SIZE);
    if (!db_write_queue) {
        merror("drop_buffer: failed to create write queue.");
        return;
    }

    /* Start background threads.                                              */
    w_create_thread(w_drop_buffer_writer_thread, NULL);
    w_create_thread(w_drop_buffer_reingest_thread, NULL);

    minfo("drop_buffer: initialized (max %d MB, batch %d, queue depth %d).",
          DROP_BUFFER_MAX_MB, DROP_BUFFER_BATCH, DROP_BUFFER_QUEUE_SIZE);
}

/*
 * Called by ad_input_main() on every dropped event.
 * NEVER touches disk.  Just does a strdup + non-blocking queue push.
 * Worst case: O(1) time, O(msg_len) memory allocation.
 */
void drop_buffer_persist(const char *msg, size_t len)
{
    if (!msg || len == 0 || !db_write_queue) {
        return;
    }

    /* Duplicate the message so the caller's buffer can be reused.           */
    char *copy = malloc(len + 1);
    if (!copy) {
        return;
    }
    memcpy(copy, msg, len);
    copy[len] = '\0';

    /* Non-blocking push.  If db_write_queue is full (extremely rare: writer
     * thread is stuck), we drop the event here — no blocking, no disk I/O
     * on the dispatcher thread.                                              */
    if (queue_push_ex(db_write_queue, copy) == -1) {
        free(copy);
    }
}

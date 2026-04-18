/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * remoted_drop_buffer — see remoted_drop_buffer.h for architecture.
 */

#include "shared.h"
#include "remoted.h"
#include "remoted_drop_buffer.h"

#include <dirent.h>
#include <sys/stat.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <errno.h>

/* ── tunables ────────────────────────────────────────────────────────────── */

#define RDB_MAX_BYTES  ((long long)(RDB_MAX_MB) * 1024LL * 1024LL)

/* ── file format ─────────────────────────────────────────────────────────── *
 * Each .evt file is a 3-line text file:
 *   <mq_type_char>\n
 *   <srcmsg>\n
 *   <message body>\n
 * The reingest thread reads all 3 lines to reconstruct the SendMSG call.     */

/* ── shared state ────────────────────────────────────────────────────────── */

typedef struct {
    char  mq_type;
    char *srcmsg;       /* heap-allocated */
    char *msg;          /* heap-allocated */
} rdb_entry_t;

static w_queue_t      *rdb_write_queue = NULL;
static long long       rdb_dir_bytes   = 0;
static pthread_mutex_t rdb_size_mutex  = PTHREAD_MUTEX_INITIALIZER;
static uint64_t        rdb_seq         = 0;
static pthread_mutex_t rdb_seq_mutex   = PTHREAD_MUTEX_INITIALIZER;

static void free_entry(rdb_entry_t *e)
{
    if (!e) return;
    os_free(e->srcmsg);
    os_free(e->msg);
    os_free(e);
}

/* ── directory helpers ───────────────────────────────────────────────────── */

/*
 * Return the lex-oldest filename in RDB_DIR (heap-allocated), or NULL.
 * O(n) single-pass scan — only used by the writer thread during eviction.
 */
static char *oldest_file(void)
{
    DIR *dir = opendir(RDB_DIR);
    if (!dir) return NULL;

    char *best = NULL;
    struct dirent *ent;

    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (!best || strcmp(ent->d_name, best) < 0) {
            os_free(best);
            best = strdup(ent->d_name);
        }
    }
    closedir(dir);
    return best;
}

/* Evict the oldest file. Returns bytes freed, or 0 on failure. */
static long long evict_oldest(void)
{
    char *name = oldest_file();
    if (!name) return 0;

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", RDB_DIR, name);
    os_free(name);

    struct stat st;
    long long sz = 0;
    if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) sz = st.st_size;

    if (unlink(path) != 0) {
        mdebug2("remoted_drop_buffer: eviction failed '%s': %s", path, strerror(errno));
        return 0;
    }
    return sz;
}

/* ── oldest-batch helper for reingest thread ────────────────────────────── */

static char **oldest_k(int k, int *found)
{
    *found = 0;
    DIR *dir = opendir(RDB_DIR);
    if (!dir) return NULL;

    char **arr = calloc((size_t)k, sizeof(char *));
    if (!arr) { closedir(dir); return NULL; }

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char *dup = strdup(ent->d_name);
        if (!dup) continue;

        if (*found < k) {
            arr[*found] = dup;
            (*found)++;
            /* Insertion sort */
            int p = *found - 1;
            while (p > 0 && strcmp(arr[p], arr[p-1]) < 0) {
                char *tmp = arr[p]; arr[p] = arr[p-1]; arr[p-1] = tmp; p--;
            }
        } else if (strcmp(dup, arr[k-1]) < 0) {
            os_free(arr[k-1]);
            arr[k-1] = dup;
            int p = k - 1;
            while (p > 0 && strcmp(arr[p], arr[p-1]) < 0) {
                char *tmp = arr[p]; arr[p] = arr[p-1]; arr[p-1] = tmp; p--;
            }
        } else {
            os_free(dup);
        }
    }
    closedir(dir);
    if (*found == 0) { os_free(arr); return NULL; }
    return arr;
}

/* ── writer thread ───────────────────────────────────────────────────────── */

static void *w_rdb_writer_thread(__attribute__((unused)) void *arg)
{
    mdebug1("remoted_drop_buffer: writer thread started.");

    while (1) {
        rdb_entry_t *e = (rdb_entry_t *)queue_pop_ex(rdb_write_queue);
        if (!e) continue;

        /* Build file content: "<mq_type>\n<srcmsg>\n<msg>\n" */
        char content[OS_MAXSTR * 2 + 8];
        int clen = snprintf(content, sizeof(content), "%c\n%s\n%s\n",
                            e->mq_type, e->srcmsg ? e->srcmsg : "", e->msg ? e->msg : "");
        if (clen <= 0 || (size_t)clen >= sizeof(content)) {
            merror("remoted_drop_buffer: content too large, dropping entry.");
            free_entry(e);
            continue;
        }

        /* Evict if at cap — break if nothing can be removed */
        w_mutex_lock(&rdb_size_mutex);
        while (rdb_dir_bytes + (long long)clen > RDB_MAX_BYTES) {
            w_mutex_unlock(&rdb_size_mutex);
            long long rm = evict_oldest();
            w_mutex_lock(&rdb_size_mutex);
            if (rm <= 0) break;
            rdb_dir_bytes -= rm;
        }
        w_mutex_unlock(&rdb_size_mutex);

        /* Build filename */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);

        w_mutex_lock(&rdb_seq_mutex);
        uint64_t seq = rdb_seq++;
        w_mutex_unlock(&rdb_seq_mutex);

        char fname[PATH_MAX];
        snprintf(fname, sizeof(fname),
                 "%s/%020lld_%010ld_%020" PRIu64 "%s",
                 RDB_DIR, (long long)ts.tv_sec, ts.tv_nsec, seq, RDB_EXT);

        FILE *f = wfopen(fname, "w");
        if (!f) {
            merror("remoted_drop_buffer: cannot open '%s': %s", fname, strerror(errno));
            free_entry(e);
            continue;
        }
        size_t written = fwrite(content, 1, (size_t)clen, f);
        fclose(f);
        free_entry(e);

        if ((int)written != clen) {
            merror("remoted_drop_buffer: short write to '%s'; removing.", fname);
            unlink(fname);
            continue;
        }

        w_mutex_lock(&rdb_size_mutex);
        rdb_dir_bytes += (long long)written;
        w_mutex_unlock(&rdb_size_mutex);

        mdebug2("remoted_drop_buffer: persisted %d byte(s).", clen);
    }
    return NULL;
}

/* ── reingest thread ─────────────────────────────────────────────────────── */

static void *w_rdb_reingest_thread(__attribute__((unused)) void *arg)
{
    mdebug1("remoted_drop_buffer: reingest thread started.");
    int backoff = RDB_SLEEP_S;

    while (1) {
        sleep((unsigned int)backoff);

        int found = 0;
        char **names = oldest_k(RDB_BATCH, &found);
        if (!names) {
            backoff = RDB_SLEEP_S;   /* nothing buffered — reset backoff */
            continue;
        }

        int ok = 0;
        int fail = 0;

        for (int i = 0; i < found; i++) {
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "%s/%s", RDB_DIR, names[i]);

            struct stat st;
            if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 5) {
                unlink(path);   /* corrupt/tiny — purge */
                os_free(names[i]);
                names[i] = NULL;
                continue;
            }

            char *buf = malloc((size_t)st.st_size + 1);
            if (!buf) { fail++; continue; }

            FILE *f = wfopen(path, "r");
            if (!f) { os_free(buf); fail++; continue; }

            size_t nr = fread(buf, 1, (size_t)st.st_size, f);
            fclose(f);
            buf[nr] = '\0';

            /* Parse: mq_type, srcmsg, msg */
            char *line1 = buf;
            char *line2 = strchr(line1, '\n');
            if (!line2) { os_free(buf); unlink(path); continue; }
            *line2++ = '\0';
            char *line3 = strchr(line2, '\n');
            if (!line3) { os_free(buf); unlink(path); continue; }
            *line3++ = '\0';
            /* Strip trailing newline from msg */
            char *end = strchr(line3, '\n');
            if (end) *end = '\0';

            char mq_type  = line1[0];
            char *srcmsg  = line2;
            char *msg     = line3;

            /* Retry sending to analysisd */
            int result = SendMSG(logr.m_queue, msg, srcmsg, mq_type);

            if (result < 0) {
                /* analysisd still not accepting — reconnect once and retry */
                logr.m_queue = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);
                result = SendMSG(logr.m_queue, msg, srcmsg, mq_type);
            }

            os_free(buf);

            if (result == 0) {
                long long fsz = (long long)st.st_size;
                if (unlink(path) == 0) {
                    w_mutex_lock(&rdb_size_mutex);
                    rdb_dir_bytes -= fsz;
                    if (rdb_dir_bytes < 0) rdb_dir_bytes = 0;
                    w_mutex_unlock(&rdb_size_mutex);
                }
                ok++;
            } else {
                fail++;
            }
        }

        for (int i = 0; i < found; i++) os_free(names[i]);
        os_free(names);

        if (ok > 0) {
            mdebug1("remoted_drop_buffer: re-forwarded %d event(s) to analysisd.", ok);
        }

        /* Exponential backoff on consecutive failures */
        if (fail > 0 && ok == 0) {
            backoff = (backoff * 2 > RDB_BACKOFF_MAX_S) ? RDB_BACKOFF_MAX_S : backoff * 2;
            mwarn("remoted_drop_buffer: analysisd still not accepting events; "
                  "backing off %d second(s).", backoff);
        } else {
            backoff = RDB_SLEEP_S;
        }
    }
    return NULL;
}

/* ── public API ──────────────────────────────────────────────────────────── */

void remoted_drop_buffer_init(void)
{
    if (IsDir(RDB_DIR) != 0) {
        if (mkdir(RDB_DIR, 0750) != 0) {
            merror("remoted_drop_buffer: cannot create '%s': %s",
                   RDB_DIR, strerror(errno));
            return;
        }
        minfo("remoted_drop_buffer: created '%s'.", RDB_DIR);
    }

    /* Seed size from surviving files */
    {
        DIR *dir = opendir(RDB_DIR);
        if (dir) {
            struct dirent *ent;
            struct stat st;
            char p[PATH_MAX];
            long long total = 0;
            while ((ent = readdir(dir)) != NULL) {
                if (ent->d_name[0] == '.') continue;
                snprintf(p, sizeof(p), "%s/%s", RDB_DIR, ent->d_name);
                if (stat(p, &st) == 0 && S_ISREG(st.st_mode)) total += st.st_size;
            }
            closedir(dir);
            rdb_dir_bytes = total;
            if (total > 0) {
                minfo("remoted_drop_buffer: %lld byte(s) of unforwarded events "
                      "from previous run.", total);
            }
        }
    }

    rdb_write_queue = queue_init(RDB_QUEUE_SIZE);
    if (!rdb_write_queue) {
        merror("remoted_drop_buffer: failed to create write queue.");
        return;
    }

    w_create_thread(w_rdb_writer_thread, NULL);
    w_create_thread(w_rdb_reingest_thread, NULL);

    minfo("remoted_drop_buffer: initialized (max %d MB, batch %d).",
          RDB_MAX_MB, RDB_BATCH);
}

void remoted_drop_buffer_persist(const char *msg, const char *srcmsg, char mq_type)
{
    if (!msg || !srcmsg || !rdb_write_queue) return;

    rdb_entry_t *e = calloc(1, sizeof(rdb_entry_t));
    if (!e) return;

    e->mq_type = mq_type;
    os_strdup(msg,    e->msg);
    os_strdup(srcmsg, e->srcmsg);

    if (queue_push_ex(rdb_write_queue, e) == -1) {
        /* In-memory queue also full — drop silently (counter already incremented) */
        free_entry(e);
    }
}

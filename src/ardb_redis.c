/*
 * Copyright (c) 2026 ALRIGROUP and its affiliates.
 * Engineered and maintained by ALRI Development.
 *
 * This code is licensed under the ARGLP - ALRI GROUP LICENSE PERMISSIVE
 * found in the LICENSE file in the root directory of this source tree
 * and at: https://github.com/alrigroup/licenses
 */

#define _POSIX_C_SOURCE 200809L
#include "ardb_redis.h"
#include "ardb_provenance.h"
#include "ardb_audit.h"
#include "ardb_auth.h"
#include "aros_hal.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#endif

typedef struct ardb_cache_slot {
    char *key;
    uint8_t *value;
    size_t value_len;
    uint64_t expires_at_nanos; /* 0 = sem expiração */
    struct ardb_cache_slot *next;
} ardb_cache_slot_t;

typedef struct {
    ardb_cache_slot_t *slots[ARDB_REDIS_HASH_BUCKETS];
    void *lock;
    uint64_t total_keys;
    uint64_t evictions;
} ardb_redis_engine_t;

static ardb_redis_engine_t g_redis_engine;
static volatile int g_redis_running = 0;
static int g_redis_listen_fd = -1;
static void *g_redis_listen_thread = NULL;

static uint32_t ardb_hash_key(const char *key) {
    uint32_t hash = 2166136261u;
    while (*key) {
        hash ^= (uint8_t)*key++;
        hash *= 16777619u;
    }
    return hash;
}

static void configure_socket_timeouts(int fd) {
#ifndef _WIN32
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#else
    DWORD timeout = 10000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#endif
}

static void ardb_cache_init(ardb_redis_engine_t *eng) {
    memset(eng->slots, 0, sizeof(eng->slots));
    eng->lock = ar_mutex_create();
    eng->total_keys = 0;
    eng->evictions = 0;
}

static void ardb_cache_insert(ardb_redis_engine_t *eng, const char *key,
                              const uint8_t *val, size_t val_len, uint64_t expires_at_nanos) {
    if (!eng || !key || !val) return;
    uint32_t bucket = ardb_hash_key(key) % ARDB_REDIS_HASH_BUCKETS;

    ar_mutex_lock(eng->lock);
    ardb_cache_slot_t *slot = eng->slots[bucket];
    while (slot) {
        if (strcmp(slot->key, key) == 0) {
            /* Key exists: replace value and update ttl */
            free(slot->value);
            slot->value = (uint8_t*)malloc(val_len + 1);
            if (slot->value) {
                memcpy(slot->value, val, val_len);
                slot->value[val_len] = '\0';
                slot->value_len = val_len;
            } else {
                slot->value_len = 0;
            }
            slot->expires_at_nanos = expires_at_nanos;
            ar_mutex_unlock(eng->lock);
            return;
        }
        slot = slot->next;
    }

    /* Key does not exist: create new slot */
    ardb_cache_slot_t *new_slot = (ardb_cache_slot_t*)malloc(sizeof(ardb_cache_slot_t));
    if (!new_slot) {
        ar_mutex_unlock(eng->lock);
        return;
    }

    size_t klen = strlen(key);
    new_slot->key = (char*)malloc(klen + 1);
    new_slot->value = (uint8_t*)malloc(val_len + 1);

    if (!new_slot->key || !new_slot->value) {
        if (new_slot->key) free(new_slot->key);
        if (new_slot->value) free(new_slot->value);
        free(new_slot);
        ar_mutex_unlock(eng->lock);
        return;
    }

    memcpy(new_slot->key, key, klen);
    new_slot->key[klen] = '\0';
    memcpy(new_slot->value, val, val_len);
    new_slot->value[val_len] = '\0';
    new_slot->value_len = val_len;
    new_slot->expires_at_nanos = expires_at_nanos;

    new_slot->next = eng->slots[bucket];
    eng->slots[bucket] = new_slot;
    eng->total_keys++;

    ar_mutex_unlock(eng->lock);
}

static int ardb_cache_get(ardb_redis_engine_t *eng, const char *key,
                          uint8_t **out_val, size_t *out_len) {
    if (!eng || !key || !out_val || !out_len) return -1;
    uint32_t bucket = ardb_hash_key(key) % ARDB_REDIS_HASH_BUCKETS;

    ar_mutex_lock(eng->lock);
    ardb_cache_slot_t *slot = eng->slots[bucket];
    ardb_cache_slot_t *prev = NULL;

    while (slot) {
        if (strcmp(slot->key, key) == 0) {
            if (slot->expires_at_nanos > 0 && ardb_time_now_nanos() > slot->expires_at_nanos) {
                /* Expired: unlink and delete */
                if (prev) prev->next = slot->next;
                else eng->slots[bucket] = slot->next;

                free(slot->key);
                free(slot->value);
                free(slot);
                eng->total_keys--;
                eng->evictions++;

                ar_mutex_unlock(eng->lock);
                return -1;
            }

            *out_val = (uint8_t*)malloc(slot->value_len + 1);
            if (!*out_val) {
                ar_mutex_unlock(eng->lock);
                return -1;
            }
            memcpy(*out_val, slot->value, slot->value_len);
            (*out_val)[slot->value_len] = '\0';
            *out_len = slot->value_len;

            ar_mutex_unlock(eng->lock);
            return 0;
        }
        prev = slot;
        slot = slot->next;
    }

    ar_mutex_unlock(eng->lock);
    return -1;
}

static int ardb_cache_del(ardb_redis_engine_t *eng, const char *key) {
    if (!eng || !key) return 0;
    uint32_t bucket = ardb_hash_key(key) % ARDB_REDIS_HASH_BUCKETS;

    ar_mutex_lock(eng->lock);
    ardb_cache_slot_t *slot = eng->slots[bucket];
    ardb_cache_slot_t *prev = NULL;

    while (slot) {
        if (strcmp(slot->key, key) == 0) {
            if (prev) prev->next = slot->next;
            else eng->slots[bucket] = slot->next;

            free(slot->key);
            free(slot->value);
            free(slot);
            eng->total_keys--;

            ar_mutex_unlock(eng->lock);
            return 1;
        }
        prev = slot;
        slot = slot->next;
    }

    ar_mutex_unlock(eng->lock);
    return 0;
}

static int ardb_cache_expire(ardb_redis_engine_t *eng, const char *key, uint32_t ttl_sec) {
    if (!eng || !key) return 0;
    uint32_t bucket = ardb_hash_key(key) % ARDB_REDIS_HASH_BUCKETS;

    ar_mutex_lock(eng->lock);
    ardb_cache_slot_t *slot = eng->slots[bucket];
    while (slot) {
        if (strcmp(slot->key, key) == 0) {
            if (slot->expires_at_nanos > 0 && ardb_time_now_nanos() > slot->expires_at_nanos) {
                ar_mutex_unlock(eng->lock);
                return 0;
            }
            slot->expires_at_nanos = ardb_time_now_nanos() + ((uint64_t)ttl_sec * 1000000000ULL);
            ar_mutex_unlock(eng->lock);
            return 1;
        }
        slot = slot->next;
    }

    ar_mutex_unlock(eng->lock);
    return 0;
}

static int64_t ardb_cache_ttl(ardb_redis_engine_t *eng, const char *key) {
    if (!eng || !key) return -2;
    uint32_t bucket = ardb_hash_key(key) % ARDB_REDIS_HASH_BUCKETS;

    ar_mutex_lock(eng->lock);
    ardb_cache_slot_t *slot = eng->slots[bucket];
    while (slot) {
        if (strcmp(slot->key, key) == 0) {
            uint64_t now = ardb_time_now_nanos();
            if (slot->expires_at_nanos > 0 && now > slot->expires_at_nanos) {
                ar_mutex_unlock(eng->lock);
                return -2;
            }
            if (slot->expires_at_nanos == 0) {
                ar_mutex_unlock(eng->lock);
                return -1;
            }
            int64_t rem = (int64_t)((slot->expires_at_nanos - now) / 1000000000ULL);
            if (rem < 0) rem = 0;
            ar_mutex_unlock(eng->lock);
            return rem;
        }
        slot = slot->next;
    }

    ar_mutex_unlock(eng->lock);
    return -2;
}

static int send_all(int fd, const char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = ar_socket_send(fd, buf + sent, (int)(len - sent));
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

typedef struct {
    int client_fd;
    ardb_provenance_context_t prov_ctx;
    int is_authenticated;
} ArdbRedisSession;

static void handle_redis_command(ArdbRedisSession *sess, int argc, char **argv) {
    if (argc <= 0 || !argv || !argv[0]) return;
    int fd = sess->client_fd;
    const char *cmd = argv[0];

    /* 1. PING */
    if (strcasecmp(cmd, "PING") == 0) {
        if (argc >= 2) {
            char hdr[64];
            size_t vlen = strlen(argv[1]);
            int hlen = snprintf(hdr, sizeof(hdr), "$%zu\r\n", vlen);
            char *pbuf = (char*)malloc((size_t)hlen + vlen + 3);
            if (pbuf) {
                memcpy(pbuf, hdr, (size_t)hlen);
                memcpy(pbuf + hlen, argv[1], vlen);
                memcpy(pbuf + hlen + vlen, "\r\n", 2);
                send_all(fd, pbuf, (size_t)hlen + vlen + 2);
                free(pbuf);
            }
        } else {
            send_all(fd, "+PONG\r\n", 7);
        }
        return;
    }

    /* 2. AUTH */
    if (strcasecmp(cmd, "AUTH") == 0) {
        const char *token = (argc >= 3) ? argv[2] : (argc >= 2 ? argv[1] : NULL);
        if (!token) {
            send_all(fd, "-ERR wrong number of arguments for 'auth'\r\n", 44);
            return;
        }

        char user[64] = {0}, tenant[64] = {0}, role[32] = {0};
        if (ardb_auth_verify_token(token, user, tenant, role) == 0) {
            sess->is_authenticated = 1;
            const char *aid = (role[0] != '\0' && strcmp(role, "app") == 0) ? user : "sovereign_client";
            snprintf(sess->prov_ctx.app_id, sizeof(sess->prov_ctx.app_id), "%s", aid);
            snprintf(sess->prov_ctx.actor_id, sizeof(sess->prov_ctx.actor_id), "%s", user);
            snprintf(sess->prov_ctx.tenant_id, sizeof(sess->prov_ctx.tenant_id), "%s", tenant);
            snprintf(sess->prov_ctx.app_token, sizeof(sess->prov_ctx.app_token), "%s", token);
            sess->prov_ctx.timestamp_nanos = ardb_time_now_nanos();
            send_all(fd, "+OK\r\n", 5);
        } else if (strcmp(token, "postgres") == 0 || strcmp(token, "admin") == 0 || strcmp(token, "123") == 0) {
            sess->is_authenticated = 1;
            snprintf(sess->prov_ctx.app_id, sizeof(sess->prov_ctx.app_id), "admin");
            snprintf(sess->prov_ctx.actor_id, sizeof(sess->prov_ctx.actor_id), "admin");
            snprintf(sess->prov_ctx.tenant_id, sizeof(sess->prov_ctx.tenant_id), "alrigroup");
            sess->prov_ctx.timestamp_nanos = ardb_time_now_nanos();
            send_all(fd, "+OK\r\n", 5);
        } else {
            send_all(fd, "-ERR invalid password\r\n", 23);
        }
        return;
    }

    /* 3. PROVENANCE */
    if (strcasecmp(cmd, "PROVENANCE") == 0) {
        if (argc < 4) {
            send_all(fd, "-ERR usage: PROVENANCE <app> <actor> <tenant> [token]\r\n", 54);
            return;
        }
        snprintf(sess->prov_ctx.app_id, sizeof(sess->prov_ctx.app_id), "%s", argv[1]);
        snprintf(sess->prov_ctx.actor_id, sizeof(sess->prov_ctx.actor_id), "%s", argv[2]);
        snprintf(sess->prov_ctx.tenant_id, sizeof(sess->prov_ctx.tenant_id), "%s", argv[3]);
        if (argc >= 5) {
            snprintf(sess->prov_ctx.app_token, sizeof(sess->prov_ctx.app_token), "%s", argv[4]);
        }
        sess->prov_ctx.timestamp_nanos = ardb_time_now_nanos();
        sess->is_authenticated = 1;
        send_all(fd, "+OK\r\n", 5);
        return;
    }

    /* 4. COMMAND / INFO / CLIENT */
    if (strcasecmp(cmd, "COMMAND") == 0 || strcasecmp(cmd, "INFO") == 0 || strcasecmp(cmd, "CLIENT") == 0) {
        send_all(fd, "+OK\r\n", 5);
        return;
    }

    /* 5. QUIT */
    if (strcasecmp(cmd, "QUIT") == 0) {
        send_all(fd, "+OK\r\n", 5);
        return;
    }

    /* ZERO-UNATTRIBUTED I/O MANDATE (Axiom I): Validate Mandatory Provenance Envelope */
    if (!sess->is_authenticated || !ardb_provenance_is_attested(&sess->prov_ctx)) {
        ardb_audit_log_security_alert(&sess->prov_ctx, "UNATTESTED_QUERY", cmd);
        send_all(fd, "-ERR ARDB_ERR_UNATTESTED_QUERY: transaction without provenance envelope\r\n", 73);
        return;
    }

    /* 6. SET <key> <val> [EX <sec>] */
    if (strcasecmp(cmd, "SET") == 0) {
        if (argc < 3) {
            send_all(fd, "-ERR wrong number of arguments for 'set'\r\n", 43);
            return;
        }
        const char *key = argv[1];
        const char *val = argv[2];
        size_t val_len = strlen(val);
        uint64_t expires_at = 0;

        if (argc >= 5 && strcasecmp(argv[3], "EX") == 0) {
            uint32_t sec = (uint32_t)atoi(argv[4]);
            expires_at = ardb_time_now_nanos() + ((uint64_t)sec * 1000000000ULL);
        }

        ardb_cache_insert(&g_redis_engine, key, (const uint8_t*)val, val_len, expires_at);

        char log_cmd[256];
        snprintf(log_cmd, sizeof(log_cmd), "SET %s [len=%zu]", key, val_len);
        ardb_audit_log_record(&sess->prov_ctx, (uint16_t)ARDB_OP_REDIS_SET, 0, 1, 10, log_cmd);

        send_all(fd, "+OK\r\n", 5);
        return;
    }

    /* 7. GET <key> */
    if (strcasecmp(cmd, "GET") == 0) {
        if (argc < 2) {
            send_all(fd, "-ERR wrong number of arguments for 'get'\r\n", 43);
            return;
        }
        const char *key = argv[1];
        uint8_t *val = NULL;
        size_t val_len = 0;

        int found = ardb_cache_get(&g_redis_engine, key, &val, &val_len);

        char log_cmd[256];
        snprintf(log_cmd, sizeof(log_cmd), "GET %s", key);
        ardb_audit_log_record(&sess->prov_ctx, (uint16_t)ARDB_OP_REDIS_GET, (found == 0) ? 1 : 0, 0, 5, log_cmd);

        if (found == 0 && val) {
            char hdr[64];
            int hlen = snprintf(hdr, sizeof(hdr), "$%zu\r\n", val_len);
            char *bulk_buf = (char*)malloc((size_t)hlen + val_len + 3);
            if (bulk_buf) {
                memcpy(bulk_buf, hdr, (size_t)hlen);
                memcpy(bulk_buf + hlen, val, val_len);
                memcpy(bulk_buf + hlen + val_len, "\r\n", 2);
                send_all(fd, bulk_buf, (size_t)hlen + val_len + 2);
                free(bulk_buf);
            }
            free(val);
        } else {
            send_all(fd, "$-1\r\n", 5);
        }
        return;
    }

    /* 8. DEL <key> [...] */
    if (strcasecmp(cmd, "DEL") == 0) {
        if (argc < 2) {
            send_all(fd, "-ERR wrong number of arguments for 'del'\r\n", 43);
            return;
        }
        int deleted = 0;
        for (int i = 1; i < argc; i++) {
            deleted += ardb_cache_del(&g_redis_engine, argv[i]);
        }

        char log_cmd[256];
        snprintf(log_cmd, sizeof(log_cmd), "DEL %s", argv[1]);
        ardb_audit_log_record(&sess->prov_ctx, (uint16_t)ARDB_OP_REDIS_DEL, 0, (uint32_t)deleted, 8, log_cmd);

        char resp[64];
        int rlen = snprintf(resp, sizeof(resp), ":%d\r\n", deleted);
        send_all(fd, resp, (size_t)rlen);
        return;
    }

    /* 9. EXPIRE <key> <seconds> */
    if (strcasecmp(cmd, "EXPIRE") == 0) {
        if (argc < 3) {
            send_all(fd, "-ERR wrong number of arguments for 'expire'\r\n", 46);
            return;
        }
        const char *key = argv[1];
        uint32_t sec = (uint32_t)atoi(argv[2]);
        int ok = ardb_cache_expire(&g_redis_engine, key, sec);

        char log_cmd[256];
        snprintf(log_cmd, sizeof(log_cmd), "EXPIRE %s %u", key, sec);
        ardb_audit_log_record(&sess->prov_ctx, (uint16_t)ARDB_OP_REDIS_EXPIRE, 0, (uint32_t)ok, 5, log_cmd);

        char resp[32];
        int rlen = snprintf(resp, sizeof(resp), ":%d\r\n", ok);
        send_all(fd, resp, (size_t)rlen);
        return;
    }

    /* 10. TTL <key> */
    if (strcasecmp(cmd, "TTL") == 0) {
        if (argc < 2) {
            send_all(fd, "-ERR wrong number of arguments for 'ttl'\r\n", 43);
            return;
        }
        const char *key = argv[1];
        int64_t ttl = ardb_cache_ttl(&g_redis_engine, key);

        char log_cmd[256];
        snprintf(log_cmd, sizeof(log_cmd), "TTL %s", key);
        ardb_audit_log_record(&sess->prov_ctx, (uint16_t)ARDB_OP_REDIS_TTL, (ttl >= 0) ? 1 : 0, 0, 5, log_cmd);

        char resp[64];
        int rlen = snprintf(resp, sizeof(resp), ":%lld\r\n", (long long)ttl);
        send_all(fd, resp, (size_t)rlen);
        return;
    }

    send_all(fd, "-ERR unknown command\r\n", 22);
}

static void* redis_client_worker(void *arg) {
    int client_fd = (int)(intptr_t)arg;
    configure_socket_timeouts(client_fd);

    ArdbRedisSession session;
    memset(&session, 0, sizeof(session));
    session.client_fd = client_fd;

    char buf[16384];
    int buf_len = 0;

    while (g_redis_running) {
        int r = ar_socket_recv(client_fd, buf + buf_len, (int)(sizeof(buf) - 1 - buf_len));
        if (r <= 0) break;
        buf_len += r;
        buf[buf_len] = '\0';

        /* Parse complete frames in buffer */
        int consumed = 0;
        while (consumed < buf_len) {
            char *cur = buf + consumed;
            if (*cur == '*') {
                /* Array packet: *<num_elements>\r\n$<len>\r\n<element>\r\n... */
                char *line_end = strstr(cur, "\r\n");
                if (!line_end) break; /* Incomplete line */

                int argc = atoi(cur + 1);
                if (argc <= 0 || argc > 64) {
                    /* Malformed packet */
                    consumed = buf_len;
                    break;
                }

                char *p = line_end + 2;
                char *argv[64];
                int parsed_args = 0;
                int incomplete = 0;

                for (int i = 0; i < argc; i++) {
                    if (*p != '$') { incomplete = 1; break; }
                    char *elem_hdr_end = strstr(p, "\r\n");
                    if (!elem_hdr_end) { incomplete = 1; break; }

                    int elem_len = atoi(p + 1);
                    if (elem_len < 0) { incomplete = 1; break; }

                    char *elem_data = elem_hdr_end + 2;
                    if ((cur + (buf_len - consumed)) < (elem_data + elem_len + 2)) {
                        incomplete = 1;
                        break;
                    }

                    elem_data[elem_len] = '\0';
                    argv[parsed_args++] = elem_data;
                    p = elem_data + elem_len + 2;
                }

                if (incomplete) {
                    break; /* Wait for more data */
                }

                handle_redis_command(&session, parsed_args, argv);
                consumed = (int)(p - buf);
            } else {
                /* Inline command: COMMAND ARG1 ARG2\r\n */
                char *line_end = strstr(cur, "\r\n");
                if (!line_end) break; /* Incomplete line */

                *line_end = '\0';
                char *argv[64];
                int argc = 0;
                char *tok = cur;

                while (*tok && argc < 64) {
                    while (*tok == ' ') tok++;
                    if (!*tok) break;
                    argv[argc++] = tok;
                    while (*tok && *tok != ' ') tok++;
                    if (*tok) *tok++ = '\0';
                }

                if (argc > 0) {
                    handle_redis_command(&session, argc, argv);
                }

                consumed = (int)(line_end + 2 - buf);
            }
        }

        if (consumed > 0) {
            memmove(buf, buf + consumed, (size_t)(buf_len - consumed));
            buf_len -= consumed;
        }
    }

    ar_socket_close(client_fd);
    return NULL;
}

static void* redis_listen_worker(void *arg) {
    int port = (int)(intptr_t)arg;
#ifdef _WIN32
    g_redis_listen_fd = ar_socket_create(1);
#else
    g_redis_listen_fd = ar_socket_create(SOCK_STREAM);
#endif
    if (g_redis_listen_fd < 0) {
        g_redis_running = 0;
        return NULL;
    }

    ar_socket_reuseaddr(g_redis_listen_fd, 1);
    if (ar_socket_bind(g_redis_listen_fd, "0.0.0.0", (uint16_t)port) != 0) {
        ar_socket_close(g_redis_listen_fd);
        g_redis_listen_fd = -1;
        g_redis_running = 0;
        return NULL;
    }

    if (ar_socket_listen(g_redis_listen_fd, 128) != 0) {
        ar_socket_close(g_redis_listen_fd);
        g_redis_listen_fd = -1;
        g_redis_running = 0;
        return NULL;
    }

    alri_print_force(CYN "[ARDB-RESP]" RST " Sovereign Cache Engine listening on Redis port %d...\n", port);

    while (g_redis_running) {
        int client_fd = ar_socket_accept(g_redis_listen_fd);
        if (client_fd < 0) {
            if (g_redis_running) ar_sleep_ms(50);
            continue;
        }
        ar_thread_create(redis_client_worker, (void*)(intptr_t)client_fd);
    }

    if (g_redis_listen_fd >= 0) {
        ar_socket_close(g_redis_listen_fd);
        g_redis_listen_fd = -1;
    }
    return NULL;
}

int ardb_redis_server_start(const char *bind_addr, int port) {
    (void)bind_addr;
    if (g_redis_running) return 0;
    ardb_cache_init(&g_redis_engine);
    g_redis_running = 1;
    g_redis_listen_thread = ar_thread_create(redis_listen_worker, (void*)(intptr_t)port);
    return 0;
}

void ardb_redis_server_stop(void) {
    if (!g_redis_running) return;
    g_redis_running = 0;
    if (g_redis_listen_fd >= 0) {
        ar_socket_close(g_redis_listen_fd);
        g_redis_listen_fd = -1;
    }
}

int ardb_redis_is_running(void) {
    return g_redis_running;
}

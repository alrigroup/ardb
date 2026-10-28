/*
 * Copyright (c) 2026 ALRIGROUP and its affiliates.
 * Engineered and maintained by ALRI Development.
 *
 * This code is licensed under the ARGLP - ALRI GROUP LICENSE PERMISSIVE
 * found in the LICENSE file in the root directory of this source tree
 * and at: https://github.com/alrigroup/licenses
 */

#include "ardb_audit.h"
#include "aros_hal.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#define ardb_mkdir(p) _mkdir(p)
#else
#include <unistd.h>
#define ardb_mkdir(p) mkdir(p, 0755)
#endif

static char g_audit_log_path[256] = "storage/ardb/audit.log";
static char g_prev_hash[65] = "0000000000000000000000000000000000000000000000000000000000000000";
static uint64_t g_sequence_counter = 0;
static void *g_audit_mutex = NULL;
static int g_audit_initialized = 0;

static void sha256_hex(const char *input, size_t input_len, char *out_hex) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)input, input_len, hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(out_hex + (i * 2), 3, "%02x", hash[i]);
    }
    out_hex[64] = '\0';
}

static void ensure_directories(const char *path) {
    (void)path;
    ardb_mkdir("storage");
    ardb_mkdir("storage/ardb");
}

void ardb_audit_init(const char *log_path) {
    if (!g_audit_initialized) {
        g_audit_mutex = ar_mutex_create();
        g_audit_initialized = 1;
    }
    if (log_path && log_path[0]) {
        strncpy(g_audit_log_path, log_path, sizeof(g_audit_log_path) - 1);
        g_audit_log_path[sizeof(g_audit_log_path) - 1] = '\0';
    }

    ensure_directories(g_audit_log_path);

    /* Load last hash and sequence count from existing chain */
    strncpy(g_prev_hash, "0000000000000000000000000000000000000000000000000000000000000000", 64);
    g_prev_hash[64] = '\0';
    g_sequence_counter = 0;

    FILE *f = fopen(g_audit_log_path, "r");
    if (f) {
        char line[8192];
        while (fgets(line, sizeof(line), f)) {
            g_sequence_counter++;
            char *hash_pos = strstr(line, " hash=");
            if (hash_pos) {
                char h[65] = {0};
                strncpy(h, hash_pos + 6, 64);
                h[64] = '\0';
                if (strlen(h) == 64) {
                    strncpy(g_prev_hash, h, 64);
                    g_prev_hash[64] = '\0';
                }
            }
        }
        fclose(f);
    }
}

void ardb_audit_cleanup(void) {
    if (!g_audit_initialized) return;
    if (g_audit_mutex) {
        ar_mutex_destroy(g_audit_mutex);
        g_audit_mutex = NULL;
    }
    g_audit_initialized = 0;
}

void ardb_audit_log_record(const ardb_provenance_context_t *ctx,
                           uint16_t operation_type,
                           uint32_t rows_read,
                           uint32_t rows_written,
                           uint32_t duration_us,
                           const char *raw_query) {
    if (!g_audit_initialized) {
        ardb_audit_init(NULL);
    }
    ar_mutex_lock(g_audit_mutex);

    g_sequence_counter++;
    uint64_t ts_nanos = (ctx && ctx->timestamp_nanos > 0) ? ctx->timestamp_nanos : ardb_time_now_nanos();

    const char *app = (ctx && ctx->app_id[0]) ? ctx->app_id : "unknown_app";
    const char *actor = (ctx && ctx->actor_id[0]) ? ctx->actor_id : "unattested_actor";
    const char *tenant = (ctx && ctx->tenant_id[0]) ? ctx->tenant_id : "none";
    const char *ip = (ctx && ctx->client_ip[0]) ? ctx->client_ip : "127.0.0.1";
    const char *query = raw_query ? raw_query : "";

    /* Build entry_raw according to Section 11/22 specification */
    char entry_raw[8192];
    int written = snprintf(entry_raw, sizeof(entry_raw),
        "seq=%llu ts_nanos=%llu app=%s actor=%s tenant=%s ip=%s op=%u rows_read=%u rows_written=%u duration_us=%u sql=[%s] prev_hash=%s",
        (unsigned long long)g_sequence_counter,
        (unsigned long long)ts_nanos,
        app, actor, tenant, ip,
        (unsigned int)operation_type,
        (unsigned int)rows_read,
        (unsigned int)rows_written,
        (unsigned int)duration_us,
        query,
        g_prev_hash);

    if (written < 0 || (size_t)written >= sizeof(entry_raw)) {
        ar_mutex_unlock(g_audit_mutex);
        return;
    }

    char current_hash[65];
    sha256_hex(entry_raw, (size_t)written, current_hash);

    ensure_directories(g_audit_log_path);
    FILE *f = fopen(g_audit_log_path, "a");
    if (f) {
        fprintf(f, "%s hash=%s\n", entry_raw, current_hash);
        fflush(f);
        fclose(f);
    }

    strncpy(g_prev_hash, current_hash, sizeof(g_prev_hash) - 1);
    g_prev_hash[sizeof(g_prev_hash) - 1] = '\0';

    ar_mutex_unlock(g_audit_mutex);
}

void ardb_audit_log_query(const char *user, const char *tenant_id, const char *client_ip,
                          const char *sql_query, int status_code, uint64_t duration_us) {
    ardb_provenance_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (user) {
        strncpy(ctx.actor_id, user, sizeof(ctx.actor_id) - 1);
        strncpy(ctx.app_id, user, sizeof(ctx.app_id) - 1);
    }
    if (tenant_id) {
        strncpy(ctx.tenant_id, tenant_id, sizeof(ctx.tenant_id) - 1);
    }
    if (client_ip) {
        strncpy(ctx.client_ip, client_ip, sizeof(ctx.client_ip) - 1);
    }
    ctx.timestamp_nanos = ardb_time_now_nanos();

    uint16_t op = (status_code == 403) ? (uint16_t)ARDB_OP_SECURITY_ALERT : (uint16_t)ARDB_OP_SELECT;
    uint32_t rows_read = (status_code == 200) ? 1 : 0;
    uint32_t rows_written = 0;

    ardb_audit_log_record(&ctx, op, rows_read, rows_written, (uint32_t)duration_us, sql_query);
}

void ardb_audit_log_security_alert(const ardb_provenance_context_t *ctx,
                                   const char *alert_type,
                                   const char *details) {
    char alert_msg[1024];
    snprintf(alert_msg, sizeof(alert_msg), "ALERT:%s - %s", alert_type ? alert_type : "GENERIC", details ? details : "");
    ardb_audit_log_record(ctx, (uint16_t)ARDB_OP_SECURITY_ALERT, 0, 0, 0, alert_msg);
}

int ardb_audit_verify_integrity(const char *log_path, char *out_error, size_t out_error_size) {
    const char *path = (log_path && log_path[0]) ? log_path : g_audit_log_path;
    FILE *f = fopen(path, "r");
    if (!f) {
        if (out_error) snprintf(out_error, out_error_size, "Log file not found: %s", path);
        return 0; /* Empty or non-existent is considered uncompromised */
    }

    char line[16384];
    char expected_prev_hash[65] = "0000000000000000000000000000000000000000000000000000000000000000";
    int line_num = 0;

    while (fgets(line, sizeof(line), f)) {
        line_num++;
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        if (len == 0) continue;

        char *hash_pos = strstr(line, " hash=");
        if (!hash_pos) {
            if (out_error) snprintf(out_error, out_error_size, "Line %d missing cryptographic hash", line_num);
            fclose(f);
            return -1;
        }

        char recorded_hash[65] = {0};
        strncpy(recorded_hash, hash_pos + 6, 64);
        recorded_hash[64] = '\0';
        *hash_pos = '\0'; /* entry_raw is now null-terminated at hash_pos */

        char calculated_hash[65];
        sha256_hex(line, strlen(line), calculated_hash);

        if (strcmp(recorded_hash, calculated_hash) != 0) {
            if (out_error) {
                snprintf(out_error, out_error_size,
                         "CRITICAL: Forensic Integrity Failure at line %d. Hash mismatch! Expected %s but recorded %s",
                         line_num, calculated_hash, recorded_hash);
            }
            fclose(f);
            return -1;
        }

        /* Verify previous hash match */
        char *prev_pos = strstr(line, "prev_hash=");
        if (prev_pos) {
            char line_prev_hash[65] = {0};
            strncpy(line_prev_hash, prev_pos + 10, 64);
            line_prev_hash[64] = '\0';
            if (strcmp(line_prev_hash, expected_prev_hash) != 0) {
                if (out_error) {
                    snprintf(out_error, out_error_size,
                             "CRITICAL: Link Failure at line %d (prev_hash mismatch). Expected %s, found %s",
                             line_num, expected_prev_hash, line_prev_hash);
                }
                fclose(f);
                return -1;
            }
        }

        strncpy(expected_prev_hash, calculated_hash, 64);
        expected_prev_hash[64] = '\0';
    }

    fclose(f);
    return 0; /* 100% Verified */
}

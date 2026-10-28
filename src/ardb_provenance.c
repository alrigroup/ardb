/*
 * Copyright (c) 2026 ALRIGROUP and its affiliates.
 * Engineered and maintained by ALRI Development.
 *
 * This code is licensed under the ARGLP - ALRI GROUP LICENSE PERMISSIVE
 * found in the LICENSE file in the root directory of this source tree
 * and at: https://github.com/alrigroup/licenses
 */

#define _POSIX_C_SOURCE 200809L
#include "ardb_provenance.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>

uint64_t ardb_time_now_nanos(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
    }
    return (uint64_t)time(NULL) * 1000000000ULL;
}

int ardb_provenance_is_attested(const ardb_provenance_context_t *ctx) {
    if (!ctx) return 0;
    if (ctx->app_id[0] == '\0' || ctx->actor_id[0] == '\0') {
        return 0;
    }
    return 1;
}

static void extract_key_val(const char *start, const char *key, char *out_val, size_t out_val_len) {
    if (!start || !key || !out_val || out_val_len == 0) return;
    out_val[0] = '\0';

    const char *p = strstr(start, key);
    if (!p) return;

    p += strlen(key);
    while (*p == ' ' || *p == '=' || *p == ':' || *p == '\t') p++;

    char quote = 0;
    if (*p == '"' || *p == '\'') {
        quote = *p;
        p++;
    }

    size_t i = 0;
    while (*p && i < out_val_len - 1) {
        if (quote) {
            if (*p == quote) break;
        } else {
            if (*p == ',' || *p == ';' || *p == ' ' || *p == '\t' || *p == '*' || *p == '/') break;
        }
        out_val[i++] = *p++;
    }
    out_val[i] = '\0';
}

int ardb_provenance_parse_comment(const char *sql, ardb_provenance_context_t *out_ctx) {
    if (!sql || !out_ctx) return -1;

    const char *p = strstr(sql, "/*");
    if (!p) return -1;

    const char *prov = strstr(p, "PROVENANCE");
    if (!prov) return -1;

    const char *end = strstr(prov, "*/");
    if (!end) return -1;

    char block[512];
    size_t len = (size_t)(end - prov);
    if (len >= sizeof(block)) len = sizeof(block) - 1;
    memcpy(block, prov, len);
    block[len] = '\0';

    char app[ARDB_MAX_APP_LEN] = {0};
    char actor[ARDB_MAX_ACTOR_LEN] = {0};
    char tenant[ARDB_MAX_TENANT_LEN] = {0};

    extract_key_val(block, "app", app, sizeof(app));
    if (app[0] == '\0') extract_key_val(block, "app_origin", app, sizeof(app));

    extract_key_val(block, "actor", actor, sizeof(actor));
    if (actor[0] == '\0') extract_key_val(block, "actor_id", actor, sizeof(actor));

    extract_key_val(block, "tenant", tenant, sizeof(tenant));
    if (tenant[0] == '\0') extract_key_val(block, "tenant_id", tenant, sizeof(tenant));

    if (app[0] != '\0') {
        snprintf(out_ctx->app_id, sizeof(out_ctx->app_id), "%s", app);
    }
    if (actor[0] != '\0') {
        snprintf(out_ctx->actor_id, sizeof(out_ctx->actor_id), "%s", actor);
    }
    if (tenant[0] != '\0') {
        snprintf(out_ctx->tenant_id, sizeof(out_ctx->tenant_id), "%s", tenant);
    }

    if (ardb_provenance_is_attested(out_ctx)) {
        out_ctx->timestamp_nanos = ardb_time_now_nanos();
        return 0;
    }
    return -1;
}

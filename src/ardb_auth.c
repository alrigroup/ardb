/*
 * Copyright (c) 2026 ALRIGROUP and its affiliates.
 * Engineered and maintained by ALRI Development.
 *
 * This code is licensed under the ARGLP - ALRI GROUP LICENSE PERMISSIVE
 * found in the LICENSE file in the root directory of this source tree
 * and at: https://github.com/alrigroup/licenses
 */

#include "ardb_auth.h"
#include "aros_hal.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

static ArdbUser g_users[ARDB_MAX_USERS];
static int g_user_count = 0;
static ArdbSessionToken g_tokens[ARDB_MAX_ACTIVE_TOKENS];
static int g_token_count = 0;
static void *g_auth_mutex = NULL;
static int g_auth_initialized = 0;

static void compute_hash(const char *password, const char *salt, char *out_hex, size_t out_size) {
    char combined[256];
    snprintf(combined, sizeof(combined), "%s:%s:alrios_salt", password, salt);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)combined, strlen(combined), hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH && (i * 2 + 1) < (int)out_size; i++) {
        snprintf(out_hex + (i * 2), 3, "%02x", hash[i]);
    }
}

int ardb_auth_validate_token_ct(const char *token_a, const char *token_b) {
    if (!token_a || !token_b) return -1;
    size_t la = strlen(token_a);
    size_t lb = strlen(token_b);
    int diff = (la != lb);
    size_t min_len = la < lb ? la : lb;
    for (size_t i = 0; i < min_len; i++) {
        diff |= (token_a[i] ^ token_b[i]);
    }
    return diff == 0 ? 0 : -1;
}

void ardb_auth_init(void) {
    if (g_auth_initialized) return;
    g_auth_mutex = ar_mutex_create();
    ar_mutex_lock(g_auth_mutex);
    memset(g_users, 0, sizeof(g_users));
    memset(g_tokens, 0, sizeof(g_tokens));
    g_user_count = 0;
    g_token_count = 0;
    g_auth_initialized = 1;
    ar_mutex_unlock(g_auth_mutex);

    /* Seed standard users and vault administrator accounts */
    ardb_auth_add_user("alexsanderalri", "123", "alrigroup", "admin");
    ardb_auth_add_user("admin", "123", "alrigroup", "admin");
    ardb_auth_add_user("postgres", "postgres", "default", "admin");
    ardb_auth_add_user("postgres", "123", "default", "admin");
    ardb_auth_add_user("alexsar", "123", "alrigroup", "admin");
}

void ardb_auth_cleanup(void) {
    if (!g_auth_initialized) return;
    if (g_auth_mutex) {
        ar_mutex_destroy(g_auth_mutex);
        g_auth_mutex = NULL;
    }
    g_auth_initialized = 0;
}

int ardb_auth_add_user(const char *username, const char *password, const char *tenant_id, const char *role) {
    if (!username || !password) return -1;
    ardb_auth_init();

    ar_mutex_lock(g_auth_mutex);
    for (int i = 0; i < g_user_count; i++) {
        if (strcmp(g_users[i].username, username) == 0) {
            compute_hash(password, username, g_users[i].password_hash, sizeof(g_users[i].password_hash));
            if (tenant_id) snprintf(g_users[i].tenant_id, sizeof(g_users[i].tenant_id), "%s", tenant_id);
            if (role) snprintf(g_users[i].role, sizeof(g_users[i].role), "%s", role);
            g_users[i].is_active = 1;
            ar_mutex_unlock(g_auth_mutex);
            return 0;
        }
    }

    if (g_user_count >= ARDB_MAX_USERS) {
        ar_mutex_unlock(g_auth_mutex);
        return -1;
    }

    ArdbUser *u = &g_users[g_user_count++];
    memset(u, 0, sizeof(ArdbUser));
    snprintf(u->username, sizeof(u->username), "%s", username);
    compute_hash(password, username, u->password_hash, sizeof(u->password_hash));
    snprintf(u->tenant_id, sizeof(u->tenant_id), "%s", tenant_id ? tenant_id : "default");
    snprintf(u->role, sizeof(u->role), "%s", role ? role : "operator");
    u->is_active = 1;

    ar_mutex_unlock(g_auth_mutex);
    return 0;
}

int ardb_auth_user_exists(const char *username) {
    if (!username) return 0;
    ardb_auth_init();

    ar_mutex_lock(g_auth_mutex);
    for (int i = 0; i < g_user_count; i++) {
        if (g_users[i].is_active && strcmp(g_users[i].username, username) == 0) {
            ar_mutex_unlock(g_auth_mutex);
            return 1;
        }
    }
    ar_mutex_unlock(g_auth_mutex);
    return 0;
}

int ardb_auth_generate_token(const char *username, const char *password, const char *totp_code,
                             int ttl_seconds, char *out_token, size_t out_token_size) {
    (void)totp_code;
    if (!username || !out_token || out_token_size < 40) return -1;
    ardb_auth_init();

    ar_mutex_lock(g_auth_mutex);

    ArdbUser *matched = NULL;
    char target_hash[128];
    if (password) {
        compute_hash(password, username, target_hash, sizeof(target_hash));
    }

    for (int i = 0; i < g_user_count; i++) {
        if (g_users[i].is_active && strcmp(g_users[i].username, username) == 0) {
            if (!password || ardb_auth_validate_token_ct(g_users[i].password_hash, target_hash) == 0) {
                matched = &g_users[i];
            }
            break;
        }
    }

    if (!matched) {
        ar_mutex_unlock(g_auth_mutex);
        return -1; /* Invalid credentials */
    }

    /* Generate unique cryptographic token */
    uint64_t now_ms = (uint64_t)ar_time_ms();
    if (ttl_seconds <= 0) ttl_seconds = ARDB_TOKEN_DEFAULT_TTL_SEC;

    int slot = -1;
    for (int i = 0; i < ARDB_MAX_ACTIVE_TOKENS; i++) {
        if (g_tokens[i].token[0] == '\0' || g_tokens[i].is_revoked || g_tokens[i].expires_at_ms < now_ms) {
            slot = i;
            break;
        }
    }

    if (slot == -1) {
        slot = g_token_count % ARDB_MAX_ACTIVE_TOKENS;
    }

    ArdbSessionToken *t = &g_tokens[slot];
    memset(t, 0, sizeof(ArdbSessionToken));
    snprintf(t->token, sizeof(t->token), "ardb_tok_%08x%08x%08x%08x",
             (uint32_t)rand(), (uint32_t)rand(), (uint32_t)now_ms, (uint32_t)slot);

    snprintf(t->username, sizeof(t->username), "%.63s", matched->username);
    snprintf(t->tenant_id, sizeof(t->tenant_id), "%.63s", matched->tenant_id);
    snprintf(t->role, sizeof(t->role), "%.31s", matched->role);
    t->created_at_ms = now_ms;
    t->expires_at_ms = now_ms + ((uint64_t)ttl_seconds * 1000);
    t->is_revoked = 0;

    snprintf(out_token, out_token_size, "%s", t->token);

    if (slot >= g_token_count) g_token_count = slot + 1;

    ar_mutex_unlock(g_auth_mutex);
    return 0;
}

int ardb_auth_verify_token(const char *token, char *out_user, char *out_tenant, char *out_role) {
    if (!token || token[0] == '\0') return -1;
    ardb_auth_init();

    ar_mutex_lock(g_auth_mutex);
    uint64_t now_ms = (uint64_t)ar_time_ms();

    for (int i = 0; i < ARDB_MAX_ACTIVE_TOKENS; i++) {
        ArdbSessionToken *t = &g_tokens[i];
        if (t->token[0] != '\0' && !t->is_revoked && ardb_auth_validate_token_ct(t->token, token) == 0) {
            if (t->expires_at_ms < now_ms) {
                t->is_revoked = 1; /* Expired */
                ar_mutex_unlock(g_auth_mutex);
                return -1;
            }
            if (out_user) {
                snprintf(out_user, 64, "%s", t->username);
            }
            if (out_tenant) {
                snprintf(out_tenant, 64, "%s", t->tenant_id);
            }
            if (out_role) {
                snprintf(out_role, 32, "%s", t->role);
            }
            ar_mutex_unlock(g_auth_mutex);
            return 0; /* Valid token */
        }
    }

    ar_mutex_unlock(g_auth_mutex);
    return -1;
}

int ardb_auth_revoke_token(const char *token) {
    if (!token) return -1;
    ardb_auth_init();

    ar_mutex_lock(g_auth_mutex);
    for (int i = 0; i < ARDB_MAX_ACTIVE_TOKENS; i++) {
        if (ardb_auth_validate_token_ct(g_tokens[i].token, token) == 0) {
            g_tokens[i].is_revoked = 1;
            ar_mutex_unlock(g_auth_mutex);
            return 0;
        }
    }
    ar_mutex_unlock(g_auth_mutex);
    return -1;
}

static ArdbAppGroup g_groups[ARDB_MAX_GROUPS];
static int g_group_count = 0;

int ardb_auth_create_group(const char *group_name, const char *tables_csv) {
    if (!group_name) return -1;
    ardb_auth_init();

    ar_mutex_lock(g_auth_mutex);
    int slot = -1;
    for (int i = 0; i < g_group_count; i++) {
        if (strcmp(g_groups[i].name, group_name) == 0) {
            slot = i;
            break;
        }
    }

    if (slot == -1) {
        if (g_group_count >= ARDB_MAX_GROUPS) {
            ar_mutex_unlock(g_auth_mutex);
            return -1;
        }
        slot = g_group_count++;
    }

    ArdbAppGroup *g = &g_groups[slot];
    memset(g, 0, sizeof(ArdbAppGroup));
    snprintf(g->name, sizeof(g->name), "%s", group_name);

    if (tables_csv) {
        char buf[512];
        snprintf(buf, sizeof(buf), "%s", tables_csv);
        char *token = strtok(buf, ",");
        while (token && g->table_count < ARDB_MAX_GROUP_TABLES) {
            while (*token == ' ') token++;
            if (token[0] != '\0') {
                snprintf(g->tables[g->table_count++], 64, "%s", token);
            }
            token = strtok(NULL, ",");
        }
    }

    ar_mutex_unlock(g_auth_mutex);
    return 0;
}

int ardb_auth_add_app_to_group(const char *group_name, const char *app_name) {
    if (!group_name || !app_name) return -1;
    ardb_auth_init();

    ar_mutex_lock(g_auth_mutex);
    for (int i = 0; i < g_group_count; i++) {
        if (strcmp(g_groups[i].name, group_name) == 0) {
            for (int a = 0; a < g_groups[i].app_count; a++) {
                if (strcmp(g_groups[i].apps[a], app_name) == 0) {
                    ar_mutex_unlock(g_auth_mutex);
                    return 0; /* Already in group */
                }
            }
            if (g_groups[i].app_count < ARDB_MAX_GROUP_APPS) {
                snprintf(g_groups[i].apps[g_groups[i].app_count++], 64, "%s", app_name);
            }
            ar_mutex_unlock(g_auth_mutex);
            return 0;
        }
    }

    ar_mutex_unlock(g_auth_mutex);
    return -1;
}

int ardb_auth_add_app(const char *app_name, const char *token_or_secret, const char *group_name, const char *tables_csv) {
    if (!app_name || !token_or_secret) return -1;
    ardb_auth_init();

    /* Add as app user */
    int res = ardb_auth_add_user(app_name, token_or_secret, app_name, "app");
    if (res != 0) return res;

    ar_mutex_lock(g_auth_mutex);
    for (int i = 0; i < g_user_count; i++) {
        if (strcmp(g_users[i].username, app_name) == 0) {
            ArdbUser *u = &g_users[i];
            if (tables_csv) {
                char buf[512];
                snprintf(buf, sizeof(buf), "%s", tables_csv);
                char *tok = strtok(buf, ",");
                while (tok && u->allowed_table_count < 32) {
                    while (*tok == ' ') tok++;
                    if (tok[0] != '\0') {
                        snprintf(u->allowed_tables[u->allowed_table_count++], 64, "%s", tok);
                    }
                    tok = strtok(NULL, ",");
                }
            }
            if (group_name && group_name[0]) {
                if (u->app_group_count < 8) {
                    snprintf(u->app_groups[u->app_group_count++], 64, "%s", group_name);
                }
            }
            break;
        }
    }
    ar_mutex_unlock(g_auth_mutex);

    if (group_name && group_name[0]) {
        ardb_auth_add_app_to_group(group_name, app_name);
    }
    return 0;
}

int ardb_auth_is_table_allowed(const char *app_name, const char *role, const char *table_name) {
    if (!table_name) return 0;
    if (role && strcmp(role, "admin") == 0) return 1; /* Admin has full access */
    if (!app_name || app_name[0] == '\0') return 0;

    /* 1. App naturally owns tables prefixed with its app_name: e.g. "app1_users", "app1_logs" */
    size_t app_len = strlen(app_name);
    if (strncmp(table_name, app_name, app_len) == 0) {
        if (table_name[app_len] == '_' || table_name[app_len] == '.' || table_name[app_len] == '\0') {
            return 1;
        }
    }

    ardb_auth_init();
    ar_mutex_lock(g_auth_mutex);

    /* 2. Check if table is explicitly allowed in user's profile */
    for (int i = 0; i < g_user_count; i++) {
        if (strcmp(g_users[i].username, app_name) == 0) {
            for (int t = 0; t < g_users[i].allowed_table_count; t++) {
                if (strcmp(g_users[i].allowed_tables[t], table_name) == 0 ||
                    strcmp(g_users[i].allowed_tables[t], "*") == 0) {
                    ar_mutex_unlock(g_auth_mutex);
                    return 1;
                }
            }

            /* 3. Check App Groups shared tables */
            for (int g = 0; g < g_users[i].app_group_count; g++) {
                const char *grp_name = g_users[i].app_groups[g];
                for (int gi = 0; gi < g_group_count; gi++) {
                    if (strcmp(g_groups[gi].name, grp_name) == 0) {
                        for (int gt = 0; gt < g_groups[gi].table_count; gt++) {
                            if (strcmp(g_groups[gi].tables[gt], table_name) == 0 ||
                                strcmp(g_groups[gi].tables[gt], "*") == 0) {
                                ar_mutex_unlock(g_auth_mutex);
                                return 1;
                            }
                        }
                    }
                }
            }
            break;
        }
    }

    ar_mutex_unlock(g_auth_mutex);
    return 0;
}

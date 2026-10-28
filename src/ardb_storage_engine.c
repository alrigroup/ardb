/*
 * Copyright (c) 2026 ALRIGROUP and its affiliates.
 * Engineered and maintained by ALRI Development.
 *
 * This code is licensed under the ARGLP - ALRI GROUP LICENSE PERMISSIVE
 * found in the LICENSE file in the root directory of this source tree
 * and at: https://github.com/alrigroup/licenses
 */

#include "ardb_storage_engine.h"
#include "aros_hal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
#include <direct.h>
#define ardb_mkdir(p) _mkdir(p)
#else
#include <unistd.h>
#define ardb_mkdir(p) mkdir(p, 0755)
#endif

#define MAX_OPEN_DBS 16

typedef struct {
    char name[64];
    sqlite3 *db;
} OpenDatabase;

static OpenDatabase g_open_dbs[MAX_OPEN_DBS];
static int g_open_db_count = 0;
static void *g_storage_mutex = NULL;
static int g_storage_initialized = 0;

static void ensure_storage_dirs(const char *app) {
    ardb_mkdir("storage");
    ardb_mkdir("storage/ardb");
    if (app && app[0]) {
        char app_dir[256];
        snprintf(app_dir, sizeof(app_dir), "storage/%s", app);
        ardb_mkdir(app_dir);
    }
}

static sqlite3* get_or_open_db(const char *db_name) {
    const char *target = (db_name && db_name[0]) ? db_name : "ardb_master";
    if (strcmp(target, "postgres") == 0 || strcmp(target, "alrios_db") == 0) {
        target = "ardb_master";
    }

    for (int i = 0; i < g_open_db_count; i++) {
        if (strcmp(g_open_dbs[i].name, target) == 0 && g_open_dbs[i].db != NULL) {
            return g_open_dbs[i].db;
        }
    }

    if (g_open_db_count >= MAX_OPEN_DBS) {
        return g_open_dbs[0].db; /* Fallback to default */
    }

    ensure_storage_dirs(target);

    char path[512];
    if (strcmp(target, "ardb_master") == 0) {
        snprintf(path, sizeof(path), "storage/ardb/data.db");
    } else {
        snprintf(path, sizeof(path), "storage/%s/data.db", target);
    }

    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(path, &db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             NULL);
    if (rc != SQLITE_OK || !db) {
        /* Fallback attempt in storage/ardb/<target>.db */
        snprintf(path, sizeof(path), "storage/ardb/%s.db", target);
        rc = sqlite3_open_v2(path, &db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             NULL);
        if (rc != SQLITE_OK || !db) {
            return NULL;
        }
    }

    /* Configure WAL mode and performance pragmas according to Section 17 */
    sqlite3_exec(db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA busy_timeout=5000;", NULL, NULL, NULL);

    strncpy(g_open_dbs[g_open_db_count].name, target, sizeof(g_open_dbs[g_open_db_count].name) - 1);
    g_open_dbs[g_open_db_count].name[sizeof(g_open_dbs[g_open_db_count].name) - 1] = '\0';
    g_open_dbs[g_open_db_count].db = db;
    g_open_db_count++;

    return db;
}

void ardb_storage_init(void) {
    if (!g_storage_initialized) {
        g_storage_mutex = ar_mutex_create();
        g_storage_initialized = 1;
    }
    ensure_storage_dirs(NULL);

    ar_mutex_lock(g_storage_mutex);
    sqlite3 *db = get_or_open_db("ardb_master");
    if (db) {
        /* Ensure baseline system tables exist */
        const char *schema =
            "CREATE TABLE IF NOT EXISTS ardb_shared_namespaces ("
            "    id TEXT PRIMARY KEY,"
            "    owner_app_id TEXT NOT NULL,"
            "    granted_app_id TEXT NOT NULL,"
            "    table_pattern TEXT NOT NULL,"
            "    permission_mask INTEGER NOT NULL,"
            "    granted_at_nanos INTEGER NOT NULL"
            ");";
        sqlite3_exec(db, schema, NULL, NULL, NULL);
    }
    ar_mutex_unlock(g_storage_mutex);
}

void ardb_storage_sync(void) {
    if (!g_storage_initialized) return;
    ar_mutex_lock(g_storage_mutex);
    for (int i = 0; i < g_open_db_count; i++) {
        if (g_open_dbs[i].db) {
            sqlite3_wal_checkpoint_v2(g_open_dbs[i].db, NULL, SQLITE_CHECKPOINT_PASSIVE, NULL, NULL);
        }
    }
    ar_mutex_unlock(g_storage_mutex);
}

void ardb_storage_cleanup(void) {
    if (!g_storage_initialized) return;
    ar_mutex_lock(g_storage_mutex);
    for (int i = 0; i < g_open_db_count; i++) {
        if (g_open_dbs[i].db) {
            sqlite3_close(g_open_dbs[i].db);
            g_open_dbs[i].db = NULL;
        }
    }
    g_open_db_count = 0;
    ar_mutex_unlock(g_storage_mutex);

    if (g_storage_mutex) {
        ar_mutex_destroy(g_storage_mutex);
        g_storage_mutex = NULL;
    }
    g_storage_initialized = 0;
}

static uint32_t map_sqlite_type_to_pg_oid(const char *decltype, int16_t *out_len) {
    if (!decltype) {
        *out_len = -1;
        return PG_OID_TEXT;
    }

    char upper[64] = {0};
    size_t i = 0;
    while (decltype[i] && i < sizeof(upper) - 1) {
        upper[i] = (char)toupper((unsigned char)decltype[i]);
        i++;
    }
    upper[i] = '\0';

    if (strstr(upper, "INT")) {
        if (strstr(upper, "BIG") || strstr(upper, "INT8")) {
            *out_len = 8;
            return PG_OID_INT8;
        }
        *out_len = 4;
        return PG_OID_INT4;
    }
    if (strstr(upper, "CHAR") || strstr(upper, "TEXT") || strstr(upper, "CLOB")) {
        *out_len = -1;
        return PG_OID_VARCHAR;
    }
    if (strstr(upper, "REAL") || strstr(upper, "FLOA") || strstr(upper, "DOUB") || strstr(upper, "NUM")) {
        *out_len = 8;
        return PG_OID_FLOAT8;
    }
    if (strstr(upper, "BOOL")) {
        *out_len = 1;
        return PG_OID_BOOL;
    }
    if (strstr(upper, "TIME") || strstr(upper, "DATE")) {
        *out_len = 8;
        return PG_OID_TIMESTAMP;
    }
    if (strstr(upper, "BLOB")) {
        *out_len = -1;
        return PG_OID_BYTEA;
    }

    *out_len = -1;
    return PG_OID_TEXT;
}

int ardb_storage_execute_query(const char *db_name, const char *sql_query, ArdbQueryResult *out_result) {
    if (!out_result) return -1;
    memset(out_result, 0, sizeof(*out_result));

    if (!sql_query || sql_query[0] == '\0') {
        snprintf(out_result->command_tag, sizeof(out_result->command_tag), "EMPTY");
        return 0;
    }

    if (!g_storage_initialized) {
        ardb_storage_init();
    }

    ar_mutex_lock(g_storage_mutex);

    sqlite3 *db = get_or_open_db(db_name);
    if (!db) {
        out_result->is_error = 1;
        snprintf(out_result->error_message, sizeof(out_result->error_message), "Failed to open embedded database");
        snprintf(out_result->command_tag, sizeof(out_result->command_tag), "ERROR");
        ar_mutex_unlock(g_storage_mutex);
        return -1;
    }

    /* Extract leading command keyword */
    const char *p = sql_query;
    while (*p && isspace((unsigned char)*p)) p++;
    char verb[32] = {0};
    size_t vi = 0;
    while (*p && isalpha((unsigned char)*p) && vi < sizeof(verb) - 1) {
        verb[vi++] = (char)toupper((unsigned char)*p++);
    }
    verb[vi] = '\0';

    const char *tail = sql_query;
    int total_changes = 0;

    while (tail && *tail) {
        while (*tail && (isspace((unsigned char)*tail) || *tail == ';')) tail++;
        if (!*tail) break;

        sqlite3_stmt *stmt = NULL;
        const char *next_tail = NULL;
        int rc = sqlite3_prepare_v2(db, tail, -1, &stmt, &next_tail);

        if (rc != SQLITE_OK || !stmt) {
            out_result->is_error = 1;
            snprintf(out_result->error_message, sizeof(out_result->error_message), "%s", sqlite3_errmsg(db));
            snprintf(out_result->command_tag, sizeof(out_result->command_tag), "ERROR");
            ar_mutex_unlock(g_storage_mutex);
            return -1;
        }

        int col_count = sqlite3_column_count(stmt);
        if (col_count > 0) {
            /* Query returning rows (SELECT, PRAGMA, etc.) */
            if (col_count > (int)ARDB_MAX_COLUMNS) col_count = (int)ARDB_MAX_COLUMNS;
            out_result->column_count = col_count;

            for (int i = 0; i < col_count; i++) {
                const char *cname = sqlite3_column_name(stmt, i);
                if (cname) {
                    strncpy(out_result->columns[i].name, cname, sizeof(out_result->columns[i].name) - 1);
                    out_result->columns[i].name[sizeof(out_result->columns[i].name) - 1] = '\0';
                } else {
                    snprintf(out_result->columns[i].name, sizeof(out_result->columns[i].name), "col_%d", i + 1);
                }

                const char *decltype = sqlite3_column_decltype(stmt, i);
                int16_t type_len = -1;
                out_result->columns[i].type_oid = map_sqlite_type_to_pg_oid(decltype, &type_len);
                out_result->columns[i].type_len = type_len;
                out_result->columns[i].table_oid = 0;
                out_result->columns[i].col_attr = (int16_t)(i + 1);
            }

            int rows = 0;
            while (sqlite3_step(stmt) == SQLITE_ROW && rows < ARDB_MAX_ROWS) {
                for (int c = 0; c < col_count; c++) {
                    if (sqlite3_column_type(stmt, c) == SQLITE_NULL) {
                        out_result->rows[rows].fields[c] = NULL;
                    } else {
                        const unsigned char *txt = sqlite3_column_text(stmt, c);
                        if (txt) {
                            size_t tlen = strlen((const char*)txt);
                            char *copy = (char*)malloc(tlen + 1);
                            if (copy) {
                                memcpy(copy, txt, tlen);
                                copy[tlen] = '\0';
                            }
                            out_result->rows[rows].fields[c] = copy;
                        } else {
                            out_result->rows[rows].fields[c] = NULL;
                        }
                    }
                }
                rows++;
            }

            out_result->row_count = rows;
            out_result->rows_read = (uint32_t)rows;
            out_result->rows_written = 0;
            snprintf(out_result->command_tag, sizeof(out_result->command_tag), "SELECT %d", rows);
            sqlite3_finalize(stmt);
            break; /* In PGWire, simple query completes with the first rowset */
        } else {
            /* DML / DDL statement without result columns */
            int step_rc = sqlite3_step(stmt);
            if (step_rc != SQLITE_DONE && step_rc != SQLITE_ROW) {
                out_result->is_error = 1;
                snprintf(out_result->error_message, sizeof(out_result->error_message), "%s", sqlite3_errmsg(db));
                snprintf(out_result->command_tag, sizeof(out_result->command_tag), "ERROR");
                sqlite3_finalize(stmt);
                ar_mutex_unlock(g_storage_mutex);
                return -1;
            }

            int chg = sqlite3_changes(db);
            total_changes += chg;
            sqlite3_finalize(stmt);
            tail = next_tail;
        }
    }

    ar_mutex_unlock(g_storage_mutex);

    if (out_result->column_count == 0) {
        out_result->rows_written = (uint32_t)total_changes;
        out_result->rows_read = 0;

        if (strcmp(verb, "INSERT") == 0) {
            snprintf(out_result->command_tag, sizeof(out_result->command_tag), "INSERT 0 %d", total_changes);
        } else if (strcmp(verb, "UPDATE") == 0) {
            snprintf(out_result->command_tag, sizeof(out_result->command_tag), "UPDATE %d", total_changes);
        } else if (strcmp(verb, "DELETE") == 0) {
            snprintf(out_result->command_tag, sizeof(out_result->command_tag), "DELETE %d", total_changes);
        } else if (strcmp(verb, "CREATE") == 0) {
            snprintf(out_result->command_tag, sizeof(out_result->command_tag), "CREATE TABLE");
        } else if (verb[0] != '\0') {
            snprintf(out_result->command_tag, sizeof(out_result->command_tag), "%s", verb);
        } else {
            snprintf(out_result->command_tag, sizeof(out_result->command_tag), "OK");
        }
    }

    return 0;
}

void ardb_storage_free_result(ArdbQueryResult *result) {
    if (!result) return;
    for (int r = 0; r < result->row_count; r++) {
        for (int c = 0; c < result->column_count; c++) {
            if (result->rows[r].fields[c]) {
                free(result->rows[r].fields[c]);
                result->rows[r].fields[c] = NULL;
            }
        }
    }
    memset(result, 0, sizeof(*result));
}

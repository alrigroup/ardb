/*
 * Copyright (c) 2026 ALRIGROUP and its affiliates.
 * Engineered and maintained by ALRI Development.
 *
 * This code is licensed under the ARGLP - ALRI GROUP LICENSE PERMISSIVE
 * found in the LICENSE file in the root directory of this source tree
 * and at: https://github.com/alrigroup/licenses
 */

#include "ardb_backend.h"
#include "ardb_storage_engine.h"
#include "ardb_pgwire.h"
#include "log.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static ArdbBackendConn g_embedded_conn;
static int g_backend_initialized = 0;

int ardb_backend_init(const char *host, int port, const char *user, const char *password, const char *database) {
    (void)host; (void)port;
    memset(&g_embedded_conn, 0, sizeof(g_embedded_conn));
    g_embedded_conn.socket_fd = -1;
    strncpy(g_embedded_conn.host, "embedded://sqlite3-wal2", sizeof(g_embedded_conn.host) - 1);
    g_embedded_conn.port = 0; /* Zero dependência de daemons externos */

    if (user && user[0]) {
        strncpy(g_embedded_conn.user, user, sizeof(g_embedded_conn.user) - 1);
    } else {
        strncpy(g_embedded_conn.user, "postgres", sizeof(g_embedded_conn.user) - 1);
    }

    if (password && password[0]) {
        strncpy(g_embedded_conn.password, password, sizeof(g_embedded_conn.password) - 1);
    }

    if (database && database[0]) {
        strncpy(g_embedded_conn.database, database, sizeof(g_embedded_conn.database) - 1);
    } else {
        strncpy(g_embedded_conn.database, "ardb_master", sizeof(g_embedded_conn.database) - 1);
    }

    g_embedded_conn.is_connected = 1;
    g_backend_initialized = 1;

    ardb_storage_init();
    return 0;
}

void ardb_backend_cleanup(void) {
    if (!g_backend_initialized) return;
    g_embedded_conn.is_connected = 0;
    ardb_storage_cleanup();
    g_backend_initialized = 0;
}

ArdbBackendConn* ardb_backend_acquire(void) {
    if (!g_backend_initialized) {
        ardb_backend_init(NULL, 0, NULL, NULL, NULL);
    }
    return &g_embedded_conn;
}

void ardb_backend_release(ArdbBackendConn *conn) {
    (void)conn;
}

int ardb_backend_relay_query(ArdbBackendConn *conn, const char *sql_query, int client_fd) {
    if (!conn || !sql_query) return -1;

    ArdbQueryResult qres;
    int rc = ardb_storage_execute_query(conn->database, sql_query, &qres);

    if (rc != 0 || qres.is_error) {
        const char *errmsg = qres.error_message[0] ? qres.error_message : "SQL execution error in autonomous storage engine";
        ardb_pgwire_send_error(client_fd, "ERROR", "42601", errmsg);
        ardb_pgwire_send_ready_for_query(client_fd, 'I');
        ardb_storage_free_result(&qres);
        return 0;
    }

    ardb_pgwire_send_query_result(client_fd, &qres);
    ardb_pgwire_send_ready_for_query(client_fd, 'I');
    ardb_storage_free_result(&qres);
    return 0;
}

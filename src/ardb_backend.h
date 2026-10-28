/*
 * Copyright (c) 2026 ALRIGROUP and its affiliates.
 * Engineered and maintained by ALRI Development.
 *
 * This code is licensed under the ARGLP - ALRI GROUP LICENSE PERMISSIVE
 * found in the LICENSE file in the root directory of this source tree
 * and at: https://github.com/alrigroup/licenses
 */

#ifndef ARDB_BACKEND_H
#define ARDB_BACKEND_H

#include "aros_hal.h"
#include <stdint.h>
#include <stddef.h>

#define ARDB_BACKEND_POOL_SIZE 16

typedef struct {
    int socket_fd;
    char host[64];
    int port;
    char user[64];
    char password[128];
    char database[64];
    int is_connected;
    int in_use;
    uint64_t last_used_ms;
} ArdbBackendConn;

/* Inicialização do motor embutido autônomo (Zero dependência externa na porta 5433) */
int ardb_backend_init(const char *host, int port, const char *user, const char *password, const char *database);
void ardb_backend_cleanup(void);

/* Adquire conexão com o motor relacional embutido */
ArdbBackendConn* ardb_backend_acquire(void);
void ardb_backend_release(ArdbBackendConn *conn);

/* Executa a query no motor relacional embutido e transmite o resultado via PGWire */
int ardb_backend_relay_query(ArdbBackendConn *conn, const char *sql_query, int client_fd);

#endif /* ARDB_BACKEND_H */

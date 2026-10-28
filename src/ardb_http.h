/*
 * Copyright (c) 2026 ALRIGROUP and its affiliates.
 * Engineered and maintained by ALRI Development.
 *
 * This code is licensed under the ARGLP - ALRI GROUP LICENSE PERMISSIVE
 * found in the LICENSE file in the root directory of this source tree
 * and at: https://github.com/alrigroup/licenses
 */

#ifndef ARDB_HTTP_H
#define ARDB_HTTP_H

#include <stdint.h>
#include <stddef.h>

int ardb_http_server_start(const char *bind_addr, int port);
void ardb_http_server_stop(void);
int ardb_http_is_running(void);

#endif /* ARDB_HTTP_H */

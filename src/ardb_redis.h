/*
 * Copyright (c) 2026 ALRIGROUP and its affiliates.
 * Engineered and maintained by ALRI Development.
 *
 * This code is licensed under the ARGLP - ALRI GROUP LICENSE PERMISSIVE
 * found in the LICENSE file in the root directory of this source tree
 * and at: https://github.com/alrigroup/licenses
 */

#ifndef ARDB_REDIS_H
#define ARDB_REDIS_H

#include <stdint.h>
#include <stddef.h>

#define ARDB_REDIS_DEFAULT_PORT 6379
#define ARDB_REDIS_HASH_BUCKETS 131072

int ardb_redis_server_start(const char *bind_addr, int port);
void ardb_redis_server_stop(void);
int ardb_redis_is_running(void);

#endif /* ARDB_REDIS_H */

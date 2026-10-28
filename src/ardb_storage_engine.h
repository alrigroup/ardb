/*
 * Copyright (c) 2026 ALRIGROUP and its affiliates.
 * Engineered and maintained by ALRI Development.
 *
 * This code is licensed under the ARGLP - ALRI GROUP LICENSE PERMISSIVE
 * found in the LICENSE file in the root directory of this source tree
 * and at: https://github.com/alrigroup/licenses
 */

#ifndef ARDB_STORAGE_ENGINE_H
#define ARDB_STORAGE_ENGINE_H

#include "ardb_provenance.h"
#include <stdint.h>
#include <stddef.h>

#define ARDB_MAX_ROWS 512

/* PostgreSQL OID data types */
#define PG_OID_BOOL 16
#define PG_OID_BYTEA 17
#define PG_OID_INT8 20
#define PG_OID_INT4 23
#define PG_OID_TEXT 25
#define PG_OID_FLOAT8 701
#define PG_OID_VARCHAR 1043
#define PG_OID_TIMESTAMP 1114

typedef struct {
    char name[64];
    uint32_t type_oid;
    int16_t type_len;
    uint32_t table_oid;
    int16_t col_attr;
} ArdbColumnDesc;

typedef struct {
    char *fields[ARDB_MAX_COLUMNS];
} ArdbRow;

typedef struct {
    int column_count;
    ArdbColumnDesc columns[ARDB_MAX_COLUMNS];
    int row_count;
    ArdbRow rows[ARDB_MAX_ROWS];
    char command_tag[64];
    char error_message[256];
    int is_error;
    uint32_t rows_read;
    uint32_t rows_written;
} ArdbQueryResult;

void ardb_storage_init(void);
void ardb_storage_sync(void);
void ardb_storage_cleanup(void);

/* Execute SQL query against target embedded database with WAL2 replication */
int ardb_storage_execute_query(const char *db_name, const char *sql_query, ArdbQueryResult *out_result);
void ardb_storage_free_result(ArdbQueryResult *result);

#endif /* ARDB_STORAGE_ENGINE_H */

/*
 * Copyright (c) 2026 ALRIGROUP and its affiliates.
 * Engineered and maintained by ALRI Development.
 *
 * This code is licensed under the ARGLP - ALRI GROUP LICENSE PERMISSIVE
 * found in the LICENSE file in the root directory of this source tree
 * and at: https://github.com/alrigroup/licenses
 */

#ifndef ARDB_PROVENANCE_H
#define ARDB_PROVENANCE_H

#include <stdint.h>
#include <stddef.h>

#define ARDB_MAGIC_HEADER             0x4152444232565354ULL /* "ARDB2VST" em ASCII */
#define ARDB_PAGE_SIZE                4096U
#define ARDB_MAX_CONNECTIONS          1024U
#define ARDB_MAX_COLUMNS              128U
#define ARDB_MAX_ROW_FIELD_LEN        4096U
#define ARDB_MAX_TENANT_LEN           64U
#define ARDB_MAX_APP_LEN              64U
#define ARDB_MAX_ACTOR_LEN            64U
#define ARDB_HASH_CHAIN_LEN           64U

typedef enum {
    ARDB_OK                              =  0,
    ARDB_ERR_INVALID_ARGUMENT            = -8001,
    ARDB_ERR_CONNECTION_REFUSED          = -8002,
    ARDB_ERR_UNATTESTED_QUERY            = -8003,
    ARDB_ERR_FIREWALL_DDL_BLOCKED        = -8004,
    ARDB_ERR_TENANT_VIOLATION            = -8005,
    ARDB_ERR_APP_NAMESPACE_VIOLATION     = -8006,
    ARDB_ERR_PGWIRE_MALFORMED_PACKET     = -8007,
    ARDB_ERR_RESP_MALFORMED_PACKET       = -8008,
    ARDB_ERR_STORAGE_CORRUPTION          = -8009,
    ARDB_ERR_AUDIT_INTEGRITY_COMPROMISED = -8010,
    ARDB_ERR_BACKUP_ENCRYPTION_FAILED    = -8011,
    ARDB_ERR_CONCURRENCY_TIMEOUT         = -8012
} ardb_error_t;

typedef enum {
    ARDB_OP_SELECT        = 1,
    ARDB_OP_INSERT        = 2,
    ARDB_OP_UPDATE        = 3,
    ARDB_OP_DELETE        = 4,
    ARDB_OP_REDIS_SET     = 5,
    ARDB_OP_REDIS_GET     = 6,
    ARDB_OP_REDIS_DEL     = 7,
    ARDB_OP_REDIS_EXPIRE  = 8,
    ARDB_OP_REDIS_TTL     = 9,
    ARDB_OP_CREATE_TABLE  = 10,
    ARDB_OP_SECURITY_ALERT= 11
} ardb_op_type_t;

#pragma pack(push, 1)
typedef struct {
    char     app_id[ARDB_MAX_APP_LEN];           /* Identidade do pacote (ex: "argonge") */
    char     app_token[128];                     /* Token atestado emitido pelo arcore */
    char     actor_id[ARDB_MAX_ACTOR_LEN];       /* ID do usuário ou "SYSTEM:<componente>" */
    char     tenant_id[ARDB_MAX_TENANT_LEN];     /* Tenant organizacional */
    char     client_ip[48];                      /* IP canônico do cliente */
    uint64_t timestamp_nanos;                    /* Timestamp monotônico atestado */
    uint8_t  is_system_actor;                    /* 1=Ação interna de cronjob, 0=Usuário humano */
    uint8_t  reserved[7];                        /* Padding de alinhamento 64-bit */
} ardb_provenance_context_t;

typedef struct {
    uint64_t sequence_id;                        /* Sequencial estrito monotônico */
    uint64_t timestamp_nanos;                    /* Timestamp da transação */
    char     app_id[ARDB_MAX_APP_LEN];           /* Origem da aplicação */
    char     actor_id[ARDB_MAX_ACTOR_LEN];       /* Ator responsável */
    char     tenant_id[ARDB_MAX_TENANT_LEN];     /* Contexto de isolamento */
    uint16_t operation_type;                     /* 1=SELECT, 2=INSERT, etc. */
    uint32_t rows_read;                          /* Quantidade exata de linhas inspecionadas/lidas */
    uint32_t rows_written;                       /* Quantidade exata de linhas mutadas */
    uint32_t execution_time_us;                  /* Tempo total de execução em microssegundos */
    uint8_t  previous_block_hash[32];            /* SHA-256 do bloco N-1 */
    uint8_t  current_block_hash[32];             /* SHA-256 deste bloco completo */
    uint32_t query_len;                          /* Comprimento do SQL bruto */
} ardb_audit_block_record_t;
#pragma pack(pop)

/* Helper functions */
uint64_t ardb_time_now_nanos(void);
int ardb_provenance_is_attested(const ardb_provenance_context_t *ctx);
int ardb_provenance_parse_comment(const char *sql, ardb_provenance_context_t *out_ctx);

#endif /* ARDB_PROVENANCE_H */

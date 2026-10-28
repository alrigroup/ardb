/*
 * Copyright (c) 2026 ALRIGROUP and its affiliates.
 * Engineered and maintained by ALRI Development.
 *
 * This code is licensed under the ARGLP - ALRI GROUP LICENSE PERMISSIVE
 * found in the LICENSE file in the root directory of this source tree
 * and at: https://github.com/alrigroup/licenses
 */

#ifndef ARDB_FIREWALL_H
#define ARDB_FIREWALL_H

#include "ardb_provenance.h"
#include <stddef.h>

typedef enum {
    ARDB_FW_OK = 0,
    ARDB_FW_BLOCK_DESTRUCTIVE = 1,  /* DROP, ALTER SYSTEM, TRUNCATE não autorizados (42501) */
    ARDB_FW_BLOCK_RLS_BYPASS = 2,   /* Tentativa de burlar tenant_id com comentários ou injection */
    ARDB_FW_BLOCK_EXFILTRATION = 3, /* Excedeu o limite de volume de dados do perfil */
    ARDB_FW_BLOCK_UNATTESTED = 4    /* Query sem proveniência atestada */
} ArdbFwAction;

/* Inspeciona e sanitiza a query SQL antes da execução */
ArdbFwAction ardb_firewall_inspect(const char *raw_sql, const char *tenant_id, const char *role,
                                   char *out_rewritten_sql, size_t out_size,
                                   char *out_reason, size_t out_reason_size);

int ardb_firewall_inspect_provenance(const char *raw_sql, const ardb_provenance_context_t *ctx);

#endif /* ARDB_FIREWALL_H */

/*
 * Copyright (c) 2026 ALRIGROUP and its affiliates.
 * Engineered and maintained by ALRI Development.
 *
 * This code is licensed under the ARGLP - ALRI GROUP LICENSE PERMISSIVE
 * found in the LICENSE file in the root directory of this source tree
 * and at: https://github.com/alrigroup/licenses
 */

#ifndef ARDB_AUDIT_H
#define ARDB_AUDIT_H

#include "ardb_provenance.h"
#include <stdint.h>
#include <stddef.h>

void ardb_audit_init(const char *log_path);
void ardb_audit_cleanup(void);

/* Grava log forense imutável com rastreamento completo de leitura e mutação */
void ardb_audit_log_record(const ardb_provenance_context_t *ctx,
                           uint16_t operation_type,
                           uint32_t rows_read,
                           uint32_t rows_written,
                           uint32_t duration_us,
                           const char *raw_query);

/* Compatibilidade com assinaturas legadas */
void ardb_audit_log_query(const char *user, const char *tenant_id, const char *client_ip,
                          const char *sql_query, int status_code, uint64_t duration_us);

void ardb_audit_log_security_alert(const ardb_provenance_context_t *ctx,
                                   const char *alert_type,
                                   const char *details);

/* Verifica a integridade da cadeia de hashes do arquivo de log */
int ardb_audit_verify_integrity(const char *log_path, char *out_error, size_t out_error_size);

#endif /* ARDB_AUDIT_H */

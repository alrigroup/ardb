/*
 * Copyright (c) 2026 ALRIGROUP and its affiliates.
 * Engineered and maintained by ALRI Development.
 *
 * This code is licensed under the ARGLP - ALRI GROUP LICENSE PERMISSIVE
 * found in the LICENSE file in the root directory of this source tree
 * and at: https://github.com/alrigroup/licenses
 */

#include "ardb_http.h"
#include "ardb_config.h"
#include "ardb_auth.h"
#include "ardb_firewall.h"
#include "ardb_audit.h"
#include "ardb_backend.h"
#include "ardb_storage_engine.h"
#include "aros_hal.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

static int g_http_listen_fd = -1;
static volatile int g_http_running = 0;
static void *g_http_thread = NULL;

static void configure_http_timeouts(int fd) {
#ifndef _WIN32
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#else
    DWORD timeout = 10000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#endif
}

static void send_http_response(int client_fd, int status_code, const char *status_text,
                               const char *content_type, const char *body) {
    size_t body_len = body ? strlen(body) : 0;
    char header[512];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Headers: Content-Type, Authorization, X-ARDB-Token\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Connection: close\r\n"
        "\r\n",
        status_code, status_text, content_type, body_len);

    if (hlen > 0) {
        ar_socket_send(client_fd, header, hlen);
    }
    if (body_len > 0) {
        ar_socket_send(client_fd, body, (int)body_len);
    }
}

static char* extract_json_string(const char *json, const char *key) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    char *pos = strstr((char*)json, pattern);
    if (!pos) return NULL;

    char *colon = strchr(pos, ':');
    if (!colon) return NULL;

    char *val_start = colon + 1;
    while (*val_start && isspace((unsigned char)*val_start)) val_start++;

    if (*val_start == '\"') {
        val_start++;
        char *val_end = strchr(val_start, '\"');
        if (!val_end) return NULL;
        size_t len = val_end - val_start;
        char *res = (char*)malloc(len + 1);
        if (!res) return NULL;
        memcpy(res, val_start, len);
        res[len] = '\0';
        return res;
    }
    return NULL;
}

static void* http_client_worker(void *arg) {
    int client_fd = (int)(intptr_t)arg;
    configure_http_timeouts(client_fd);

    char buf[8192];
    int r = ar_socket_recv(client_fd, buf, sizeof(buf) - 1);
    if (r <= 0) {
        ar_socket_close(client_fd);
        return NULL;
    }
    buf[r] = '\0';

    char method[16] = {0};
    char path[256] = {0};
    sscanf(buf, "%15s %255s", method, path);

    /* OPTIONS (CORS preflight) */
    if (strcmp(method, "OPTIONS") == 0) {
        send_http_response(client_fd, 204, "No Content", "text/plain", "");
        ar_socket_close(client_fd);
        return NULL;
    }

    ArdbConfig *cfg = ardb_config_get();

    /* 1. GET /api/v1/db/status ou /status */
    if (strcmp(method, "GET") == 0 &&
        (strstr(path, "/status") || strstr(path, "/health"))) {
        char resp_json[512];
        snprintf(resp_json, sizeof(resp_json),
            "{\"status\":\"online\",\"engine\":\"ALRI DB Sovereign Guardian\","
            "\"pgwire_port\":%d,\"redis_port\":%d,\"http_port\":%d,\"sql_firewall\":\"%s\",\"audit\":\"active\"}\n",
            cfg->server_port, cfg->redis_port, cfg->http_port, cfg->sql_firewall);
        send_http_response(client_fd, 200, "OK", "application/json", resp_json);
        ar_socket_close(client_fd);
        return NULL;
    }

    /* 2. POST /api/v1/db/query ou /query */
    if (strcmp(method, "POST") == 0 &&
        (strstr(path, "/query") || strstr(path, "/execute"))) {

        char token[128] = {0};
        char *tok_hdr = strstr(buf, "X-ARDB-Token:");
        if (!tok_hdr) tok_hdr = strstr(buf, "x-ardb-token:");
        if (tok_hdr) {
            sscanf(tok_hdr + 13, "%127s", token);
        } else {
            char *auth_hdr = strstr(buf, "Authorization: Bearer ");
            if (!auth_hdr) auth_hdr = strstr(buf, "authorization: bearer ");
            if (auth_hdr) {
                sscanf(auth_hdr + 22, "%127s", token);
            }
        }

        char user[64] = "anonymous";
        char tenant[64] = "default";
        char role[32] = "operator";

        if (cfg->http_auth_required) {
            if (token[0] == '\0') {
                send_http_response(client_fd, 401, "Unauthorized", "application/json",
                    "{\"error\":\"Missing X-ARDB-Token or Authorization Bearer header\"}\n");
                ar_socket_close(client_fd);
                return NULL;
            }

            if (ardb_auth_verify_token(token, user, tenant, role) != 0) {
                send_http_response(client_fd, 401, "Unauthorized", "application/json",
                    "{\"error\":\"Invalid or expired session token\"}\n");
                ar_socket_close(client_fd);
                return NULL;
            }
        }

        char *body = strstr(buf, "\r\n\r\n");
        if (!body) {
            send_http_response(client_fd, 400, "Bad Request", "application/json", "{\"error\":\"Missing body\"}\n");
            ar_socket_close(client_fd);
            return NULL;
        }
        body += 4;

        char *sql = extract_json_string(body, "sql");
        if (!sql || sql[0] == '\0') {
            if (sql) free(sql);
            send_http_response(client_fd, 400, "Bad Request", "application/json", "{\"error\":\"Missing 'sql' in JSON body\"}\n");
            ar_socket_close(client_fd);
            return NULL;
        }

        ardb_provenance_context_t pctx;
        memset(&pctx, 0, sizeof(pctx));
        snprintf(pctx.app_id, sizeof(pctx.app_id), "%s", user);
        snprintf(pctx.actor_id, sizeof(pctx.actor_id), "%s", user);
        snprintf(pctx.tenant_id, sizeof(pctx.tenant_id), "%s", tenant);
        snprintf(pctx.client_ip, sizeof(pctx.client_ip), "%s", "127.0.0.1");
        pctx.timestamp_nanos = ardb_time_now_nanos();

        /* Inspeciona proveniência na query se houver comentário */
        ardb_provenance_parse_comment(sql, &pctx);

        uint64_t start_us = (uint64_t)ar_time_ms() * 1000;
        char rewritten[2048];
        char reason[512] = {0};

        ArdbFwAction act = ardb_firewall_inspect(sql, tenant, role,
                                                 rewritten, sizeof(rewritten),
                                                 reason, sizeof(reason));

        if (act != ARDB_FW_OK) {
            ardb_audit_log_record(&pctx, (uint16_t)ARDB_OP_SECURITY_ALERT, 0, 0,
                                  (uint32_t)((uint64_t)ar_time_ms() * 1000 - start_us), sql);
            char err_json[512];
            snprintf(err_json, sizeof(err_json), "{\"error\":\"SQL Firewall Blocked: %s\"}\n", reason);
            send_http_response(client_fd, 403, "Forbidden", "application/json", err_json);
            free(sql);
            ar_socket_close(client_fd);
            return NULL;
        }

        /* Execução da consulta via motor autônomo */
        ArdbQueryResult qres;
        ardb_storage_execute_query("ardb_master", rewritten, &qres);

        char resp_body[16384];
        size_t off = 0;
        int n = snprintf(resp_body + off, sizeof(resp_body) - off, "{\"status\":\"success\",\"rows\":[");
        if (n > 0) off += (size_t)n;

        for (int r_idx = 0; r_idx < qres.row_count && off < sizeof(resp_body) - 256; r_idx++) {
            n = snprintf(resp_body + off, sizeof(resp_body) - off, "%s{", (r_idx > 0) ? "," : "");
            if (n > 0) off += (size_t)n;

            for (int c_idx = 0; c_idx < qres.column_count && off < sizeof(resp_body) - 256; c_idx++) {
                n = snprintf(resp_body + off, sizeof(resp_body) - off, "%s\"%s\":\"%s\"",
                             (c_idx > 0) ? "," : "",
                             qres.columns[c_idx].name,
                             qres.rows[r_idx].fields[c_idx] ? qres.rows[r_idx].fields[c_idx] : "");
                if (n > 0) off += (size_t)n;
            }

            n = snprintf(resp_body + off, sizeof(resp_body) - off, "}");
            if (n > 0) off += (size_t)n;
        }

        n = snprintf(resp_body + off, sizeof(resp_body) - off, "],\"row_count\":%d}\n", qres.row_count);
        if (n > 0) off += (size_t)n;

        uint16_t op = (qres.column_count > 0) ? (uint16_t)ARDB_OP_SELECT : (uint16_t)ARDB_OP_UPDATE;
        ardb_audit_log_record(&pctx, op, qres.rows_read, qres.rows_written,
                              (uint32_t)((uint64_t)ar_time_ms() * 1000 - start_us), rewritten);

        ardb_storage_free_result(&qres);
        send_http_response(client_fd, 200, "OK", "application/json", resp_body);
        free(sql);
        ar_socket_close(client_fd);
        return NULL;
    }

    send_http_response(client_fd, 404, "Not Found", "application/json", "{\"error\":\"Route not found\"}\n");
    ar_socket_close(client_fd);
    return NULL;
}

static void* http_listen_worker(void *arg) {
    (void)arg;
    while (g_http_running) {
        int client_fd = ar_socket_accept(g_http_listen_fd);
        if (client_fd < 0) {
            if (g_http_running) ar_sleep_ms(50);
            continue;
        }
        ar_thread_create(http_client_worker, (void*)(intptr_t)client_fd);
    }
    return NULL;
}

int ardb_http_server_start(const char *bind_addr, int port) {
    if (g_http_running) return 0;
#ifdef _WIN32
    g_http_listen_fd = ar_socket_create(1);
#else
    g_http_listen_fd = ar_socket_create(SOCK_STREAM);
#endif
    if (g_http_listen_fd < 0) return -1;

    ar_socket_reuseaddr(g_http_listen_fd, 1);
    if (ar_socket_bind(g_http_listen_fd, bind_addr, (uint16_t)port) != 0) {
        ar_socket_close(g_http_listen_fd);
        g_http_listen_fd = -1;
        return -1;
    }

    if (ar_socket_listen(g_http_listen_fd, 64) != 0) {
        ar_socket_close(g_http_listen_fd);
        g_http_listen_fd = -1;
        return -1;
    }

    g_http_running = 1;
    g_http_thread = ar_thread_create(http_listen_worker, NULL);
    alri_print_force(CYN "[ARDB-HTTP]" RST " Embedded REST micro-server listening on http://%s:%d\n", bind_addr, port);
    return 0;
}

void ardb_http_server_stop(void) {
    if (!g_http_running) return;
    g_http_running = 0;
    if (g_http_listen_fd >= 0) {
        ar_socket_close(g_http_listen_fd);
        g_http_listen_fd = -1;
    }
}

int ardb_http_is_running(void) {
    return g_http_running;
}

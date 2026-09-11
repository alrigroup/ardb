# ARDB — Technical Reference Manual

*Sovereign Data Guardian & SQL Engine Proxy*

*Version: 0.2.02 | Engineered by ALRI Development | Governed by ALRI GROUP © 2026 | License: ARGLP*

---

## Table of Contents

- [1. Overview & Sovereign Architecture](#1-overview--sovereign-architecture)
- [2. Architecture & SQL Pipeline](#2-architecture--sql-pipeline)
- [3. Configuration Reference (ardb.cfg)](#3-configuration-reference-ardbcfg)
- [4. Module Reference](#4-module-reference)
  - [4.1 Entry Point (ardb_entry)](#41-entry-point-ardb_entry)
  - [4.2 Authentication (ardb_auth)](#42-authentication-ardb_auth)
  - [4.3 SQL Firewall & AST (ardb_firewall)](#43-sql-firewall--ast-ardb_firewall)
  - [4.4 PGWire Protocol (ardb_pgwire)](#44-pgwire-protocol-ardb_pgwire)
  - [4.5 Backend Connector (ardb_backend)](#45-backend-connector-ardb_backend)
  - [4.6 Storage Engine (ardb_storage_engine)](#46-storage-engine-ardb_storage_engine)
  - [4.7 Audit Log (ardb_audit)](#47-audit-log-ardb_audit)
  - [4.8 HTTP Management API (ardb_http)](#48-http-management-api-ardb_http)
  - [4.9 Configuration Parser (ardb_config)](#49-configuration-parser-ardb_config)
- [5. SQL Firewall Deep Dive](#5-sql-firewall-deep-dive)
- [6. PGWire Protocol v3.0 Implementation](#6-pgwire-protocol-v30-implementation)
- [7. Blockchain-Style Forensic Audit Log](#7-blockchain-style-forensic-audit-log)
- [8. App Table Isolation & Multi-Tenancy](#8-app-table-isolation--multi-tenancy)
- [9. CLI Governance (`alrios ardb`)](#9-cli-governance-alrios-ardb)
- [10. Build & Packaging](#10-build--packaging)

---

## 1. Overview & Sovereign Architecture

**ARDB (ALRI Data Guardian)** is the sovereign database security proxy and execution engine for the ALRIOS platform. It provides a zero-trust execution barrier between all database clients (microservices, web applications, ORMs, DBeaver, psql) and the isolated physical PostgreSQL database instance.

### Core Architectural Mandate

> **The physical PostgreSQL database never listens on external interfaces.**  
> It binds strictly to loopback (default: `127.0.0.1:5433`). Every inbound SQL interaction must traverse the ARDB proxy pipeline on port `5432` (PGWire) or port `5435` (HTTP REST).

### Key Features

| Feature | Specification |
|---|---|
| Native Protocol | PostgreSQL Wire Protocol v3.0 (`PG_MSG_STARTUP_V3`) |
| Isolation | Physical PostgreSQL on `127.0.0.1:5433` (unreachable from outside) |
| SQL Firewall | AST inspection, destructive DDL blocking, tenant injection |
| Multi-Tenancy | Automatic `SET LOCAL alri.tenant_id = '...'` injection |
| App Table ACL | Table namespace ownership + Shared App Groups |
| Audit Trail | Immutable SHA-256 hash-chain (blockchain-style non-repudiation) |
| Session Security | Ephemeral 4-hour tokens with 2FA TOTP support |
| REST API | Embedded HTTP server for JSON query execution |

---

## 2. Architecture & SQL Pipeline

### Data Flow Diagram

```
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                         ARDB Execution Pipeline                             │
 │                                                                             │
 │  Clients (ORMs / DBeaver / Apps)        HTTP Clients (ARWS / Webhooks)     │
 │             │                                         │                     │
 │             ▼                                         ▼                     │
 │      Port 5432 (PGWire)                        Port 5435 (HTTP API)         │
 │             │                                         │                     │
 │             └───────────────────┬─────────────────────┘                     │
 │                                 │                                           │
 │                       ┌─────────▼──────────┐                                │
 │                       │   Authentication   │                                │
 │                       │  (Tokens, Roles,   │                                │
 │                       │   Tenant & 2FA)    │                                │
 │                       └─────────┬──────────┘                                │
 │                                 │ Authenticated Session                     │
 │                       ┌─────────▼──────────┐                                │
 │                       │    SQL Firewall    │                                │
 │                       │   (AST Inspection, │                                │
 │                       │   Table ACL Check, │                                │
 │                       │   DDL Blocking)    │                                │
 │                       └─────────┬──────────┘                                │
 │                                 │ Clean / Rewritten SQL                     │
 │                       ┌─────────▼──────────┐                                │
 │                       │   Backend Relay    │                                │
 │                       │  (Connection Pool  │                                │
 │                       │   to PG: 5433)     │                                │
 │                       └─────────┬──────────┘                                │
 │                                 │ Query Execution                           │
 │                       ┌─────────▼──────────┐                                │
 │                       │   Storage Engine   │                                │
 │                       │  (Row Parsing, OID │                                │
 │                       │   Type Mapping)    │                                │
 │                       └─────────┬──────────┘                                │
 │                                 │ Results + Telemetry                       │
 │                       ┌─────────▼──────────┐                                │
 │                       │  Forensic Audit    │                                │
 │                       │  (SHA-256 Chained  │                                │
 │                       │   Immutable Log)   │                                │
 │                       └─────────┬──────────┘                                │
 │                                 │                                           │
 │                                 ▼                                           │
 │                        Client Response                                      │
 └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Configuration Reference (ardb.cfg)

The configuration file is located at `arcore/storage/ardb/ardb.cfg`.

### Configuration Table

| Section | Key | Type | Default | Description |
|---|---|---|---|---|
| `[server]` | `server_port` | int | `5432` | Primary PGWire listen port |
| `[server]` | `server_bind` | string | `"0.0.0.0"` | Listen address for incoming connections |
| `[server]` | `max_connections` | int | `128` | Maximum concurrent client connections |
| `[backend]` | `backend_host` | string | `"127.0.0.1"` | Isolated PostgreSQL host address |
| `[backend]` | `backend_port` | int | `5433` | Isolated PostgreSQL port |
| `[backend]` | `backend_user` | string | `"postgres"` | Superuser for PostgreSQL backend connection |
| `[backend]` | `backend_password` | string | `""` | Password for PostgreSQL backend |
| `[backend]` | `backend_database` | string | `"postgres"` | Default database name |
| `[http_api]` | `http_enabled` | int | `1` | Enable/disable embedded HTTP REST API (`1` or `0`) |
| `[http_api]` | `http_bind` | string | `"127.0.0.1"` | Bind address for HTTP API |
| `[http_api]` | `http_port` | int | `5435` | HTTP API listen port |
| `[http_api]` | `http_route_prefix` | string | `"/api/v1/db"` | URL prefix for REST endpoints |
| `[http_api]` | `http_auth_required` | int | `1` | Require authentication on HTTP endpoints |
| `[http_api]` | `http_max_payload_bytes` | int | `1048576` | Maximum request body size (1 MiB) |
| `[firewall]` | `firewall_enabled` | int | `1` | Enable SQL AST inspection firewall |
| `[firewall]` | `block_destructive` | int | `1` | Block `DROP`, `TRUNCATE`, `ALTER SYSTEM` |
| `[firewall]` | `enforce_rls` | int | `1` | Force `SET LOCAL alri.tenant_id` on transactions |
| `[audit]` | `audit_enabled` | int | `1` | Enable cryptographic audit logging |
| `[audit]` | `audit_log_path` | string | `"storage/ardb/audit.log"` | Path to the chained audit log file |

---

## 4. Module Reference

### 4.1 Entry Point (ardb_entry)

**Files**: `src/ardb_entry.c`

**Purpose**: Daemon entry point. Loads configuration, initializes HAL resources, boots the backend connection pool, starts the PGWire listener thread, starts the HTTP server thread, and handles IPC control commands on port 9500.

#### Key Functions

| Signature | Description |
|---|---|
| `int main(int argc, char **argv)` | Process bootstrap, signal handlers, sub-system initialization |
| `void* pgwire_server_thread(void *arg)` | Listener loop accepting client connections and spawning worker threads |
| `void* client_worker_thread(void *arg)` | Handles full connection lifecycle for a single PGWire client |
| `int handle_ipc_command(const char *cmd, char *out_resp, size_t max_resp)` | Dispatches CLI governance commands from `alrios ardb` |

---

### 4.2 Authentication (ardb_auth)

**Files**: `src/ardb_auth.h`, `src/ardb_auth.c`

**Purpose**: Manages database users, credentials, role-based permissions (admin, operator, app), multi-tenant mappings, 2FA TOTP verification, and ephemeral 4-hour session tokens.

#### Structs

```c
typedef struct {
    char name[64];                                 // Group name (e.g., "shared_store")
    char tables[ARDB_MAX_GROUP_TABLES][64];         // Tables shared within group
    int  table_count;
    char apps[ARDB_MAX_GROUP_APPS][64];             // Applications assigned to group
    int  app_count;
} ArdbAppGroup;

typedef struct {
    char username[64];
    char password_hash[128];                        // PBKDF2-HMAC-SHA512 or argon2 hash
    char tenant_id[64];                             // Multi-tenant bound identifier
    char role[32];                                  // "admin", "operator", "app"
    char allowed_tables[32][64];                    // Private table whitelist
    int  allowed_table_count;
    char app_groups[8][64];                         // Assigned shared groups
    int  app_group_count;
    int  is_active;
    int  requires_2fa;
    char totp_secret[64];
} ArdbUser;

typedef struct {
    char token[128];                                // CSPRNG 256-bit token
    char username[64];
    char tenant_id[64];
    char role[32];
    uint64_t created_at_ms;
    uint64_t expires_at_ms;                         // default: 4 hours (14400 sec)
    int is_valid;
} ArdbSessionToken;
```

#### Functions

| Signature | Description |
|---|---|
| `int ardb_auth_init(void)` | Initialize user table and session token pool |
| `int ardb_auth_validate_user(const char *user, const char *pass, ArdbUser *out_user)` | Validate credentials using constant-time comparison |
| `int ardb_auth_validate_totp(const char *username, const char *code)` | Validate TOTP 2FA code against user secret |
| `int ardb_auth_create_token(const char *user, char *out_token, size_t token_size)` | Issue ephemeral 4-hour session token |
| `int ardb_auth_validate_token(const char *token, ArdbSessionToken *out_session)` | Validate token liveness and tenant context |
| `int ardb_auth_revoke_token(const char *token)` | Immediately invalidate an active session token |
| `int ardb_auth_add_user(const ArdbUser *user)` | Register new user or application credential |
| `int ardb_auth_can_access_table(const ArdbUser *user, const char *table_name)` | Verify if user/app can access table via private or group scope |

#### Constants

| Constant | Value | Description |
|---|---|---|
| `ARDB_MAX_USERS` | `64` | Maximum configured users |
| `ARDB_MAX_ACTIVE_TOKENS` | `128` | Maximum active concurrent session tokens |
| `ARDB_MAX_GROUPS` | `32` | Maximum shared App Groups |
| `ARDB_MAX_GROUP_TABLES` | `64` | Maximum tables per group |
| `ARDB_MAX_GROUP_APPS` | `64` | Maximum member applications per group |
| `ARDB_TOKEN_DEFAULT_TTL_SEC` | `14400` | Token lifetime (4 hours) |

---

### 4.3 SQL Firewall & AST (ardb_firewall)

**Files**: `src/ardb_firewall.h`, `src/ardb_firewall.c`

**Purpose**: Real-time SQL syntax analysis and safety inspection. Intercepts queries before they reach PostgreSQL to enforce multi-tenant RLS, block destructive DDL/DML, and enforce table-level ACLs.

#### Enums

```c
typedef enum {
    ARDB_FW_OK = 0,                   // Query approved and rewritten
    ARDB_FW_BLOCK_DESTRUCTIVE = 1,    // DROP, ALTER SYSTEM, TRUNCATE blocked
    ARDB_FW_BLOCK_RLS_BYPASS = 2,     // Comment injection or tenant bypass attempt
    ARDB_FW_BLOCK_EXFILTRATION = 3    // Volume/size limit exceeded for role
} ArdbFwAction;
```

#### Functions

| Signature | Description |
|---|---|
| `ArdbFwAction ardb_firewall_inspect(const char *raw_sql, const char *tenant_id, const char *role, char *out_rewritten_sql, size_t out_size, char *out_reason, size_t out_reason_size)` | Main inspection and rewriting engine |
| `int ardb_firewall_check_table_acl(const char *sql, const ArdbUser *user, char *out_denied_table, size_t table_size)` | Extract all referenced tables and verify against allowed lists |
| `int ardb_firewall_inject_rls(const char *sql, const char *tenant_id, char *out_sql, size_t out_size)` | Prepend `SET LOCAL alri.tenant_id = '...'` to query transaction |

---

### 4.4 PGWire Protocol (ardb_pgwire)

**Files**: `src/ardb_pgwire.h`, `src/ardb_pgwire.c`

**Purpose**: Complete implementation of the PostgreSQL Wire Protocol version 3.0. Handles connection handshake, startup parameters, SSL negotiation, password authentication, simple query mode, and extended query protocol.

#### Message Type Identifiers

```c
#define PG_MSG_STARTUP_V3       0x00030000
#define PG_MSG_SSL_REQUEST      80877103
#define PG_MSG_CANCEL_REQUEST   80877102

// Backend -> Frontend (Server to Client)
#define PG_TYPE_AUTH_REQ        'R'
#define PG_TYPE_KEY_DATA        'K'
#define PG_TYPE_PARAM_STATUS    'S'
#define PG_TYPE_READY_FOR_QUERY 'Z'
#define PG_TYPE_ROW_DESC        'T'
#define PG_TYPE_DATA_ROW        'D'
#define PG_TYPE_CMD_COMPLETE    'C'
#define PG_TYPE_ERROR_RESP      'E'
#define PG_TYPE_NOTICE_RESP     'N'

// Frontend -> Backend (Client to Server)
#define PG_TYPE_PASSWORD        'p'
#define PG_TYPE_QUERY           'Q'
#define PG_TYPE_PARSE           'P'
#define PG_TYPE_BIND            'B'
#define PG_TYPE_EXECUTE         'E'
#define PG_TYPE_SYNC            'S'
```

#### Key Functions

| Signature | Description |
|---|---|
| `int ardb_pgwire_read_startup(int fd, char *out_user, char *out_db, char *out_tenant)` | Parse `StartupMessage` parameters |
| `int ardb_pgwire_send_auth_ok(int fd)` | Send `AuthenticationOk` (type 'R', code 0) |
| `int ardb_pgwire_send_ready(int fd)` | Send `ReadyForQuery` (type 'Z', status 'I') |
| `int ardb_pgwire_send_error(int fd, const char *code, const char *message)` | Send PostgreSQL `ErrorResponse` with SQLSTATE code |
| `int ardb_pgwire_passthrough(int client_fd, int backend_fd, const ArdbUser *user)` | Stream query and response between client and backend with inspection |

---

### 4.5 Backend Connector (ardb_backend)

**Files**: `src/ardb_backend.h`, `src/ardb_backend.c`

**Purpose**: Manages a resilient pool of 16 connections to the isolated PostgreSQL backend on loopback port 5433.

#### Structs

```c
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
```

#### Functions

| Signature | Description |
|---|---|
| `int ardb_backend_init(const char *host, int port, const char *user, const char *pass, const char *db)` | Initialize the connection pool |
| `void ardb_backend_cleanup(void)` | Close all pooled sockets |
| `ArdbBackendConn* ardb_backend_acquire(void)` | Borrow an idle connection from the pool |
| `void ardb_backend_release(ArdbBackendConn *conn)` | Return connection to pool |

---

### 4.6 Storage Engine (ardb_storage_engine)

**Files**: `src/ardb_storage_engine.h`, `src/ardb_storage_engine.c`

**Purpose**: In-memory tabular representation of SQL result sets. Parses `RowDescription` and `DataRow` messages, maps PostgreSQL OIDs to native C types, and serializes results into JSON for the HTTP API.

#### Structs

```c
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
} ArdbResultSet;
```

#### Supported OIDs

| OID | Constant | PostgreSQL Type |
|---|---|---|
| `16` | `PG_OID_BOOL` | boolean |
| `20` | `PG_OID_INT8` | bigint |
| `23` | `PG_OID_INT4` | integer |
| `25` | `PG_OID_TEXT` | text |
| `1043` | `PG_OID_VARCHAR` | varchar |
| `1114` | `PG_OID_TIMESTAMP` | timestamp |

---

### 4.7 Audit Log (ardb_audit)

**Files**: `src/ardb_audit.h`, `src/ardb_audit.c`

**Purpose**: Cryptographic audit logger. Records every query executed through ARDB into a SHA-256 chained log file where each entry signs the previous entry's hash.

#### Functions

| Signature | Description |
|---|---|
| `void ardb_audit_init(const char *log_path)` | Open audit file and verify existing chain |
| `void ardb_audit_cleanup(void)` | Flush buffers and close log file |
| `void ardb_audit_log_query(const char *user, const char *tenant_id, const char *client_ip, const char *sql, int status, uint64_t duration_us)` | Hash and append entry to the chain |
| `int ardb_audit_verify_integrity(const char *log_path, char *out_error, size_t err_size)` | Read entire chain from byte 0 to EOF, recomputing every SHA-256 hash to detect retroactive tampering |

---

### 4.8 HTTP Management API (ardb_http)

**Files**: `src/ardb_http.h`, `src/ardb_http.c`

**Purpose**: Embedded micro-HTTP server listening on port 5435. Exposes REST endpoints for health monitoring, token generation, user administration, and JSON query execution.

#### Endpoints

| Method | Route | Auth Required | Description |
|---|---|---|---|
| `GET` | `/api/v1/db/status` | No | Engine health, connection counts, uptime |
| `POST` | `/api/v1/db/auth/login` | No | Ephemeral token issuance with username/password/2FA |
| `POST` | `/api/v1/db/auth/revoke` | Yes (Bearer) | Invalidate active token |
| `POST` | `/api/v1/db/query` | Yes (Bearer) | Execute SQL query and receive JSON result set |
| `GET` | `/api/v1/db/audit/tail` | Yes (Admin) | Stream last N audit records |
| `GET` | `/api/v1/db/audit/verify` | Yes (Admin) | Run cryptographic chain verification |

---

### 4.9 Configuration Parser (ardb_config)

**Files**: `src/ardb_config.h`, `src/ardb_config.c`

**Purpose**: Reads and validates `ardb.cfg`. Supports live reload via the IPC control plane without daemon restart.

---

## 5. SQL Firewall Deep Dive

### Blocked Operations for Non-Admin Roles

1. **Destructive DDL**: `DROP TABLE`, `DROP DATABASE`, `DROP SCHEMA`, `TRUNCATE`
2. **System Alterations**: `ALTER SYSTEM`, `ALTER USER`, `CREATE ROLE`
3. **Privilege Escalation**: `GRANT`, `REVOKE`
4. **Copy/Export**: `COPY ... TO PROGRAM`, `COPY ... TO FILE`
5. **Comment Evasion**: SQL comments (`--`, `/* */`) that attempt to hide injected statements

### Multi-Tenant RLS Injection

When a query is dispatched under a tenant-bound user, the firewall automatically prepends:

```sql
SET LOCAL alri.tenant_id = '<tenant_id>';
```

This guarantees PostgreSQL Row-Level Security (RLS) policies evaluate against the authenticated tenant context, making cross-tenant data leaks impossible at the database engine level.

### Error Code 42501

If an application attempts to access a table outside its private namespace or its assigned App Groups, the firewall immediately terminates the query and returns PostgreSQL standard error:

```
ERROR: 42501: Permission denied for table '<table_name>' by ALRI Firewall
```

---

## 6. PGWire Protocol v3.0 Implementation

### Handshake Sequence

```
 Client                                              ARDB (5432)
   │                                                     │
   ├─── StartupMessage (v3.0, user, database) ──────────►│
   │                                                     ├── Authenticate user
   │◄── AuthenticationOk ('R', code 0) ──────────────────┤
   │◄── ParameterStatus ('S', client_encoding, etc.) ────┤
   │◄── ReadyForQuery ('Z', status 'I') ─────────────────┤
   │                                                     │
   │                    Query Phase                      │
   ├─── Query ('Q', "SELECT * FROM users") ─────────────►│
   │                                                     ├── Firewall inspect
   │                                                     ├── RLS injection
   │                                                     ├── Forward to PG (5433)
   │◄── RowDescription ('T', columns) ──────────────────┤
   │◄── DataRow ('D', values) ───────────────────────────┤
   │◄── CommandComplete ('C', "SELECT 1") ───────────────┤
   │◄── ReadyForQuery ('Z') ─────────────────────────────┤
```

---

## 7. Blockchain-Style Forensic Audit Log

### Hash-Chain Architecture

Every query produces an immutable log entry structured as follows:

```
Entry N:
┌────────────────────────────────────────────────────────┐
│ timestamp_iso: 2026-09-08T20:00:00.000Z               │
│ user: app_store                                        │
│ tenant_id: tenant_alpha                                │
│ client_ip: 10.0.0.12                                   │
│ sql_query: SELECT * FROM store_items                   │
│ status: 200                                            │
│ duration_us: 1420                                      │
│ prev_hash: a1b2c3d4... (SHA-256 of Entry N-1)         │
│ current_hash: e5f6g7h8... (SHA-256 of this entry data) │
└────────────────────────────────────────────────────────┘
```

### Verification Algorithm

`ardb_audit_verify_integrity()` reads the log file sequentially from byte 0:
1. Re-computes `current_hash` using the entry payload and `prev_hash`.
2. Compares computed hash with stored `current_hash`.
3. If any record was modified, inserted, or deleted retroactively, the hash chain breaks at that exact entry number, identifying the tampering location.

---

## 8. App Table Isolation & Multi-Tenancy

### Two-Tier Namespace Model

1. **Private Scope**: An app named `store` automatically owns and can query any table beginning with `store_` (e.g., `store_orders`, `store_inventory`).
2. **Shared Groups**: When multiple apps need shared access:
   - Create an App Group: `loja` with tables `loja_produtos,loja_pedidos`
   - Assign member apps: `store_web` and `store_mobile`
   - Only assigned apps can access `loja_*` tables

Any query referencing tables outside the app's private scope and assigned groups is rejected with `ERROR 42501`.

---

## 9. CLI Governance (`alrios ardb`)

```bash
# View engine status (PGWire, HTTP API, Firewall, Audit)
alrios ardb status

# Hot-reload configuration without daemon restart
alrios ardb cfg reload

# Generate ephemeral 4-hour token
alrios ardb auth login alex

# Revoke active token
alrios ardb auth revoke <token>

# Add user with tenant binding
alrios ardb user add <user> <pass> <tenant> [role]

# Provision app credentials with table scope
alrios ardb app add <app_name> <token_or_hash> [group|-] [tables_csv]

# Create shared App Group
alrios ardb group create <group_name> <tables_csv>

# Add app to group
alrios ardb group add-app <group_name> <app_name>

# Cryptographically verify the audit log chain
alrios ardb audit verify

# Stream real-time query logs
alrios ardb audit tail
```

---

## 10. Build & Packaging

### Compilation

ARDB compiles as a native binary packaged into `ardb.arapp`:

```bash
gcc -O2 \
  -Isrc -I../../ALRIOS/core \
  -I../../ALRIOS/arkernel/include \
  -I../../ALRIOS/arkernel/os/include \
  -o $STAGING/ardb \
  src/ardb_entry.c src/ardb_config.c src/ardb_http.c \
  src/ardb_pgwire.c src/ardb_storage_engine.c src/ardb_backend.c \
  src/ardb_auth.c src/ardb_firewall.c src/ardb_audit.c \
  -L$ARCORE/lib -larkernel -lssl -lcrypto -lpthread
```

### .arapp Manifest (`ardb.arappmake`)

```json
{
  "name": "ardb",
  "version": "0.2.02",
  "runtime": "native",
  "entry": "ardb",
  "services": [{"name": "ardb", "entry": "ardb"}],
  "files": ["ardb", "ardb.cfg"],
  "description": "Banco de dados nativo linear com protocolo PGWire e Firewall AST",
  "commands": ["status", "cfg reload", "auth login", "auth revoke", "user add", "audit tail", "audit verify"]
}
```

---

*Document generated from source code analysis of ARDB v0.2.02.*
*Engineered by ALRI Development. Governed by ALRI GROUP © 2026 — All rights reserved.*
*License: ARGLP (ALRI GROUP LICENSE PERMISSIVE — Version 2)*

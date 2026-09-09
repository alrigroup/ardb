# AGENTS.md — Autonomous AI Agent Operating Protocol & Technical Invariants

> **Target Audience**: Autonomous AI Agents (Antigravity, Claude Code, Cursor, Copilot) & Database Systems Engineers.  
> **Repository**: `ardb` (Sovereign Database Guardian, PGWire Protocol Proxy & SQL Firewall Engine)  
> **Visibility**: Public Open-Core  
> **Asset Owner**: ALRI Group | **Engineering**: ALRI Development  
> **License**: ARGLP (ALRI Group License Permissive — Version 2)  
> **Primary Technical Reference**: Consult [`DOCS.md`](DOCS.md) for complete technical manual covering PGWire messages, AST firewall rules, and SHA-256 hash chains.

---

## 1. Project Mission & Identity

**ARDB** is the sovereign database security proxy and execution engine for the ALRIOS platform. It acts as an active security shield between external database clients (DBeaver, ORMs, microservices) and the isolated physical PostgreSQL backend.

### Core Architectural Specifications
- **Loopback Isolation Mandate**: The physical PostgreSQL database runs exclusively on loopback TCP `127.0.0.1:5433` without public interface exposure. All queries must route through ARDB on port `5432` (PGWire) or `5435` (HTTP REST).
- **Native PGWire Protocol v3.0 (`ardb_pgwire.c`)**: Complete implementation of PostgreSQL wire protocol messages (`StartupMessage`, `AuthenticationOk`, `RowDescription`, `DataRow`, `CommandComplete`, `ReadyForQuery`).
- **SQL AST Firewall (`ardb_firewall.c`)**: Syntax-level query inspection blocking destructive DDL (`DROP`, `TRUNCATE`, `ALTER SYSTEM`) for non-admin profiles and injecting multi-tenant Row-Level Security (`SET LOCAL alri.tenant_id = '...'`).
- **Cryptographic Audit Log (`ardb_audit.c`)**: Blockchain-style SHA-256 hash-chained log guaranteeing tamper detection and forensic non-repudiation.
- **App Table Isolation & Shared Groups (`ardb_auth.c`)**: Enforces namespace boundaries (`<app>_*` tables) and shared data spaces via App Groups with strict table ACLs.

---

## 2. Directory Structure & Key Subsystems

```
ardb/
├── ardb.arappmake           # ALRIOS package manifest & compilation rules
├── ardb.cfg                 # Master configuration (server, backend, firewall, audit)
├── DOCS.md                  # Complete 590+ lines technical reference manual
├── README.md                # Public overview & operational guide
├── AGENTS.md                # This autonomous agent operating protocol
└── src/
    ├── ardb_entry.c         # Process bootstrap, PGWire listener thread, CLI command dispatcher
    ├── ardb_auth.c / .h     # User authentication, 2FA TOTP, session tokens, table ACLs
    ├── ardb_firewall.c / .h # AST query inspection, DDL blocking, tenant RLS injection
    ├── ardb_pgwire.c / .h   # PostgreSQL wire protocol v3.0 message parser and serializer
    ├── ardb_backend.c / .h  # Connection pool (16 sockets) to isolated PostgreSQL on port 5433
    ├── ardb_storage_engine.c / .h # In-memory tabular result sets and PostgreSQL OID mapping
    ├── ardb_audit.c / .h    # SHA-256 chained immutable forensic query logger
    ├── ardb_http.c / .h     # Embedded REST micro-server on port 5435 (/api/v1/db/*)
    └── ardb_config.c / .h   # Parser for ardb.cfg with live hot-reloading support
```

---

## 3. Essential Commands & Toolchain Invariants

### 3.1 Compilation from Source (Linux x64)
```bash
gcc -O2 \
  -Isrc -I../../ALRIOS/core -I../../ALRIOS/arkernel/include -I../../ALRIOS/arkernel/os/include \
  -o ardb \
  src/ardb_entry.c src/ardb_config.c src/ardb_http.c src/ardb_pgwire.c \
  src/ardb_storage_engine.c src/ardb_backend.c src/ardb_auth.c \
  src/ardb_firewall.c src/ardb_audit.c \
  -L../../ALRIOS/arcore/lib -larkernel -lssl -lcrypto -lpthread
```

### 3.2 Packaging into ALRIOS Modular Archive (`.arapp`)
```bash
armake build . ardb.arapp
```

### 3.3 CLI Governance & Forensic Verification
```bash
alrios ardb status                                       # Inspect PGWire, HTTP, firewall, and audit state
alrios ardb cfg reload                                   # Hot-reload ardb.cfg live without downtime
alrios ardb auth login <user>                            # Generate ephemeral 4-hour session token
alrios ardb auth revoke <token>                          # Immediately invalidate active session token
alrios ardb user add <user> <pass> <tenant> [role]       # Provision tenant-bound user
alrios ardb app add <app> <token> [group] [tables]       # Provision application credentials and table scope
alrios ardb group create <group> <tables_csv>            # Create shared App Group (shared data space)
alrios ardb audit verify                                 # Cryptographically verify the SHA-256 hash chain
alrios ardb audit tail                                   # Stream live query log events
```

---

## 4. Architectural Rules & The "NEVER" List

Autonomous AI Agents operating within this codebase must strictly observe these inviolable rules:

### 4.1 Strict Prohibitions
- ❌ **NEVER concatenate user input to construct SQL queries**: All internal queries and proxy operations must use bind parameters.
- ❌ **NEVER allow destructive DDL execution by non-admin roles**: `DROP TABLE`, `DROP DATABASE`, `TRUNCATE`, and `ALTER SYSTEM` must be blocked by the firewall with error code `42501`.
- ❌ **NEVER bypass multi-tenant RLS**: Every tenant-bound transaction must strictly begin with `SET LOCAL alri.tenant_id = '...'` injected prior to the client's query.
- ❌ **NEVER modify or truncate the audit log**: `storage/ardb/audit.log` is an immutable, append-only cryptographic hash chain. Any out-of-order write breaks chain verification.
- ❌ **NEVER expose the backend PostgreSQL port 5433 publicly**: Only ARDB (5432 / 5435) may bind to public or service-accessible interfaces.

---

## 5. Code Style & Engineering Standards

### 5.1 Correct vs. Incorrect Implementations

#### Multi-Tenant RLS Query Rewriting
```c
/* FORBIDDEN: Passing client query without tenant isolation enforcement */
send_query_to_backend(backend_fd, raw_client_sql);

/* CORRECT (ARDB Standard): Injecting local tenant context transactionally */
char rewritten_sql[ARDB_PGWIRE_MAX_BUF];
snprintf(rewritten_sql, sizeof(rewritten_sql),
         "SET LOCAL alri.tenant_id = '%s'; %s",
         sanitized_tenant_id, raw_client_sql);
send_query_to_backend(backend_fd, rewritten_sql);
```

#### Constant-Time Session Comparison
```c
/* CORRECT (ARDB Standard): Mitigating timing side-channels on ephemeral tokens */
int ardb_auth_validate_token_ct(const char *token_a, const char *token_b) {
    size_t la = strlen(token_a);
    size_t lb = strlen(token_b);
    int diff = (la != lb);
    size_t min_len = la < lb ? la : lb;
    for (size_t i = 0; i < min_len; i++) {
        diff |= (token_a[i] ^ token_b[i]);
    }
    return diff == 0 ? 0 : -1;
}
```

### 5.2 Mandatory Copyright Header
Every new C source or header file created must begin with:
```c
/*
 * Copyright (c) 2026 ALRIGROUP and its affiliates.
 * Engineered and maintained by ALRI Development.
 *
 * This code is licensed under the ARGLP - ALRI GROUP LICENSE PERMISSIVE
 * found in the LICENSE file in the root directory of this source tree
 * and at: https://github.com/alrigroup/licenses
 */
```

---

## 6. Pre-Commit & Pull Request Verification Checklist

Before submitting changes, the agent must verify:
1. All 9 C source files compile cleanly with zero warnings under `-O2 -Wall -Wextra`.
2. The PGWire handshake handles PostgreSQL v3.0 startup packets and SSL negotiations without dropping connections.
3. The SQL firewall intercepts unauthorized table access and returns error `42501`.
4. Cryptographic audit verification (`ardb_audit_verify_integrity()`) succeeds with zero chain breaks.
5. Git commits adhere to Conventional Commits with the mandatory trailer:
   `Signed-off-by: ALRI Development <dev@alrigroup.com>`.

# AGENTS.md — AI Agent Guidance & Repository Rules

> **Target Audience**: Autonomous AI Agents (Antigravity, Claude Code, Cursor, Copilot) & Database Systems Engineers.  
> **Repository**: `ardb` (Sovereign Database Guardian, PGWire Proxy & SQL Firewall Engine)  
> **Visibility**: Public Open-Core  
> **Asset Owner**: ALRI Group | **Engineering**: ALRI Development  
> **License**: ARGLP (ALRI Group License Permissive — Version 2)  

---

## 1. Project Mission & Identity

**ARDB** is the sovereign database security proxy and execution engine for the ALRIOS platform. It acts as an active security shield between external database clients (DBeaver, ORMs, microservices) and the isolated physical PostgreSQL backend.

- **Isolation Mandate**: The physical PostgreSQL runs on loopback `127.0.0.1:5433` without public exposure. All queries must route through ARDB on port `5432` (PGWire) or `5435` (HTTP REST).
- **PGWire v3.0**: Native implementation of the PostgreSQL wire protocol (Startup, Auth, RowDescription, DataRow, CommandComplete).
- **SQL Firewall**: AST-level query inspection blocking destructive DDL (`DROP`, `TRUNCATE`, `ALTER`) and enforcing multi-tenant isolation.
- **Forensic Audit**: Blockchain-style SHA-256 hash-chained log ensuring tamper detection and non-repudiation.
- **Reference**: Consult [`DOCS.md`](DOCS.md) for complete technical reference covering all structs and functions.

---

## 2. Essential Commands

### Build from Source
```bash
gcc -O2 \
  -Isrc -I../../ALRIOS/core -I../../ALRIOS/arkernel/include -I../../ALRIOS/arkernel/os/include \
  -o ardb \
  src/ardb_entry.c src/ardb_config.c src/ardb_http.c src/ardb_pgwire.c \
  src/ardb_storage_engine.c src/ardb_backend.c src/ardb_auth.c \
  src/ardb_firewall.c src/ardb_audit.c \
  -larkernel -lssl -lcrypto -lpthread
```

### CLI Governance Commands
```bash
alrios ardb status              # View engine, PGWire, firewall, and audit status
alrios ardb cfg reload          # Hot-reload ardb.cfg without daemon restart
alrios ardb auth login <user>   # Issue ephemeral 4-hour token
alrios ardb auth revoke <token> # Invalidate session token
alrios ardb audit verify        # Cryptographically verify the SHA-256 hash chain
alrios ardb audit tail          # Stream live query log events
```

---

## 3. Strict Prohibitions for AI Agents (The "NEVER" List)

- ❌ **NEVER concatenate raw strings to build SQL statements**: All queries must use parameterized bind variables.
- ❌ **NEVER bypass tenant isolation**: In multi-tenant contexts, transactions must begin with `SET LOCAL alri.tenant_id = '...'`.
- ❌ **NEVER alter audit log entries in place**: The audit log is an append-only cryptographic hash chain; manual edits break chain verification.
- ❌ **NEVER commit `.cfg` with real credentials**: Secrets must be injected via environment or secure vaults.
- ❌ **NEVER expose port 5433**: Only ARDB (5432/5435) may be accessible to callers.

---

## 4. Code Style & Architectural Invariants

- **Language Standard**: Strict C11 (`-std=c11 -O2 -Wall -Wextra`).
- **Table ACL Enforcement**: Applications may only query tables within their private namespace (`<app>_*`) or explicitly assigned App Groups.
- **Error Response Standard**: Unauthorized cross-table access must return PostgreSQL standard error `42501`.
- **Compulsory File Header**:
  ```c
  /*
   * Copyright (c) 2026 ALRIGROUP and its affiliates.
   * Engineered and maintained by ALRI Development.
   *
   * This code is licensed under the ARGLP - ALRI GROUP LICENSE PERMISSIVE
   * found in the LICENSE file in the root directory of this source tree.
   */
  ```

---

## 5. Git Commit Protocol

- Conventional Commits enforced (`feat(firewall): ...`, `fix(pgwire): ...`, `docs: ...`).
- Mandatory trailer: `Signed-off-by: ALRI Development <dev@alrigroup.com>`.

# ALRI DB — Sovereign Database Guardian & Zero-Trust Engine

The **ALRI DB (`ardb`)** is the exclusive database guardian and proxy engine for the ALRIOS ecosystem. It serves as an active security shield between external database clients (such as DBeaver, ORMs, microservices, and web apps) and the isolated physical PostgreSQL instance.

---

## 🛡️ 1. Core Architectural Principle

> **The physical PostgreSQL runs 100% isolated without public exposure or direct external ports.**  
> **Every query (via PG-Wire or HTTP REST API) MUST route through ALRI DB.**

```
[ DBeaver / Apps / REST ] ---> (PG-Wire 5432 / HTTP 5435) ---> [ ALRI DB Engine ] ---> (Loopback 5433) ---> [ Isolated PostgreSQL ]
                                                                       |
                                                     +-----------------+-----------------+
                                                     |                 |                 |
                                                [ Auth 2FA ]     [ AST Firewall ]   [ Forensic Audit ]
```

---

## ⚡ 2. Core Native Modules (`src/apps/ardb/`)

| Module | Files | Responsibility |
| :--- | :--- | :--- |
| **PG-Wire Server** | `ardb_pgwire.h/.c` | Native PostgreSQL wire protocol v3 parser (Startup, Password, Query, Sync, ReadyForQuery). |
| **HTTP REST Gateway** | `ardb_http.h/.c` | Optional embedded REST/JSON micro-server (`/api/v1/db/query`) integrated with ARWS. |
| **Declarative Config** | `ardb_config.h/.c` | Dynamic parser for `ardb.cfg` with live hot-reloading capabilities. |
| **Backend Relay** | `ardb_backend.h/.c` | Connection pool to isolated PostgreSQL backend with bidirectional streaming. |
| **Auth Engine** | `ardb_auth.h/.c` | Ephemeral 4-hour session tokens, Constant-Time memory comparisons against Timing Attacks. |
| **AST SQL Firewall** | `ardb_firewall.h/.c` | Syntax parser blocking destructive commands (`DROP`, `ALTER`), comment injection, enforcing Table ACL & App Group isolation. |
| **Forensic Audit** | `ardb_audit.h/.c` | Immutable SHA-256 hash-chained query log (blockchain-like integrity). |
| **App Table Isolation** | `ardb_auth.h/.c` | Dynamic provisioning of app tokens, private table namespaces, and Shared App Groups. |

---

## 🔒 3. App Table Isolation & Shared App Groups

ARDB protects multi-tenant applications from cross-data contamination using **Table-Level Access Control Lists (ACL)** enforced directly inside the SQL Firewall:

1. **App Table Ownership**: An application exclusively owns and accesses tables prefixed with its name (e.g., `app1` owns `app1_users`, `app1_orders`).
2. **Shared Data Spaces (App Groups)**: When multiple applications need to cooperate (e.g., `app1` (Web Store) and `app4` (Mobile Store)), an App Group is created with shared tables (e.g., group `loja` with `loja_produtos,loja_pedidos`). Only member applications assigned to that group can read or write those shared tables.
3. **Firewall Interception**: Any attempt by an unauthorized application (e.g., `app2`) to query `app1_users` or `loja_produtos` is blocked before hitting PostgreSQL, returning `ERROR: 42501: Permission denied for table by ALRI Firewall`.

---

## 🎮 4. CLI Governance (`alrios ardb`)

```bash
# View engine status (PG-Wire, HTTP REST API, Firewall and Audit state)
alrios ardb status

# Hot reload configuration without daemon restart
alrios ardb cfg reload

# Generate ephemeral 4-hour Zero-Knowledge token
alrios ardb auth login alex

# Revoke active session token immediately
alrios ardb auth revoke <token>

# Create tenant-bound user
alrios ardb user add <user> <password> <tenant> [role]

# Provision app credentials, group binding, and private table scope
alrios ardb app add <app_name> <token_or_hash> [group_name|-] [allowed_tables_csv]

# Create shared App Group (shared data spaces) with allowed tables
alrios ardb group create <group_name> <shared_tables_csv>

# Associate an application with an App Group
alrios ardb group add-app <group_name> <app_name>

# Cryptographically verify the forensic audit log chain
alrios ardb audit verify

# Stream real-time query logs
alrios ardb audit tail
```

---

## 🧪 5. Security Validation and Testing

- **`tests/test_ardb_isolation.c`** — Verification of table isolation, shared group access, and SQL firewall blocking.
- **`docs/test_suite_runner.py`** — Ecosystem master test runner validating 100% of ARDB features.


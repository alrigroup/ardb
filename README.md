<p align="center">
  <img src="https://raw.githubusercontent.com/alrigroup/.github/main/alrigroup.svg" width="120" />
</p>

<h1 align="center">ARDB v2</h1>
<p align="center"><strong>Universal Multi-Model Sovereign Storage & Audit Engine</strong></p>
<p align="center">
  <a href="https://github.com/alrigroup/alrios"><img alt="ALRIOS" src="https://img.shields.io/badge/Powered%20by-ALRIOS-blue?style=flat-square" /></a>
  <img alt="Language" src="https://img.shields.io/badge/language-C11-00599C?style=flat-square" />
  <img alt="License" src="https://img.shields.io/badge/license-ARGLP-green?style=flat-square" />
  <img alt="Standard" src="https://img.shields.io/badge/standard-ALRI--SPEC--DATA--2026--ARDB--V2-purple?style=flat-square" />
</p>

---

## Overview

**ARDB v2** is the sovereign multi-model persistence and low-latency cache authority for the [ALRIOS](https://github.com/alrigroup/alrios) operating system. It provides an autonomous, embedded multi-model engine written in pure C11 serving both relational SQL (PGWire v3.0 on port 5432) and in-memory cache (Redis RESP on port 6379) with zero external daemon dependencies.

### Features

- 🔌 **PGWire Protocol v3.0 (Port 5432)** — Connect directly with DBeaver, Prisma, TypeORM, or psql with real SQL DDL/DML support
- ⚡ **Redis RESP Cache Engine (Port 6379)** — Low-latency concurrent in-memory cache supporting `PING`, `GET`, `SET`, `EXPIRE`, `TTL`, `DEL`
- 💾 **Autonomous Embedded Persistence** — 100% standalone relational engine powered by integrated SQLite with WAL2 mode
- 🛡️ **Zero-Unattributed I/O Mandate (Axiom I)** — Blocks any query without an attested provenance envelope (`ARDB_ERR_UNATTESTED_QUERY`)
- 🧱 **AST SQL Firewall & Namespace Isolation** — AST-level query inspection blocking destructive DDL (`42501`) and isolating application namespaces
- 📊 **Total Read & Write Forensic Auditing** — Every single command (including `SELECT` and `GET`) records rows processed into an immutable SHA-256 continuous hash chain
- 🌐 **HTTP REST API (Port 5435)** — Embedded RESTful interface for web-based queries and administration
- 🔒 **Zero-Trust Engineering** — Strict C11 compilation (`-Wall -Wextra -Wpedantic -Werror`), zero banned libc APIs, socket timeouts on all network endpoints

## Building & Packaging

Requires the ALRIOS toolchain:

```bash
armake build . ardb.arapp
```

## Architecture

ARDB runs as a standalone daemon managed by the ALRIOS service manager. It listens on configurable ports for both PGWire and HTTP management connections.

## Part of ALRIOS

ARDB is a core component of the [ALRIOS Operating System](https://github.com/alrigroup/alrios).

---

<p align="center">© 2025 ALRI Group — All rights reserved.</p>

---

## License

This project is licensed under the **ARGLP** (ALRI Group License Permissive) - see the [LICENSE-ARGLP](https://github.com/alrigroup/licenses/blob/main/LICENSE-ARGLP) file for full terms.

*Commercial and enterprise use is permitted. Resale of the software itself is prohibited.*

---

## 🏢 Credits & Governance

- **Engineering & Architecture**: **[ALRI Development](https://alrigroup.com)** *(Software & Systems Division)*
- **Holding & Asset Management**: **[ALRI Group](https://alrigroup.com)** *(Holding Company)*
- **Licensing**: Governed by **ARGLP** owned by ALRI Group.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://cdn.alrigroup.com/ARD-SF-W.png">
    <source media="(prefers-color-scheme: light)" srcset="https://cdn.alrigroup.com/ARD-SF-B.png">
    <img alt="ARD Seal" src="https://cdn.alrigroup.com/ARD-SF-W.png" width="80">
  </picture><br>
  <sub>© 2026 ALRI Group and its affiliates. Engineered by ALRI Development.</sub>
</p>

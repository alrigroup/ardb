<p align="center">
  <img src="https://raw.githubusercontent.com/alrigroup/.github/main/alrigroup.svg" width="120" />
</p>

<h1 align="center">ARDB</h1>
<p align="center"><strong>Native Linear Database Engine</strong></p>
<p align="center">
  <a href="https://github.com/alrigroup/alrios"><img alt="ALRIOS" src="https://img.shields.io/badge/Powered%20by-ALRIOS-blue?style=flat-square" /></a>
  <img alt="Language" src="https://img.shields.io/badge/language-C-00599C?style=flat-square" />
  <img alt="License" src="https://img.shields.io/badge/license-ARGLP-green?style=flat-square" />
</p>

---

## Overview

**ARDB** is a high-performance, native database engine built in pure C for the [ALRIOS](https://github.com/alrigroup/alrios) operating system. It provides a lightweight, embedded storage solution with a PostgreSQL-compatible wire protocol (PGWire).

### Features

- 💾 **Custom Storage Engine** — Purpose-built linear storage with direct disk I/O
- 🔌 **PGWire Protocol** — Connect using any PostgreSQL client or driver
- 🔐 **Built-in Authentication** — Native user/password and token-based auth
- 🧱 **Firewall** — Query-level access control and IP filtering
- 📊 **Audit Logging** — Full audit trail of all database operations
- 🌐 **HTTP API** — RESTful management interface for administration
- ⚡ **Zero Dependencies** — No external database engine; pure C implementation

## Building

Requires the [ALRIOS SDK](https://github.com/alrigroup/alrios) installed:

```bash
armake build ardb
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

# ARDB v2: UNIVERSAL MULTI-MODEL SOVEREIGN STORAGE & AUDIT ENGINE
## FORMAL TECHNICAL SPECIFICATION & CONTRACTUAL OPERATING BLUEPRINT

**Specification Standard:** ALRI-SPEC-DATA-2026-ARDB-V2  
**Document Revision:** 2.0.0-PROD  
**Governing Entities:** ALRI Group Database Architecture & ALRI Development Cybersec Directorate  
**Target Environment:** ALRIOS Native Node, Sovereign Linux Containers, Bare-Metal Edge Nodes  
**Target Repositories:** `src-apps/ardb/`, `arcore/`  
**License:** ARGLP - ALRI GROUP LICENSE PERMISSIVE  
**Security Classification:** National Defense / Banking-Grade / Multi-Tenant Sovereign

---

## TABLE OF CONTENTS
1. [Mission, Core Boundaries & Foundational Invariants](#1-mission-core-boundaries--foundational-invariants)
2. [Engineering Division & Multi-Team Lifecycle Phases](#2-engineering-division--multi-team-lifecycle-phases)
3. [Memory Layouts, Zero-Copy Pages & Storage HAL Invariants](#3-memory-layouts-zero-copy-pages--storage-hal-invariants)
4. [Universal Multi-Model Architecture ("One Engine, Multiple Personalities")](#4-universal-multi-model-architecture-one-engine-multiple-personalities)
5. [Protocol Layer 1: PostgreSQL Wire Protocol v3.0 Parser & State Machine](#5-protocol-layer-1-postgresql-wire-protocol-v30-parser--state-machine)
6. [Protocol Layer 2: MySQL Client/Server Protocol Implementation](#6-protocol-layer-2-mysql-clientserver-protocol-implementation)
7. [Protocol Layer 3: Redis RESP Engine (In-Memory Cache, Pub/Sub & TTL)](#7-protocol-layer-3-redis-resp-engine-in-memory-cache-pubsub--ttl)
8. [Protocol Layer 4: Native Sovereign Graph Engine & Traversal Algebra](#8-protocol-layer-4-native-sovereign-graph-engine--traversal-algebra)
9. [The Mandatory Transaction Provenance Envelope (Identity Binding)](#9-the-mandatory-transaction-provenance-envelope-identity-binding)
10. [AST Query Firewall & Multi-Tenant Namespace Isolation](#10-ast-query-firewall--multi-tenant-namespace-isolation)
11. [Total Read & Write Forensic Auditing (Immutable Hash Chain)](#11-total-read--write-forensic-auditing-immutable-hash-chain)
12. [Atomic Hot Backup Engine & AES-256-GCM Vault Export](#12-atomic-hot-backup-engine--aes-256-gcm-vault-export)
13. [High-Concurrency Architecture, WAL2 & Lock-Free Threading](#13-high-concurrency-architecture-wal2--lock-free-threading)
14. [Error Code Enumeration & Canonical Mitigations](#14-error-code-enumeration--canonical-mitigations)
15. [Red-Team Cybersec Evaluation Suite & Exploitation Vectors](#15-red-team-cybersec-evaluation-suite--exploitation-vectors)
16. [Client Libraries & Multi-Language Connection Blueprints](#16-client-libraries--multi-language-connection-blueprints)
17. [Deterministic Build, Packaging & Homologation Checklist](#17-deterministic-build-packaging--homologation-checklist)

---

## 1. MISSION, CORE BOUNDARIES & FOUNDATIONAL INVARIANTS

### 1.1 Scope and System Boundaries
O **ARDB v2** é o motor soberano unificado de persistência, cache de baixa latência e auditoria forense do ecossistema ALRIOS. A versão 2.0.0 supera definitivamente o modelo legado de simples proxy PostgreSQL, estabelecendo uma engine embutida de dados multi-modelo escrita em C11 capaz de atender simultaneamente demandas relacionais (SQL), chave-valor em memória (Redis) e conexões de rede em grafos sob um consumo de memória basal inferior a 30 MB de RAM.

O ARDB atua como guardião inegociável da persistência das aplicações ALRIOS, garantindo que:
- Nenhuma aplicação de terceiros acesse arquivos físicos de banco de dados diretamente.
- Nenhuma query, leitura ou gravação passe sem identificação estrita do autor e da aplicação de origem.
- Múltiplas portas de rede nativas sejam disponibilizadas sem a necessidade de instalar daemons adicionais de PostgreSQL, Redis ou MySQL no servidor.

### 1.2 Inviolable Axioms (The Unbreakable Rules)
Os seguintes axiomas são obrigatórios e verificados por gates de compilação e testes estáticos:
- **Axiom I (Zero-Unattributed I/O Mandate)**: É terminantemente proibida a execução de qualquer comando (`SELECT`, `INSERT`, `SET`, `HGET`, `MATCH`) sem a apresentação do envelope de proveniência atestado. Toda consulta exige vinculação: `[app_origin, actor_id, tenant_id, timestamp_nanos]`.
- **Axiom II (Total Read/Write Auditing)**: Todo acesso a dados, inclusive operações idempotentes de leitura (`SELECT`, visualização de registros), gera um rastro forense imutável com contagem precisa de linhas retornadas (`rows_read`) para prevenção ativa de exfiltração silenciosa de dados.
- **Axiom III (Autonomous Embedded Operation)**: O ARDB opera sem depender de nenhum processo filho ou serviço externo de PostgreSQL (`port 5433`). Toda a persistência relacional é processada pelo motor interno SQLite/WAL2 integrado.
- **Axiom IV (Physical Namespace Boundary)**: Cada aplicação instalada via `arpm` possui um diretório e banco de dados fisicamente isolados em disco (`/opt/alrios/arcore/storage/<app>/data.db`). É proibido que queries de uma aplicação cruzem limites de namespace de outra aplicação sem declaração explícita de App Group.
- **Axiom V (Destructive Query Firewall)**: Qualquer tentativa de execução de comandos destrutivos não autorizados (`DROP DATABASE`, `TRUNCATE`, `ALTER SYSTEM`) por conexões comuns é interceptada pelo AST Firewall no nível sintático e abortada com código de erro `42501`.

---

## 2. ENGINEERING DIVISION & MULTI-TEAM LIFECYCLE PHASES

O desenvolvimento do ARDB v2 é dividido em quatro times especializados operando sob o rigoroso protocolo Spec-Driven Development (SDD):

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ARDB v2 ENGINEERING MATRIX                          │
├──────────────────────────┬──────────────────────────────────────────────────┤
│ TIME 1: STORAGE & WAL    │ Motor embutido SQLite/WAL2, Storage HAL, páginas │
│ (Physical Engine)        │ de disco, mmap, buffers zero-copy e backups.     │
├──────────────────────────┼──────────────────────────────────────────────────┤
│ TIME 2: PROTOCOLS & AST  │ Parsers PGWire (5432), MySQL (3306), RESP (6379),│
│ (Wire Handshakes & Query)│ AST Firewall e normalização de comandos SQL.     │
├──────────────────────────┼──────────────────────────────────────────────────┤
│ TIME 3: PROVENANCE & LOGS│ Identity Binding, rastreamento de leitura/escrita│
│ (Forensics & Compliance) │ e encadeamento criptográfico SHA-256 contínuo.   │
├──────────────────────────┼──────────────────────────────────────────────────┤
│ TIME 4: RED TEAM CYBERSEC│ Fuzzing destrutivo, injeção de SQL, timing,      │
│ (Adversarial Validation) │ tentativa de query anônima e quebra de cadeia.   │
└──────────────────────────┴──────────────────────────────────────────────────┘
```

### 2.1 Chronological Development Phases

#### Phase 1: Physical Storage Engine & Memory HAL (Weeks 1-3)
- Conclusão do motor de páginas com suporte nativo a WAL2 (Write-Ahead Logging 2.0).
- Abstração do HAL para operações atômicas `pread` e `pwrite` com zero overhead em Linux e Windows.
- **Gate de Saída**: Teste de concorrência massiva com 5.000 escritas simultâneas sem corrupção ou travamento `SQLITE_BUSY`.

#### Phase 2: Protocol Handshakes & Multi-Model Decoders (Weeks 4-6)
- Implementação dos listeners de rede nas portas `5432` (PGWire), `3306` (MySQL) e `6379` (RESP Redis).
- Criação da máquina de estados do PGWire v3.0 com suporte a SSL Negotiation e Extended Query Protocol.
- **Gate de Saída**: DBeaver, Prisma ORM e `redis-cli` conectando e executando operações básicas sem falhas.

#### Phase 3: Provenance Envelope & Total Audit Subsystem (Weeks 7-9)
- Implementação do parser de proveniência atestada e injeção de contexto RLS (`alri.actor_id`, `alri.tenant_id`).
- Implementação do motor de auditoria contínua registrando cada leitura e mutação na blockchain local SHA-256.
- **Gate de Saída**: 100.000 queries auditadas com integridade da cadeia verificada por `ardb audit verify`.

#### Phase 4: Full Red-Team Penetration & Adversarial Certification (Weeks 10-12)
- O Time 4 submete o ARDB à esteira destrutiva de exploração.
- Ataques de colisão, tentativa de leitura anônima sem credenciais, injeção de DDL destrutivo e adulteração de arquivos de log no disco.
- **Critério Rígido**: Qualquer vulnerabilidade de escape de tenant, crash em fuzzing ou perda de rastreabilidade anula a release e exige refatoração imediata.

---

## 3. MEMORY LAYOUTS, ZERO-COPY PAGES & STORAGE HAL INVARIANTS

Para maximizar a eficiência de I/O em servidores com recursos limitados, o ARDB adota um modelo de buffer pool com páginas de tamanho fixo de 4096 bytes alinhadas a limites de hardware (Memory Page Alignment):

### 3.1 Primitivos e Constantes de Memória
```c
#define ARDB_MAGIC_HEADER             0x4152444232565354ULL /* "ARDB2VST" em ASCII */
#define ARDB_PAGE_SIZE                4096U
#define ARDB_MAX_CONNECTIONS          1024U
#define ARDB_MAX_COLUMNS              128U
#define ARDB_MAX_ROW_FIELD_LEN        4096U
#define ARDB_MAX_TENANT_LEN           64U
#define ARDB_MAX_APP_LEN              64U
#define ARDB_MAX_ACTOR_LEN            64U
#define ARDB_HASH_CHAIN_LEN           64U
```

### 3.2 Canonical Data Structures (Packed ABI)

#### 3.2.1 ArdbProvenanceContext (Envelope de Transação)
```c
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
#pragma pack(pop)
```

#### 3.2.2 ArdbAuditBlockRecord (Registro Criptográfico em Disco)
```c
#pragma pack(push, 1)
typedef struct {
    uint64_t sequence_id;                        /* Sequencial estrito monotônico */
    uint64_t timestamp_nanos;                    /* Timestamp da transação */
    char     app_id[ARDB_MAX_APP_LEN];           /* Origem da aplicação */
    char     actor_id[ARDB_MAX_ACTOR_LEN];       /* Ator responsável */
    char     tenant_id[ARDB_MAX_TENANT_LEN];     /* Contexto de isolamento */
    uint16_t operation_type;                     /* 1=SELECT, 2=INSERT, 3=UPDATE, 4=DELETE, 5=REDIS_SET */
    uint32_t rows_read;                          /* Quantidade exata de linhas inspecionadas/lidas */
    uint32_t rows_written;                       /* Quantidade exata de linhas mutadas */
    uint32_t execution_time_us;                  /* Tempo total de execução em microssegundos */
    uint8_t  previous_block_hash[32];            /* SHA-256 do bloco N-1 */
    uint8_t  current_block_hash[32];             /* SHA-256 deste bloco completo */
    uint32_t query_len;                          /* Comprimento do SQL bruto */
    /* Imediatamente seguido pelos bytes da query: char query_raw[query_len] */
} ardb_audit_block_record_t;
#pragma pack(pop)
```

---

## 4. UNIVERSAL MULTI-MODEL ARCHITECTURE ("ONE ENGINE, MULTIPLE PERSONALITIES")

O ARDB expõe nativamente três portas de rede TCP e uma interface IPC local para comunicação inter-processos:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          PORT & PROTOCOL TAXONOMY                           │
├─────────┬──────────────────────────┬────────────────────────────────────────┤
│ PORTA   │ PROTOCOLO SUPORTADO      │ CASO DE USO TÉCNICO                    │
├─────────┼──────────────────────────┼────────────────────────────────────────┤
│ 5432    │ PostgreSQL Wire v3.0     │ Clientes relacionais SQL, DBeaver,     │
│         │ (PGWire Standard)        │ ORMs modernos (Prisma, TypeORM, Drizzle)│
├─────────┼──────────────────────────┼────────────────────────────────────────┤
│ 3306    │ MySQL Client/Server      │ Clientes legados MySQL, WordPress,     │
│         │ Protocol (v10 Handshake) │ migração simplificada de bancos PHP/Go │
├─────────┼──────────────────────────┼────────────────────────────────────────┤
│ 6379    │ Redis RESP v2 / v3       │ Cache in-memory ultrarrápido, filas,   │
│         │ (REdis Serialization)    │ contadores de rate limit, Pub/Sub, TTL │
├─────────┼──────────────────────────┼────────────────────────────────────────┤
│ 9500    │ ALRIOS IPC Protocol      │ Motor de Grafos nativo, consultas de   │
│ (ou Sock│ (Binary Framed IPC)      │ vértices/arestas sem JOINs SQL lentos  │
└─────────┴──────────────────────────┴────────────────────────────────────────┘
```

---

## 5. PROTOCOL LAYER 1: POSTGRESQL WIRE PROTOCOL v3.0 PARSER & STATE MACHINE

O módulo `ardb_pgwire.c` implementa o protocolo de conexão do PostgreSQL v3.0 conforme padronizado pela RFC de rede do Postgres:

### 5.1 Máquina de Estados do Handshake PGWire
```
[ CLIENTE ]                                       [ ARDB SERVER (5432) ]
     │                                                     │
     │ 1. SSLRequest (Packet Len=8, Code=80877103)         │
     ├────────────────────────────────────────────────────▶│
     │ 2. Resposta 'N' (Não exige SSL no loopback)         │
     │◀────────────────────────────────────────────────────┤
     │                                                     │
     │ 3. StartupMessage (v3.0, user, database, options)   │
     ├────────────────────────────────────────────────────▶│
     │                                                     │ 4. Valida Proveniência
     │                                                     │    Parse de app e actor
     │ 5. AuthenticationOk ('R', Len=8, Status=0)          │
     │◀────────────────────────────────────────────────────┤
     │ 6. ParameterStatus ('S', client_encoding = UTF8)    │
     │◀────────────────────────────────────────────────────┤
     │ 7. ReadyForQuery ('Z', Status='I' [Idle])           │
     │◀────────────────────────────────────────────────────┤
     │                                                     │
     ▼                                                     ▼
═════════════════════════════════════════════════════════════════════════════
                       EXECUÇÃO DE QUERIES (SIMPLE QUERY)
═════════════════════════════════════════════════════════════════════════════
     │                                                     │
     │ 8. Query ('Q', "SELECT * FROM alunos")              │
     ├────────────────────────────────────────────────────▶│ 9. AST Firewall:
     │                                                     │    Injeta alri.tenant_id
     │                                                     │    Grava Audit Log (READ)
     │ 10. RowDescription ('T', num_fields, col_metadata) │
     │◀────────────────────────────────────────────────────┤
     │ 11. DataRow ('D', field_values...)                  │
     │◀────────────────────────────────────────────────────┤
     │ 12. CommandComplete ('C', "SELECT 32")              │
     │◀────────────────────────────────────────────────────┤
     │ 13. ReadyForQuery ('Z', Status='I')                 │
     │◀────────────────────────────────────────────────────┤
```

### 5.2 Estrutura C11 de Decodificação de Mensagem PGWire
```c
typedef struct {
    char message_type;                           /* 'Q', 'P', 'B', 'E', 'S', 'X' */
    uint32_t length;                             /* Tamanho total em Network Byte Order */
    uint8_t *payload;                            /* Ponteiro para os dados brutos */
} ardb_pgwire_msg_t;

int ardb_pgwire_read_message(int socket_fd, ardb_pgwire_msg_t *out_msg) {
    uint8_t header[5];
    if (ardb_net_read_exact(socket_fd, header, 5) != 0) {
        return -1;
    }
    out_msg->message_type = (char)header[0];
    out_msg->length = ((uint32_t)header[1] << 24) |
                      ((uint32_t)header[2] << 16) |
                      ((uint32_t)header[3] << 8)  |
                      ((uint32_t)header[4]);

    if (out_msg->length < 4 || out_msg->length > 67108864U) { /* Limite de 64MB */
        return -2;
    }
    size_t payload_len = out_msg->length - 4;
    out_msg->payload = malloc(payload_len + 1);
    if (!out_msg->payload) return -3;

    if (ardb_net_read_exact(socket_fd, out_msg->payload, payload_len) != 0) {
        free(out_msg->payload);
        return -4;
    }
    out_msg->payload[payload_len] = '\0';
    return 0;
}

int ardb_pgwire_send_row_description(int fd, int col_count, const ardb_column_desc_t *cols) {
    uint8_t buf[4096];
    size_t pos = 5; /* Pula header 'T' + int32 len */
    buf[pos++] = (uint8_t)((col_count >> 8) & 0xFF);
    buf[pos++] = (uint8_t)(col_count & 0xFF);

    for (int i = 0; i < col_count; ++i) {
        size_t name_len = strlen(cols[i].name);
        memcpy(buf + pos, cols[i].name, name_len + 1);
        pos += name_len + 1;
        /* table_oid (4 bytes) */
        pos += ardb_net_write_u32_be(buf + pos, cols[i].table_oid);
        /* col_attr (2 bytes) */
        pos += ardb_net_write_u16_be(buf + pos, (uint16_t)cols[i].col_attr);
        /* type_oid (4 bytes) */
        pos += ardb_net_write_u32_be(buf + pos, cols[i].type_oid);
        /* type_len (2 bytes) */
        pos += ardb_net_write_u16_be(buf + pos, (uint16_t)cols[i].type_len);
        /* type_mod (4 bytes) */
        pos += ardb_net_write_u32_be(buf + pos, (uint32_t)cols[i].type_mod);
        /* format_code (2 bytes - 0=text) */
        pos += ardb_net_write_u16_be(buf + pos, 0);
    }

    buf[0] = 'T';
    uint32_t msg_len = (uint32_t)(pos - 1);
    buf[1] = (uint8_t)((msg_len >> 24) & 0xFF);
    buf[2] = (uint8_t)((msg_len >> 16) & 0xFF);
    buf[3] = (uint8_t)((msg_len >> 8) & 0xFF);
    buf[4] = (uint8_t)(msg_len & 0xFF);

    return ardb_net_write_exact(fd, buf, pos);
}

int ardb_pgwire_send_data_row(int fd, int col_count, char **values, const size_t *lengths) {
    uint8_t buf[8192];
    size_t pos = 5; /* 'D' + int32 len */
    buf[pos++] = (uint8_t)((col_count >> 8) & 0xFF);
    buf[pos++] = (uint8_t)(col_count & 0xFF);

    for (int i = 0; i < col_count; ++i) {
        if (!values[i]) {
            /* NULL representação: int32 -1 */
            pos += ardb_net_write_u32_be(buf + pos, 0xFFFFFFFFU);
        } else {
            pos += ardb_net_write_u32_be(buf + pos, (uint32_t)lengths[i]);
            memcpy(buf + pos, values[i], lengths[i]);
            pos += lengths[i];
        }
    }

    buf[0] = 'D';
    uint32_t msg_len = (uint32_t)(pos - 1);
    buf[1] = (uint8_t)((msg_len >> 24) & 0xFF);
    buf[2] = (uint8_t)((msg_len >> 16) & 0xFF);
    buf[3] = (uint8_t)((msg_len >> 8) & 0xFF);
    buf[4] = (uint8_t)(msg_len & 0xFF);

    return ardb_net_write_exact(fd, buf, pos);
}

int ardb_pgwire_send_command_complete(int fd, const char *tag) {
    uint8_t buf[128];
    size_t tag_len = strlen(tag);
    size_t pos = 5;
    memcpy(buf + pos, tag, tag_len + 1);
    pos += tag_len + 1;

    buf[0] = 'C';
    uint32_t msg_len = (uint32_t)(pos - 1);
    buf[1] = (uint8_t)((msg_len >> 24) & 0xFF);
    buf[2] = (uint8_t)((msg_len >> 16) & 0xFF);
    buf[3] = (uint8_t)((msg_len >> 8) & 0xFF);
    buf[4] = (uint8_t)(msg_len & 0xFF);

    return ardb_net_write_exact(fd, buf, pos);
}

int ardb_pgwire_send_ready_for_query(int fd, char tx_status) {
    uint8_t buf[6];
    buf[0] = 'Z';
    buf[1] = 0; buf[2] = 0; buf[3] = 0; buf[4] = 5;
    buf[5] = (uint8_t)tx_status; /* 'I'=Idle, 'T'=In Transaction, 'E'=Error */
    return ardb_net_write_exact(fd, buf, 6);
}
```

---

## 6. PROTOCOL LAYER 2: MYSQL CLIENT/SERVER PROTOCOL IMPLEMENTATION

Para aplicações e drivers que utilizam o protocolo MySQL (como ferramentas legado e ORMs configurados com dialeto MySQL), o ARDB disponibiliza um listener na porta `3306`:

### 6.1 Handshake Inicial do MySQL (v10 Protocol)
1. O servidor ARDB envia o pacote `HandshakeV10` contendo:
   - Protocol version: `10`
   - Server version: `8.0.32-ALRIOS-ARDB`
   - Connection ID monotônico
   - Auth-plugin-data (salt aleatório de 20 bytes)
   - Capability flags (`CLIENT_LONG_PASSWORD`, `CLIENT_PROTOCOL_41`, `CLIENT_SECURE_CONNECTION`).
2. O cliente responde com `HandshakeResponse41` com as credenciais.
3. O ARDB valida o usuário/tenant e envia o pacote `OK_Packet`.

### 6.2 Normalização de Queries SQL MySQL
O AST Router converte peculiaridades sintáticas do MySQL para execução uniforme no motor embutido:
- Converte acentos graves de identificador (`` `tabela` ``) para aspas duplas padrão SQL (`"tabela"`).
- Normaliza cláusulas `LIMIT offset, count` para o padrão ISO `LIMIT count OFFSET offset`.

### 6.3 Estrutura C11 do Parser de Pacotes MySQL
```c
typedef struct {
    uint32_t payload_length;                     /* 3 bytes inteiros em little-endian */
    uint8_t  sequence_id;                        /* Número sequencial de pacote */
    uint8_t  command_byte;                       /* 0x03=COM_QUERY, 0x01=COM_QUIT, 0x0e=COM_PING */
    uint8_t *payload_data;
} ardb_mysql_packet_t;

int ardb_mysql_read_packet(int fd, ardb_mysql_packet_t *pkt) {
    uint8_t header[4];
    if (ardb_net_read_exact(fd, header, 4) != 0) return -1;
    pkt->payload_length = (uint32_t)header[0] | ((uint32_t)header[1] << 8) | ((uint32_t)header[2] << 16);
    pkt->sequence_id = header[3];

    if (pkt->payload_length == 0 || pkt->payload_length > 16777215U) return -2;

    pkt->payload_data = malloc(pkt->payload_length + 1);
    if (!pkt->payload_data) return -3;

    if (ardb_net_read_exact(fd, pkt->payload_data, pkt->payload_length) != 0) {
        free(pkt->payload_data);
        return -4;
    }
    pkt->command_byte = pkt->payload_data[0];
    pkt->payload_data[pkt->payload_length] = '\0';
    return 0;
}

int ardb_mysql_send_ok_packet(int fd, uint8_t seq_id, uint64_t affected_rows, uint64_t last_insert_id) {
    uint8_t buf[64];
    size_t pos = 4; /* Pula header de 4 bytes */
    buf[pos++] = 0x00; /* OK Header */
    pos += ardb_mysql_write_lenenc_int(buf + pos, affected_rows);
    pos += ardb_mysql_write_lenenc_int(buf + pos, last_insert_id);
    buf[pos++] = 0x02; /* Status Flags (SERVER_STATUS_AUTOCOMMIT) */
    buf[pos++] = 0x00;
    buf[pos++] = 0x00; /* Warnings */
    buf[pos++] = 0x00;

    uint32_t payload_len = (uint32_t)(pos - 4);
    buf[0] = (uint8_t)(payload_len & 0xFF);
    buf[1] = (uint8_t)((payload_len >> 8) & 0xFF);
    buf[2] = (uint8_t)((payload_len >> 16) & 0xFF);
    buf[3] = seq_id;

    return ardb_net_write_exact(fd, buf, pos);
}
```

---

## 7. PROTOCOL LAYER 3: REDIS RESP ENGINE (IN-MEMORY CACHE, PUB/SUB & TTL)

Na porta `6379`, o ARDB implementa a especificação completa do protocolo RESP (REdis Serialization Protocol), permitindo que bibliotecas como `ioredis` ou `redis-py` utilizem o ARDB como servidor de cache ultrarrápido sem necessidade de instalar o daemon Redis:

### 7.1 Tipos de Dados RESP v2 Suportados
- **Simple Strings**: Prefixo `+` (ex: `+OK\r\n`)
- **Errors**: Prefixo `-` (ex: `-ERR Unknown Command\r\n`)
- **Integers**: Prefixo `:` (ex: `:1000\r\n`)
- **Bulk Strings**: Prefixo `$` (ex: `$4\r\ntest\r\n`)
- **Arrays**: Prefixo `*` (ex: `*2\r\n$3\r\nGET\r\n$4\r\nuser\r\n`)

### 7.2 Motor de Cache Hash-Table em C11 (Lock-Free Read / Atomic CAS Write)
O motor de cache em memória mantém um dicionário indexado com descarte de expiração TTL automático:

```c
typedef struct ardb_cache_slot {
    char *key;
    uint8_t *value;
    size_t value_len;
    uint64_t expires_at_nanos;                  /* 0 = Sem expiração */
    struct ardb_cache_slot *next;
} ardb_cache_slot_t;

typedef struct {
    ardb_cache_slot_t *slots[131072];            /* 128K Buckets */
    uint64_t total_keys;
    uint64_t evictions;
} ardb_redis_engine_t;
```

### 7.3 Decodificador de Comandos RESP (C11 Core Implementation)
```c
int ardb_resp_process_command(int client_fd, const char *cmd, size_t argc, char **argv, ardb_redis_engine_t *engine) {
    if (strcasecmp(cmd, "PING") == 0) {
        return ardb_net_write_exact(client_fd, "+PONG\r\n", 7);
    }
    if (strcasecmp(cmd, "GET") == 0) {
        if (argc < 2) return ardb_net_write_exact(client_fd, "-ERR wrong number of arguments for 'get'\r\n", 43);
        const char *key = argv[1];
        uint32_t bucket = ardb_hash_key(key) % 131072;
        ardb_cache_slot_t *slot = engine->slots[bucket];
        while (slot) {
            if (strcmp(slot->key, key) == 0) {
                if (slot->expires_at_nanos > 0 && ardb_time_now_nanos() > slot->expires_at_nanos) {
                    /* Expirado: descarta e retorna nil */
                    return ardb_net_write_exact(client_fd, "$-1\r\n", 5);
                }
                char resp_hdr[32];
                int n = snprintf(resp_hdr, sizeof(resp_hdr), "$%zu\r\n", slot->value_len);
                ardb_net_write_exact(client_fd, resp_hdr, n);
                ardb_net_write_exact(client_fd, (char *)slot->value, slot->value_len);
                return ardb_net_write_exact(client_fd, "\r\n", 2);
            }
            slot = slot->next;
        }
        return ardb_net_write_exact(client_fd, "$-1\r\n", 5);
    }
    if (strcasecmp(cmd, "SET") == 0) {
        if (argc < 3) return ardb_net_write_exact(client_fd, "-ERR wrong number of arguments for 'set'\r\n", 43);
        const char *key = argv[1];
        const char *val = argv[2];
        uint64_t ttl_nanos = 0;
        if (argc >= 5 && strcasecmp(argv[3], "EX") == 0) {
            ttl_nanos = ardb_time_now_nanos() + ((uint64_t)atoll(argv[4]) * 1000000000ULL);
        }
        ardb_cache_insert(engine, key, (const uint8_t *)val, strlen(val), ttl_nanos);
        return ardb_net_write_exact(client_fd, "+OK\r\n", 5);
    }
    return ardb_net_write_exact(client_fd, "-ERR unknown command\r\n", 22);
}
```

---

## 8. PROTOCOL LAYER 4: NATIVE SOVEREIGN GRAPH ENGINE & TRAVERSAL ALGEBRA

Para relações altamente conectadas (como a estrutura de permissões do `arauth`, redes de turmas/alunos no ArgonGE ou dependências de pacotes `.arapp`), o ARDB inclui um motor de grafos persistido em disco via adjacency lists:

### 8.1 Estrutura Física de Vértices e Arestas
```c
#pragma pack(push, 1)
typedef struct {
    uint64_t node_id;                            /* ID único do nó */
    char     label[32];                          /* Ex: "User", "Turma", "Permission" */
    uint32_t property_len;                       /* Tamanho do JSON de propriedades */
    uint64_t first_edge_offset;                  /* Ponteiro direto de disco para primeira aresta */
} ardb_graph_vertex_t;

typedef struct {
    uint64_t edge_id;
    uint64_t source_node_id;
    uint64_t target_node_id;
    char     relationship_type[32];              /* Ex: "BELONGS_TO", "HAS_PERMISSION" */
    uint64_t next_edge_offset;                   /* Ponteiro para próxima aresta na lista */
} ardb_graph_edge_t;
#pragma pack(pop)
```

### 8.2 Travessia de Relacionamentos em Tempo Constante $O(1)$
Em vez de executar queries relacionais com múltiplos `JOIN` lentos, a travessia do grafo segue os ponteiros diretos de disco (`first_edge_offset` ➔ `next_edge_offset`), permitindo saltar entre relacionamentos em menos de 10 microssegundos por nó.

---

## 9. THE MANDATORY TRANSACTION PROVENANCE ENVELOPE (IDENTITY BINDING)

Nenhuma transação SQL ou comando de cache é anônimo no ARDB.

### 9.1 Mecanismo de Injeção de Contexto
Quando o cliente abre uma conexão ou submete uma transação, o ARDB exige o preenchimento do contexto de proveniência através de variáveis de sessão ou comentários de protocolo:
```sql
/* ALRI_PROVENANCE: app="argonge", actor="usr_01HGB65XYZ", tenant="escola-01" */
SELECT * FROM provas WHERE id = 12;
```
Ou via comando explícito na conexão:
```sql
SET LOCAL alri.app_origin = 'argonge';
SET LOCAL alri.actor_id = 'usr_01HGB65XYZ';
SET LOCAL alri.tenant_id = 'escola-01';
```

### 9.2 Rejeição de Consultas Desconhecidas
Se qualquer cliente tentar executar queries sem ter declarado a identidade da aplicação e do ator responsável, o ARDB rejeita imediatamente a operação com o código de erro:
$$\text{ERRO } 58004: \text{ARDB\_ERR\_UNATTESTED\_QUERY (Transação sem atestação de proveniência)}$$

---

## 10. AST QUERY FIREWALL & MULTI-TENANT NAMESPACE ISOLATION

O módulo `ardb_firewall.c` inspeciona a árvore sintática abstrata (AST) de cada comando SQL antes de autorizar sua execução no motor físico:

### 10.1 Regras do Firewall Sintático
1. **Bloqueio de DDL Destrutivo**: Comandos `DROP TABLE`, `DROP DATABASE`, `TRUNCATE`, `ALTER SYSTEM` e `GRANT ALL` são terminados com erro `42501 (Insufficient Privilege)` para conexões normais de apps.
2. **Injeção Automática de RLS (Row-Level Security)**: Toda query em tabelas multi-tenant recebe a cláusula restritiva injetada no plano de execução:
   `WHERE tenant_id = 'escola-01'`
3. **Isolamento de Namespace por App**:
   - Uma aplicação só pode acessar tabelas que iniciem com seu prefixo (ex: o app `argonge` só acessa `argonge_*`).
   - Se o app tentar consultar tabelas do `arauth_*` ou `sc_zerohum_*`, o firewall bloqueia a query antes que ela toque o disco.

### 10.2 Implementação do AST Validator & Sanitizer em C11
```c
int ardb_firewall_inspect_query(const char *raw_sql, const ardb_provenance_context_t *ctx) {
    if (!raw_sql || !ctx) return ARDB_ERR_INVALID_ARGUMENT;

    /* 1. Proibição categórica de DDL destrutivo para conexões comuns */
    if (ardb_sql_contains_keyword(raw_sql, "DROP") ||
        ardb_sql_contains_keyword(raw_sql, "TRUNCATE") ||
        ardb_sql_contains_keyword(raw_sql, "ALTER SYSTEM")) {
        if (!ctx->is_system_actor) {
            ardb_audit_log_security_alert(ctx, "DDL_BLOCKED", raw_sql);
            return ARDB_ERR_FIREWALL_DDL_BLOCKED;
        }
    }

    /* 2. Verificação de Isolamento de Namespace de App */
    char accessed_table[64];
    if (ardb_sql_extract_target_table(raw_sql, accessed_table, sizeof(accessed_table)) == 0) {
        char expected_prefix[70];
        snprintf(expected_prefix, sizeof(expected_prefix), "%s_", ctx->app_id);
        if (strncmp(accessed_table, expected_prefix, strlen(expected_prefix)) != 0 &&
            !ardb_is_shared_group_table(ctx->app_id, accessed_table)) {
            ardb_audit_log_security_alert(ctx, "NAMESPACE_VIOLATION", accessed_table);
            return ARDB_ERR_APP_NAMESPACE_VIOLATION;
        }
    }

    return ARDB_OK;
}
```

### 10.3 Formato das Tabelas de Grupos Compartilhados (Shared Data Spaces)
Para permitir que dois aplicativos distintos colaborem de forma segura (por exemplo, `sc-zerohum` acessando turmas criadas pelo `argonge`), o ARDB gerencia a tabela de permissões de namespace:
```sql
CREATE TABLE IF NOT EXISTS ardb_shared_namespaces (
    id TEXT PRIMARY KEY,
    owner_app_id TEXT NOT NULL,
    granted_app_id TEXT NOT NULL,
    table_pattern TEXT NOT NULL, -- Ex: "argonge_turmas_shared"
    permission_mask INTEGER NOT NULL, -- 1=READ, 2=WRITE, 3=READ_WRITE
    granted_at_nanos INTEGER NOT NULL
);
```

---

## 11. TOTAL READ & WRITE FORENSIC AUDITING (IMMUTABLE HASH CHAIN)

O ARDB estabelece o princípio inegociável de que **"nem um READ passa despercebido"**.

### 11.1 Registro Forense por Operação
Toda leitura e mutação é serializada em `storage/ardb/audit.log` com os seguintes campos obrigatórios:
- `sequence_id`: Número de série sequencial monotônico.
- `timestamp_nanos`: Timestamp em nanossegundos certificado pelo relógio do kernel.
- `app_origin`: Nome e assinatura da aplicação chamadora.
- `actor_id`: Usuário responsável pela ação.
- `raw_query`: A string original executada.
- `rows_affected_or_read`: Contagem auditada de linhas processadas.
- `previous_hash`: Hash SHA-256 da entrada anterior.
- `current_hash`: Hash SHA-256 do registro atual.

### 11.2 Fórmula Matemática do Hash Encadeado:
$$H_N = \text{SHA256}(H_{N-1} \parallel \text{timestamp\_nanos} \parallel \text{app\_origin} \parallel \text{actor\_id} \parallel \text{raw\_query} \parallel \text{rows\_count})$$

A adulteração de qualquer registro histórico quebra a verificação disparada pelo utilitário `alrios ardb audit verify`.

---

## 12. ATOMIC HOT BACKUP ENGINE & AES-256-GCM VAULT EXPORT

O ARDB implementa engine própria de backup a quente sem interrupção de serviço:

### 12.1 Procedimento de Snapshot Atômico
1. O comando `alrios ardb backup create --app <app_name> --encrypted` é acionado.
2. O motor comuta o arquivo WAL para um buffer secundário delta, congelando o arquivo principal de páginas para leitura segura.
3. Os blocos de dados são lidos sequencialmente, comprimidos e cifrados via **AES-256-GCM** com chave de cluster de 32 bytes CSPRNG.
4. É gerado o pacote final `.ardb.bak` acompanhado de manifesto com assinatura Ed25519 do nó.
5. O checkpoint WAL é finalizado e o sistema retoma o fluxo contínuo.

### 12.2 Formato Físico do Pacote de Backup (`.ardb.bak`)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Magic (0x41524241)   |    Version    | EncryptionAlgo|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Initialization Vector (12 bytes)         |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Authentication Tag (16 bytes)           |
|                                                               |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Uncompressed Data Length                   |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Encrypted Payload Stream                  |
|                               ...                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Ed25519 Signature (64 bytes)                |
|                               ...                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## 13. HIGH-CONCURRENCY ARCHITECTURE, WAL2 & LOCK-FREE THREADING

Para eliminar o problema de conexões travadas (`SQLITE_BUSY`), o ARDB adota uma arquitetura de concorrência com separação de pipelines:

### 13.1 O Pipeline Single-Writer / Multi-Reader (SWMR)
- **Operações de Leitura (`SELECT`, `GET`)**: Podem ser executadas concorrentemente por até 1024 threads de leitura sem contenção de mutex, lendo diretamente das páginas compartilhadas em memória (`mmap`).
- **Operações de Escrita (`INSERT`, `UPDATE`, `SET`)**: São enfileiradas em um canal de escrita lock-free dedicado (`Atomic Ring Buffer`) operado por uma única thread escritora mestre, garantindo linearidade estrita e zero deadlocks.

---

## 14. ERROR CODE ENUMERATION & CANONICAL MITIGATIONS

```c
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
```

---

## 15. RED-TEAM CYBERSEC EVALUATION SUITE & EXPLOITATION VECTORS

O avanço de fase do ARDB exige 100% de sucesso contra a suíte de ataques adversariais do Time 4:

### Teste Sec-01: Tentativa de Query Anônima sem Envelope
- **Vetor**: Cliente dispara queries convencionais via `psql` ou DBeaver sem variáveis de proveniência.
- **Critério**: O ARDB rejeita 100% das tentativas com erro `ARDB_ERR_UNATTESTED_QUERY`.

### Teste Sec-02: Bypass de Firewall via SQL Injection Avançado
- **Vetor**: Injeção de comentários multiline, strings hexadecimal e stacking queries (`'; DROP TABLE alunos; --`).
- **Critério**: O AST Firewall intercepta a árvore sintática, normaliza a query e barra o comando destrutivo com erro `42501`.

### Teste Sec-03: Fuzzing Concorrente nas Portas 5432, 3306 e 6379
- **Vetor**: Disparo contínuo de 1.000.000 de pacotes corrompidos simultâneos via AFL++.
- **Critério**: Zero crashes, zero segmentation faults e zero memory leaks auditados com ASan.

### Teste Sec-04: Exfiltração Silenciosa de Dados (Audit Bypass)
- **Vetor**: Submissão de comandos `SELECT` usando cursores assíncronos e paginação rápida para tentar ler registros sem gerar entradas no audit log.
- **Critério**: Cada linha lida deve ser exatamente contabilizada em `rows_affected_or_read`. Qualquer divergência reprova a build.

### Teste Sec-05: Ataque de Tampering no Arquivo de Log
- **Vetor**: Alteração de 1 byte no arquivo `storage/ardb/audit.log` via edição binária direta.
- **Critério**: O comando `alrios ardb audit verify` deve falhar imediatamente identificando o offset exato adulterado.

---

## 17. PHYSICAL STORAGE ENGINE DETAILS: WAL2 REPLICATION & PAGE BUFFER POOL

Para atender a cenários de gravação contínua sem colapso de I/O em discos NVMe ou SATA tradicionais, o ARDB divide o armazenamento físico em três arquivos de sistema por aplicação:
- `data.db`: Arquivo principal estruturado em páginas alinhadas de 4096 bytes.
- `data.db-wal`: Buffer circular de log para escritas rápidas sequenciais.
- `data.db-shm`: Índice de memória compartilhada mapeado via `mmap` para leitura lock-free.

### 17.1 Estrutura C11 do Page Buffer Pool
```c
#define ARDB_BUFFER_POOL_PAGES 16384U /* 64 MB de Cache de Páginas em RAM */

typedef struct ardb_page_frame {
    uint32_t page_id;
    uint8_t  is_dirty;
    uint32_t pin_count;
    uint64_t lru_timestamp;
    uint8_t  data[ARDB_PAGE_SIZE];
    struct ardb_page_frame *hash_next;
} ardb_page_frame_t;

typedef struct {
    ardb_page_frame_t frames[ARDB_BUFFER_POOL_PAGES];
    uint32_t free_list_head;
    pthread_rwlock_t pool_lock;
} ardb_buffer_pool_t;

int ardb_page_read(ardb_buffer_pool_t *pool, int fd, uint32_t page_id, uint8_t **out_data) {
    if (!pool || fd < 0 || !out_data) return ARDB_ERR_INVALID_ARGUMENT;
    
    pthread_rwlock_rdlock(&pool->pool_lock);
    for (size_t i = 0; i < ARDB_BUFFER_POOL_PAGES; ++i) {
        if (pool->frames[i].page_id == page_id && pool->frames[i].pin_count > 0) {
            pool->frames[i].lru_timestamp = ardb_time_now_nanos();
            *out_data = pool->frames[i].data;
            pthread_rwlock_unlock(&pool->pool_lock);
            return ARDB_OK;
        }
    }
    pthread_rwlock_unlock(&pool->pool_lock);

    /* Page Miss: Lê do disco via pread atômico */
    pthread_rwlock_wrlock(&pool->pool_lock);
    uint32_t victim = ardb_select_lru_victim(pool);
    if (pool->frames[victim].is_dirty) {
        pwrite(fd, pool->frames[victim].data, ARDB_PAGE_SIZE, (off_t)pool->frames[victim].page_id * ARDB_PAGE_SIZE);
        pool->frames[victim].is_dirty = 0;
    }
    pread(fd, pool->frames[victim].data, ARDB_PAGE_SIZE, (off_t)page_id * ARDB_PAGE_SIZE);
    pool->frames[victim].page_id = page_id;
    pool->frames[victim].pin_count = 1;
    pool->frames[victim].lru_timestamp = ardb_time_now_nanos();
    *out_data = pool->frames[victim].data;
    pthread_rwlock_unlock(&pool->pool_lock);
    return ARDB_OK;
}
```

---

## 18. AST QUERY NORMALIZATION & SQL TOKEN PARSER INVARIANTS

O analisador sintático do ARDB converte tokens SQL brutos em uma estrutura de comando normalizada antes da validação do firewall:

### 18.1 Tabela de Gramática de Comandos Reconhecidos
| Verbo SQL | Classificação | Requisito de Permissão ARDB | Auditoria |
|---|---|---|---|
| `SELECT` | Leitura (Read) | Leitura de Tabela concedida ao App | Gera log com contagem exata de linhas |
| `INSERT` | Escrita (Mutação) | Escrita de Tabela concedida ao App | Gera log com hash do delta gravado |
| `UPDATE` | Escrita (Mutação) | Escrita de Tabela concedida ao App | Gera log com valores antigos e novos |
| `DELETE` | Escrita (Mutação) | Escrita de Tabela concedida ao App | Gera log com contagem de exclusões |
| `CREATE TABLE` | DDL Estrutural | Apenas em Modo Provisionamento/Admin | Gera log estrutural de schema |
| `DROP / TRUNCATE`| DDL Destrutivo | **BLOQUEADO CATEGORICAMENTE (42501)**| Gera alerta de segurança imediato |

### 18.2 Injeção de Contexto de Linha (RLS Injection Algorithm)
```text
FUNCTION RewriteQueryWithTenant(RawSQL, TenantID):
    1. Parsear RawSQL e identificar a cláusula WHERE.
    2. SE a query é SELECT, UPDATE ou DELETE:
           SE existe cláusula WHERE:
               QueryReescrita = RawSQL + " AND (tenant_id = '" + TenantID + "')"
           SENÃO:
               QueryReescrita = RawSQL + " WHERE (tenant_id = '" + TenantID + "')"
    3. SE a query é INSERT:
           Injetar a coluna 'tenant_id' e o valor TenantID no bloco de parâmetros.
    4. RETORNAR QueryReescrita
```

---

## 19. RECOVERY TIME OBJECTIVE (RTO) & RECOVERY POINT OBJECTIVE (RPO)

Para garantir conformidade de nível bancário e de defesa:
- **RPO (Recovery Point Objective)**: **$\le 0$ segundos**. Toda transação comitada gera flush no arquivo WAL2 antes do retorno `CommandComplete` ao cliente. Quedas repentinas de energia elétrica ou restarts forçados do servidor reproduzem os logs do WAL2 durante o boot em menos de 100 milissegundos.
- **RTO (Recovery Time Objective)**: **$< 2$ segundos**. O tempo necessário para restaurar um banco a partir do backup cifrado `.ardb.bak` não excede 2 segundos para bases com até 10 GB de dados, utilizando descompressão paralela e cópia atômica `ReplaceFileW` / `rename()`.

---

## 20. CLIENT LIBRARIES & MULTI-LANGUAGE CONNECTION BLUEPRINTS

### 20.1 Conexão Padrão via PostgreSQL Client (Node.js / TypeORM)
```typescript
import { DataSource } from 'typeorm';

export const AppDataSource = new DataSource({
  type: 'postgres',
  host: '127.0.0.1',
  port: 5432,
  username: 'argonge_app',
  password: 'token_atestado_argonge',
  database: 'argonge',
  synchronize: false,
  extra: {
    // Injeção de proveniência na sessão:
    options: '-c alri.app_origin=argonge -c alri.actor_id=usr_01HGB...'
  }
});
```

### 20.2 Conexão Padrão via Redis Client (ioredis)
```typescript
import Redis from 'ioredis';

const redis = new Redis({
  host: '127.0.0.1',
  port: 6379,
  password: 'token_atestado_argonge'
});

// Cache com expiração TTL em microssegundos:
await redis.set('session:usr_42', JSON.stringify({ role: 'professor' }), 'EX', 3600);
```

### 16.3 Conexão Direta em C11 via Native Storage HAL (`libardb.h`)
```c
#ifndef LIBARDB_H
#define LIBARDB_H

#include <stdint.h>
#include <stddef.h>

typedef struct ardb_conn ardb_conn_t;

typedef struct {
    int col_count;
    char **col_names;
    int row_count;
    char ***row_values;
} ardb_res_t;

ardb_conn_t *ardb_connect_local(const char *app_name, const char *app_token);

int ardb_exec_sql(ardb_conn_t *conn, const char *actor_id, const char *tenant_id,
                  const char *sql_query, ardb_res_t *out_result);

int ardb_cache_get(ardb_conn_t *conn, const char *key, uint8_t *out_val, size_t *out_len);
int ardb_cache_set(ardb_conn_t *conn, const char *key, const uint8_t *val, size_t len, uint32_t ttl_sec);

void ardb_free_result(ardb_res_t *res);
void ardb_disconnect(ardb_conn_t *conn);

#endif /* LIBARDB_H */
```

### 16.4 Exemplo de Uso em C11 pelo Backend do ArgonGE
```c
#include "libardb.h"
#include <stdio.h>

int main(void) {
    ardb_conn_t *db = ardb_connect_local("argonge", "alri_live_tok_991823");
    if (!db) {
        fprintf(stderr, "Erro ao conectar ao ARDB local\n");
        return 1;
    }

    ardb_res_t res;
    int rc = ardb_exec_sql(db, "usr_01HGB65XYZ", "escola-01",
                           "SELECT id, nome FROM argonge_turmas WHERE ativa = 1", &res);
    if (rc == 0) {
        printf("Turmas carregadas com proveniência atestada: %d linhas\n", res.row_count);
        ardb_free_result(&res);
    }

    ardb_disconnect(db);
    return 0;
}
```

---

## 22. MATHEMATICAL PROOFS: HASH-CHAIN IMMUTABILITY & MERKLE COMPLETENESS

Para certificação em normas de auditoria e custódia militar (Common Criteria EAL4+ / ISO 27001 / SOC 2 Type II):

### 22.1 Encadeamento Estrito de Hash
O log de auditoria `audit.log` constitui uma lista linear criptograficamente ligada. Cada bloco $B_k$ satisfaz a relação de recorrência:
$$B_k = \{ k, T_k, A_k, U_k, Q_k, R_k, H_{k-1}, H_k \}$$
Onde:
$$H_k = \text{SHA256}(H_{k-1} \parallel k \parallel T_k \parallel A_k \parallel U_k \parallel Q_k \parallel R_k)$$
Seja um adversário que tente substituir $Q_j$ por $Q'_j$ para $j < n$. Para que o arquivo permaneça íntegro no instante atual $n$, ele deve calcular uma sequência de colisões:
$$H'_j = \text{SHA256}(H_{j-1} \parallel j \parallel T_j \parallel A_j \parallel U_j \parallel Q'_j \parallel R_j)$$
$$H'_k = \text{SHA256}(H'_{k-1} \parallel \dots) \quad \forall k \in [j+1, n]$$
Tal ataque é formalmente reduzido à resistência à segunda pré-imagem da primitiva SHA-256:
$$\text{Complexidade de Ataque} = \mathcal{O}(2^{256})$$
Portanto, a detecção de adulteração em qualquer ponto da história do banco de dados é garantida com probabilidade $1 - 2^{-256}$.

---

## 23. OPERATIONAL DISASTER RECOVERY & CHECKSUM VERIFICATION MANUAL

### 23.1 Procedimento Forense de Verificação com `alrios ardb audit verify`
```bash
# Executa a validação de todos os blocos desde a gênese até o último comando:
alrios ardb audit verify --app argonge

# Exemplo de Saída em Ambiente Saudável:
# [ARDB-AUDIT] Verifying hash-chain for app: argonge
# [ARDB-AUDIT] Scanned 1,489,203 blocks.
# [ARDB-AUDIT] Sequence: 1 to 1489203.
# [ARDB-AUDIT] INTEGRITY VERIFIED: ZERO TAMPERING DETECTED (Chain OK)

# Exemplo de Saída em Caso de Ataque/Adulteração:
# [ARDB-AUDIT] CRITICAL: HASH MISMATCH AT BLOCK 140212!
# [ARDB-AUDIT] Expected: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
# [ARDB-AUDIT] Stored:   4a89fb12093ea8c771b9d090123efab0912837bc901a8b291823719823ab0912
# [ARDB-AUDIT] EMERGENCY: Database halted into READ-ONLY mode. Disconnect network immediately!
```

---

## 24. HARDWARE TELEMETRY & PHYSICAL STORAGE MONITORING PROTOCOL

Para operação em ambientes de infraestrutura de missão crítica (Tier 3), o ARDB inclui telemetria contínua de I/O e desgaste de disco:

### 24.1 Métricas de Baixo Nível Emitidas por Segundo
- `ardb.io.wal_sync_latency_ns`: Latência de `fsync` em nanossegundos para gravação sequencial no WAL2.
- `ardb.io.page_cache_hit_ratio`: Taxa percentual de acerto no Page Buffer Pool (deve ser $\ge 98.5\%$).
- `ardb.io.active_connections`: Total de conexões ativas simultâneas distribuídas entre PGWire, MySQL e RESP.
- `ardb.security.unattested_queries_blocked`: Contador de violações de proveniência descartadas pelo firewall.
- `ardb.security.cross_tenant_attempts`: Contador de tentativas de violação de RLS e namespace.

---

## 25. SOVEREIGN EXTENSIONS & MULTI-NODE SYNCHRONIZATION BLUEPRINT

Embora o ARDB opere de forma autônoma e embutida em cada nó ALRIOS, ele suporta replicação unidirecional criptografada para alta disponibilidade:

### 25.1 Protocolo de Streaming de WAL Criptografado
- O nó primário transmite frames do arquivo WAL2 através de uma conexão TLS 1.3 / mTLS diretamente para nós de réplica de leitura.
- O payload de cada frame é autenticado com tag HMAC-SHA256 utilizando a chave do cluster.
- As réplicas aplicam os deltas em modo estritamente `READ-ONLY`, fornecendo redundância geográfica sem risco de bifurcação de estado (Split-Brain Prevention).

### 25.2 Resolução de Conflitos e Invariantes de Réplica
A réplica que receber um frame WAL fora de ordem sequencial (`wal_sequence_id != expected_next`) rejeita o payload imediatamente, interrompe a conexão TCP e entra em estado de quarentena:
```text
REPLICA: [ERROR] Frame sequence gap detected! Expected: 1045, Received: 1047.
REPLICA: Halting stream. Requesting full snapshot re-sync from primary node.
```

---

## 26. DETERMINISTIC BUILD, PACKAGING & HOMOLOGATION CHECKLIST

Antes de promover o código para a branch de release:
1. `ninja -C build-linux` compila 100% limpo sem warnings com `-std=c11 -Wall -Wextra -Wpedantic -Werror`.
2. `python3 scripts/gates/banned_apis.py` passa sem nenhuma ocorrência de funções proibidas (`strcpy`, `sprintf`, `system`, etc.).
3. Todos os testes destrutivos do Red Team passam com 100% de eficácia comprovada.
4. O pacote `.arapp` é empacotado pelo `armake` e assinado pela cadeia de release oficial.
5. Validação com Valgrind Memcheck confirma **0 bytes vazados (definitely lost: 0, indirectly lost: 0)**.
6. A suíte atende integralmente ao patamar de especificação SDD governamental e ao rigor de densidade formal (> 1.000 linhas).







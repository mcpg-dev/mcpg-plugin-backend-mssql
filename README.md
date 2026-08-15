# `mcpg-plugin-backend-mssql`

Microsoft SQL Server (TDS) backend binding plugin for mcpg (`kind: mssql`).
Runs a parameterised statement as MCP **tools** and **resources** — the
`@P1, @P2, …` placeholders are bound from CEL expressions evaluated against
the tool arguments (bound as SQL **parameters**, never string-interpolated,
so injection-safe), over a pooled tiberius connection.

Part of the legacy → MCP bridge suite. The
SQL-Server complement to the `sql` backend (Postgres / MySQL / SQLite),
which sqlx can't drive for MSSQL.

## How it works

One binding = one statement = one MCP tool (or resource). Per call:

1. Each `params[i]` CEL expression is evaluated against the call's
   `arguments` object, producing a value that is **bound** to `@P{i+1}`.
   Values cross the wire as TDS parameters — the statement text is
   operator-fixed and never templated from caller input, so a caller cannot
   alter the query (injection defense).
2. A pooled connection (rustls TLS) runs the statement: `op: query` returns
   the rows (each projected to JSON by column); `op: execute` returns the
   rows-affected count.
3. SQL rejections and transport failures become a structured
   `downstreamError` (the gateway's `isError` signal); connect / login /
   pool / timeout failures are marked retryable.

## Configuration

| Field | Type | Default | Notes |
|---|---|---|---|
| `host` | string (required) | — | SQL Server host. Operator-configured (not caller-templated). |
| `port` | int | `1433` | TDS port. |
| `database` | string (required) | — | Initial database. |
| `user` | string (required) | — | SQL Server login. |
| `password` | string (required) | — | A literal, or `${env.X}` / `vault://…` resolved at config load. Per-caller `cred://` is **not** supported. |
| `encryption` | `required`\|`off` | `required` | `off` still encrypts the login handshake (SQL Server always does), then continues cleartext. |
| `trust_server_certificate` | bool | `false` | Trust a self-signed / internal-CA server cert. |
| `query` | string (required) | — | Statement with `@P1, @P2, …` placeholders. Operator-fixed. |
| `op` | `query`\|`execute` | `query` | `query` → rows; `execute` → rows-affected. |
| `params` | `[string]` | `[]` | Ordered CEL expressions; `params[i]` → `@P{i+1}`. |
| `size_limit` | int | `100` | Client-side cap on returned rows (`query`). |
| `pool_max_size` | int | `8` | Max pooled connections for this binding. |
| `timeout_ms` | int | `10000` | acquire + query + read timeout. |

### As a tool

```yaml
mcp:
  capabilities:
    tools:
      - name: directory.find_employee
        description: Look up an employee by id.
        input_schema:
          type: object
          properties: { id: { type: integer } }
          required: [id]
        backend:
          kind: mssql
          host: "sql1.corp.example.com"
          database: "HR"
          user: "svc_mcpg"
          password: "${env.MSSQL_HR_PASSWORD}"
          trust_server_certificate: true
          op: query
          query: "SELECT id, full_name, email FROM dbo.employees WHERE id = @P1"
          params: ["arguments.id"]              # bound to @P1 — injection-safe
```

### As a write tool (`op: execute`)

```yaml
      backend:
        kind: mssql
        host: "sql1.corp.example.com"
        database: "HR"
        user: "svc_mcpg"
        password: "${env.MSSQL_HR_PASSWORD}"
        op: execute
        query: "UPDATE dbo.employees SET email = @P1 WHERE id = @P2"
        params: ["arguments.email", "arguments.id"]
```

## Response envelope

```jsonc
{
  "toolName": "directory.find_employee",
  "profile":  "directory.find_employee",
  "request":  { "host": "sql1.corp.example.com", "database": "HR", "op": "query" },
  "response": {                               // op: query
    "rows": [ { "id": 7, "full_name": "Alice", "email": "a@x" } ],
    "count": 1,
    "rowsAffected": null,
    "durationMs": 9
  },
  "downstreamError": null,        // non-null ⇒ isError:true (mssql_error / transport_error)
  "downstreamErrors": [],
  "error": null
}
```

`op: execute` instead populates `response.rowsAffected` (and `rows`/`count`
are null).

## Security

- **Parameter binding.** Caller data reaches the database only as bound TDS
  parameters (`@P1, …`), never concatenated into the statement — SQL
  injection is structurally impossible. The `query` text is operator-fixed.
- **No plaintext secrets.** The login `password` resolves through the
  gateway secret-resolver (`${env.X}` / `vault://…`); it is never committed.
- **`cred://` not supported.** The pool is per-binding (one service
  identity), so per-caller `cred://` is rejected at config validation — use
  a service account + the config secret-resolver. (Per-caller pooling, as
  the `sql` backend supports, is a possible follow-on.)
- **TLS.** rustls. Note: tiberius 0.12's `rustls` feature pulls the legacy
  `rustls 0.21` / `rustls-webpki 0.101` stack (native-tls is banned), the
  same transitive stack as `ldap3` — covered by the existing scoped
  `deny.toml` ignores (RUSTSEC-2026-0098/-0099/-0104). Revisit when tiberius
  ships on rustls 0.23.

## Build / test

```bash
nx build mcpg-plugin-backend-mssql
nx test  mcpg-plugin-backend-mssql                                    # unit tests
cargo test -p mcpg-plugin-backend-mssql --features integration-tests   # SQL Server (docker)
nx lint  mcpg-plugin-backend-mssql
```

## Scope / deferred

- **Per-caller credentials** (`cred://`, per-cred pooling) — v1 is one
  pooled service identity per binding.
- **Multi-result-set / output parameters** — v1 returns the first result set
  (`query`) or the rows-affected total (`execute`).
- **Oracle** — planned as a separate plugin (`odpi`/FFI).
- **Native modern-rustls** — pending a tiberius upstream release.

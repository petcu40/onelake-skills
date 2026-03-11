---
name: onelake-security-cli
description: >
  Manage OneLake security data access roles (table/folder-level, RLS, CLS) on Microsoft Fabric Lakehouses,
  Mirrored Databases, and Databricks Mirrored Catalogs from agentic CLI environments using az rest. Use when
  the user wants to: (1) list, create, update, or delete OneLake security roles from terminal, (2) configure
  row-level or column-level security via CLI, (3) audit or inspect existing data access roles, (4) generate
  reusable shell scripts for security provisioning, (5) troubleshoot access issues (user sees all/no data,
  RLS/CLS errors), (6) manage DefaultReader role or virtual memberships programmatically. Triggers: "onelake
  security", "data access role", "create security role", "RLS on lakehouse", "CLS columns", "list roles",
  "delete role", "who has access", "restrict table access", "hide PII columns", "DefaultReader", "manage
  lakehouse security from CLI", "security role script".
license: MIT
---

> **CRITICAL NOTES**
> 1. To find the workspace details (including its ID) from workspace name: list all workspaces and, then, use JMESPath filtering
> 2. To find the item details (including its ID) from workspace ID, item type, and item name: list all items of that type in that workspace and, then, use JMESPath filtering

# OneLake Security — CLI Skill

## Critical Rules — Read Before Every Operation

These rules are non-negotiable. Violating them causes data loss or errors.

**1. Always use POST upsert to create or update a single role — NEVER use bulk PUT for that purpose.**
- POST upsert: `POST .../dataAccessRoles?dataAccessRoleConflictPolicy=Overwrite` — affects only the named role, leaves all other roles untouched.
- Bulk PUT: `PUT .../dataAccessRoles` — **replaces ALL roles on the item**. Any role not in the payload is **permanently deleted**. Only use when deploying a complete role set from scratch.

**2. API paths use the role NAME (string), never the role ID (UUID).**
- ✅ Correct: `.../dataAccessRoles/DefaultReader`
- ❌ Wrong: `.../dataAccessRoles/22b64df5-5142-5fcc-55e4-d42a148795d9`
- The `id` field in list responses is for internal tracking only. Ignore it.

**3. Always write JSON payloads to a temp file and use `@file.json`.**
- ❌ `az rest --body '{"name":"..."}'` — breaks in PowerShell, fragile in bash with quotes/escapes.
- ✅ Write JSON to `/tmp/role.json`, then: `az rest --body @/tmp/role.json`

**4. RLS predicates require the full SELECT statement, and three fields must be coordinated.**
- The role's `permission[].Path` must include the table: `"/Tables/nyctlc"`
- The `constraints.rows[].tablePath` must match: `"/Tables/nyctlc"`
- The `constraints.rows[].value` must use the exact table name: `"SELECT * FROM nyctlc WHERE tripDistance>10"`
- ❌ `"WHERE tripDistance>10"` — missing `SELECT * FROM TableName`.
- ❌ Table name case mismatch between Delta log and SQL statement.
- See [ONELAKE-SECURITY-CORE.md](../../common/ONELAKE-SECURITY-CORE.md) §3.4 for full RLS syntax rules and examples, §6.7 for a complete worked example.

**5. Always `--resource "https://api.fabric.microsoft.com"` on `az rest`.**
- Without it, `az rest` does not inject the correct Fabric token → 401 Unauthorized.

**6. Role changes take ~5 minutes to propagate. Group membership changes take ~1 hour.**

---

## Prerequisite Knowledge

Read these companion documents — they contain foundational context:

- [COMMON-CORE.md](../../common/COMMON-CORE.md) — Fabric REST API patterns, authentication, token audiences, item discovery.
- [COMMON-CLI.md](../../common/COMMON-CLI.md) — `az rest`, `az login`, token acquisition, Fabric REST via CLI.
- [ONELAKE-SECURITY-CORE.md](../../common/ONELAKE-SECURITY-CORE.md) — Access control model, REST API reference, role payloads, RLS/CLS, engine enforcement, best practices, gotchas, common patterns.

---

## Table of Contents

| Task | Reference | Notes |
|---|---|---|
| Finding workspaces and items | [COMMON-CLI.md](../../common/COMMON-CLI.md) § Finding Workspaces and Items in Fabric | Get workspace ID and item ID first |
| Fabric topology, workspaces, items, OneLake | [COMMON-CORE.md](../../common/COMMON-CORE.md) § Fabric Topology & Key Concepts | Workspace → item → folder hierarchy |
| API endpoints and environment URLs | [COMMON-CORE.md](../../common/COMMON-CORE.md) § Environment URLs | Base: `https://api.fabric.microsoft.com/v1` |
| Authentication and token acquisition | [COMMON-CORE.md](../../common/COMMON-CORE.md) § Authentication & Token Acquisition | Scope: `https://api.fabric.microsoft.com/.default` |
| Control-plane REST APIs (item discovery) | [COMMON-CORE.md](../../common/COMMON-CORE.md) § Core Control-Plane REST APIs | List workspaces, list items to get IDs |
| OneLake data access (storage layer) | [COMMON-CORE.md](../../common/COMMON-CORE.md) § OneLake Data Access | DFS endpoint — separate from security API |
| Platform gotchas | [COMMON-CORE.md](../../common/COMMON-CORE.md) § Gotchas, Best Practices & Troubleshooting | Token expiry, 429 handling, pagination |
| Tool selection (az, curl, jq) | [COMMON-CLI.md](../../common/COMMON-CLI.md) § Tool Selection Rationale | `az rest` is primary — zero extra install |
| Authentication recipes | [COMMON-CLI.md](../../common/COMMON-CLI.md) § Authentication Recipes | `az login`, service principal, managed identity |
| `az rest` patterns for Fabric APIs | [COMMON-CLI.md](../../common/COMMON-CLI.md) § Fabric Control-Plane API via `az rest` | `az rest --method GET --resource <audience> --url <url>` |
| SQL / TDS data-plane access | [COMMON-CLI.md](../../common/COMMON-CLI.md) § SQL / TDS Data-Plane Access | SQL Endpoint must be in User's Identity mode |
| OneLake shortcuts | [COMMON-CLI.md](../../common/COMMON-CLI.md) § OneLake Shortcuts | Security flows through to shortcut target |
| CLI gotchas | [COMMON-CLI.md](../../common/COMMON-CLI.md) § Gotchas & Troubleshooting (CLI-Specific) | `--resource` required for token injection |
| Access control model (deny-by-default, roles, inheritance, ReadWrite, shortcuts) | [ONELAKE-SECURITY-CORE.md](../../common/ONELAKE-SECURITY-CORE.md) § 1. Access Control Model | **Read first** — workspace Admin/Member/Contributor bypass all roles |
| REST API reference — POST upsert (recommended), GET, DELETE, bulk PUT | [ONELAKE-SECURITY-CORE.md](../../common/ONELAKE-SECURITY-CORE.md) § 2. REST API Reference | POST upsert = safe default. Bulk PUT = dangerous, replaces all |
| Role payload structure (DecisionRule, Path, Members, RLS, CLS) | [ONELAKE-SECURITY-CORE.md](../../common/ONELAKE-SECURITY-CORE.md) § 3. Role Payload Anatomy | §3.4 has RLS anatomy showing how Path/tablePath/value connect, examples table, common mistakes |
| Engine enforcement and SQL endpoint modes | [ONELAKE-SECURITY-CORE.md](../../common/ONELAKE-SECURITY-CORE.md) § 4. Engine Enforcement and SQL Endpoint | Switch SQL Endpoint to User's Identity mode |
| Best practices, gotchas, troubleshooting, latency, limits | [ONELAKE-SECURITY-CORE.md](../../common/ONELAKE-SECURITY-CORE.md) § 5. Best Practices, Gotchas, and Monitoring | POST over PUT, roleName not roleId, @file.json for payloads |
| Common patterns (table, RLS, CLS, ReadWrite, end-to-end worked example) | [ONELAKE-SECURITY-CORE.md](../../common/ONELAKE-SECURITY-CORE.md) § 6. Common Patterns and Decision Guide | §6.7 has full worked example: user request → resolve identity → JSON → POST → verify |
| All `az rest` recipes (list, get, upsert, delete, RLS, CLS, audit) + end-to-end worked example | [cli-invocation-patterns.md](references/cli-invocation-patterns.md) | Starts with full worked example; POST upsert is the default; all payloads use @file.json |
| Bash/PowerShell script templates | [cli-invocation-patterns.md](references/cli-invocation-patterns.md) § Script Templates | Parameterized, with dry-run validation |
| Tool stack and connection setup | [§ Tool Stack and Connection](#tool-stack-and-connection) (below) | `az` CLI only — zero extra install |
| Agentic exploration/authoring workflow | [§ Agentic Workflows](#agentic-workflows) (below) | 5-step discover → inspect → build payload → apply → verify |
| Agent integration (Copilot CLI, Claude Code) | [§ Agent Integration](#agent-integration) (below) | Always write JSON to temp file before calling az rest |

---

## Tool Stack and Connection

| Tool | Role | Install |
|---|---|---|
| `az` CLI | **Primary**: Auth (`az login`), all security API calls via `az rest`, item discovery. | Pre-installed in most dev environments |
| `jq` | Parse/filter JSON responses. | Pre-installed or trivial |

> **Agent check** — verify before first operation:
> ```bash
> az version 2>/dev/null || echo "INSTALL: https://aka.ms/installazurecli"
> az account show >/dev/null 2>&1 || echo "RUN: az login"
> ```

### Connection Variables

```bash
WS_ID="<workspaceId>"
ITEM_ID="<lakehouseId>"
API="https://api.fabric.microsoft.com"
BASE="$API/v1/workspaces/$WS_ID/items/$ITEM_ID/dataAccessRoles"
```

### Quick Operations (safe one-liners)

```bash
# List all role names
az rest --method get --resource "$API" --url "$BASE" | jq '.value[].name'

# Get one role by NAME (not ID!)
az rest --method get --resource "$API" --url "$BASE/DefaultReader" | jq .

# Delete a role by NAME
az rest --method delete --resource "$API" --url "$BASE/ObsoleteRole"

# Upsert a role (write JSON to file first!)
cat > /tmp/role.json <<'EOF'
{
  "name": "SalesReaders",
  "decisionRules": [{
    "effect": "Permit",
    "permission": [
      {"attributeName": "Path", "attributeValueIncludedIn": ["/Tables/Sales"]},
      {"attributeName": "Action", "attributeValueIncludedIn": ["Read"]}
    ]
  }],
  "members": {
    "microsoftEntraMembers": [
      {"tenantId": "TENANT_ID", "objectId": "GROUP_OBJ_ID", "objectType": "Group"}
    ]
  }
}
EOF
az rest --method post --resource "$API" \
  --url "$BASE?dataAccessRoleConflictPolicy=Overwrite" \
  --headers "Content-Type=application/json" \
  --body @/tmp/role.json
```

For full recipes (RLS, CLS, audit, scripts): see [references/cli-invocation-patterns.md](references/cli-invocation-patterns.md).

---

## Agentic Workflows

### Exploration (Inspect Current Security)

1. **Discover item** → `az rest --method get --resource "$API" --url "$API/v1/workspaces/$WS_ID/items" | jq '.value[] | select(.type=="Lakehouse") | {id, displayName}'`
2. **List roles** → `az rest --method get --resource "$API" --url "$BASE" | jq '.value[] | {name, paths: .decisionRules[0].permission[0].attributeValueIncludedIn}'`
3. **Inspect one role** → `az rest --method get --resource "$API" --url "$BASE/<roleName>" | jq .`
4. **Summarize** → Present roles, paths, members, RLS/CLS to user.

### Authoring (Create/Modify Roles)

1. **Ask** → What tables/folders? What permission (Read or ReadWrite)? Any RLS/CLS? Which users/groups?
2. **Resolve Entra IDs** → `az ad group show --group "<name>" --query id -o tsv` or `az ad user show --id "<email>" --query id -o tsv`
3. **Build payload JSON** → Write to temp file (e.g., `/tmp/role.json`). See [ONELAKE-SECURITY-CORE.md](../../common/ONELAKE-SECURITY-CORE.md) § 3 for payload structure, § 6 for complete examples.
4. **Apply via POST upsert** → `az rest --method post --resource "$API" --url "$BASE?dataAccessRoleConflictPolicy=Overwrite" --headers "Content-Type=application/json" --body @/tmp/role.json`
5. **Verify** → `az rest --method get --resource "$API" --url "$BASE/<roleName>" | jq .`

> **NEVER use PUT to add or update a single role** — it replaces all roles. Use POST with `dataAccessRoleConflictPolicy=Overwrite`.

### Script Generation

When the user wants a reusable script:
1. Determine bash vs PowerShell.
2. Generate using templates from [references/cli-invocation-patterns.md](references/cli-invocation-patterns.md) § Script Templates.
3. **Always use `@file.json` pattern** for the payload — write JSON to a file, then pass the file to `az rest`.
4. Include `az login` check, dry run validation, apply, and verification steps.

---

## Agent Integration

### GitHub Copilot CLI / GitHub Copilot

- Generate `az rest` commands for security operations.
- Ensure generated commands always include `--resource "$API"` for token injection.
- **Always write JSON payloads to a temp file** and use `--body @file.json`.
- Use `--method post` with `dataAccessRoleConflictPolicy=Overwrite` for creating/updating roles.

### Claude Code / Cowork

- Use `bash` tool to execute `az rest` commands directly.
- **Always write JSON to a temp file first**, then call `az rest --body @/tmp/role.json`.
- For exploration: run the 4-step workflow above, read JSON, present summary.
- For authoring: build JSON, write to file, POST upsert, verify.
- Always verify `az account show` before first API call.

### Common Agent Pattern

```
User: "Restrict the Sales table to the EMEA team"
Agent:
1. az rest GET → list current roles (to understand existing state)
2. az ad group show → get EMEA group objectId and tenantId
3. Write role JSON to /tmp/role.json with:
   - Path: /Tables/Sales, Action: Read
   - RLS: "SELECT * FROM Sales WHERE Region='EMEA'"
   - Member: the EMEA group
4. az rest POST → upsert with Overwrite (safe — only touches this role)
5. az rest GET → verify the new role exists with correct config
6. Present summary to user
```

---

## CLI-Specific Gotchas

### MUST DO

- **Always `--resource "https://api.fabric.microsoft.com"`** on `az rest` — required for automatic token injection.
- **Always POST upsert for single-role operations** — never bulk PUT unless deploying a complete role set.
- **Always `--body @file.json`** — write JSON to temp file first. Inline JSON breaks in PowerShell and is fragile in bash.
- **Use role `name` in API paths** — never the `id` UUID.
- **`az login` first** — all operations use the logged-in session.
- **Wait ~5 minutes** after role changes before verifying access.

### AVOID

- **Bulk PUT for single-role changes** — risk of deleting all other roles.
- **Inline JSON in `--body '{...}'`** — especially in PowerShell. Use `@file.json`.
- **Using `id` field from list response in URL paths** — use `name` instead.
- **Assuming immediate effect** — role changes take ~5 min; group changes take ~1 hour.
- **RLS predicates without `SELECT * FROM TableName`** — the full statement is required.

### PREFER

- **POST upsert** (`dataAccessRoleConflictPolicy=Overwrite`) as the default write operation.
- **`@file.json`** for all payloads — write to temp, pass file reference.
- **`jq` for output filtering** — keeps agent context window clean.
- **Entra security groups** over individual objectIds — simpler management.

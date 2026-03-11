---
name: onelake-security-cli
description: >
  Manage OneLake security data access roles (table/folder-level, RLS, CLS) on Microsoft Fabric Lakehouses,
  Mirrored Databases, and Databricks Mirrored Catalogs from agentic CLI environments using az rest. Use when
  the user wants to: (1) list, create, update, or delete OneLake security roles from terminal, (2) configure
  row-level or column-level security via CLI, (3) audit or inspect existing data access roles, (4) generate
  reusable shell scripts for security provisioning, (5) troubleshoot access issues (user sees all/no data,
  RLS/CLS errors), (6) manage DefaultReader role or virtual memberships programmatically. Triggers: "onelake
  security", "data access role", "create role", "RLS on lakehouse", "CLS columns", "list roles",
  "delete role", "who has access", "restrict table access", "hide PII columns", "DefaultReader", "manage
  lakehouse security from CLI", "security role script".
---

> **CRITICAL NOTES**
> 1. To find the workspace details (including its ID) from workspace name: list all workspaces and, then, use JMESPath filtering
> 2. To find the item details (including its ID) from workspace ID, item type, and item name: list all items of that type in that workspace and, then, use JMESPath filtering
> 3. To create or update a single role: ALWAYS use POST upsert. NEVER use PUT.

# OneLake Security — CLI Skill

## Critical Rules — Read Before Every Operation

These rules are non-negotiable. Violating them causes data loss or errors.

**1. To create or update a single role: ALWAYS use POST upsert. NEVER use PUT.**
- ✅ POST upsert: `POST .../dataAccessRoles?dataAccessRoleConflictPolicy=Overwrite` — affects **only** the named role, leaves all other roles untouched.
- ❌ PUT: `PUT .../dataAccessRoles` — **replaces ALL roles on the item**. Any role not in the payload is **permanently deleted**.
- The PUT API exists only for full role-set deployment (CI/CD). It must NEVER be used to create or update a single role.
- See [§2.3 POST Upsert](../../common/ONELAKE-SECURITY-CORE.md#23-create-or-update-single-role-post--upsert--recommended-default) for the recommended API.

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
- See [§3.4 RLS Constraints](../../common/ONELAKE-SECURITY-CORE.md#34-rls-constraints) for full syntax rules, examples table, and common mistakes.

**5. Always `--resource "https://api.fabric.microsoft.com"` on `az rest`.**
- Without it, `az rest` does not inject the correct Fabric token → 401 Unauthorized.

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
| Finding workspaces and items | [COMMON-CLI.md § Finding Workspaces and Items](../../common/COMMON-CLI.md#finding-workspaces-and-items-in-fabric) | Get workspace ID and item ID first |
| **⭐ Create or update a single role (POST upsert)** | [ONELAKE-SECURITY-CORE.md § 2.3 POST Upsert ⭐](../../common/ONELAKE-SECURITY-CORE.md#23-create-or-update-single-role-post--upsert--recommended-default) | **⭐ ALWAYS USE THIS for create/update.** `POST ...?| Fabric topology, workspaces, items, OneLake | [COMMON-CORE.md § Fabric Topology](../../common/COMMON-CORE.md#fabric-topology-key-concepts) | Workspace → item → folder hierarchy |
| List all data access roles | [ONELAKE-SECURITY-CORE.md § 2.1 List Data Access Roles](../../common/ONELAKE-SECURITY-CORE.md#21-list-data-access-roles) | GET. Paginated via `continuationToken`. Role `id` field is internal — ignore it |
| Get a single role by name | [ONELAKE-SECURITY-CORE.md § 2.2 Get Single Data Access Role](../../common/ONELAKE-SECURITY-CORE.md#22-get-single-data-access-role) | GET by **role name** (string), never by UUID |
dataAccessRoleConflictPolicy=Overwrite`. Safe — only affects named role, never deletes others |
| Delete a single role | [ONELAKE-SECURITY-CORE.md § 2.4 Delete Single Role](../../common/ONELAKE-SECURITY-CORE.md#24-delete-single-role) | DELETE by **role name** (string), never by UUID |
| **⚠️ Bulk replace ALL roles (PUT) — DANGEROUS** | [ONELAKE-SECURITY-CORE.md § 2.5 Bulk Replace ⚠️](../../common/ONELAKE-SECURITY-CORE.md#25-bulk-replace-all-roles-put--dangerous--use-only-when-intended) | **⚠️ NEVER use this to create/update a single role. Replaces ALL roles. Omitted roles are DELETED.** CI/CD only |
| API endpoints and environment URLs | [COMMON-CORE.md § Environment URLs](../../common/COMMON-CORE.md#environment-urls) | Base: `https://api.fabric.microsoft.com/v1` |
| Authentication and token acquisition | [COMMON-CORE.md § Authentication](../../common/COMMON-CORE.md#authentication-token-acquisition) | Scope: `https://api.fabric.microsoft.com/.default` |
| Control-plane REST APIs (item discovery) | [COMMON-CORE.md § Core Control-Plane REST APIs](../../common/COMMON-CORE.md#core-control-plane-rest-apis) | List workspaces, list items to get IDs |
| OneLake data access (storage layer) | [COMMON-CORE.md § OneLake Data Access](../../common/COMMON-CORE.md#onelake-data-access) | DFS endpoint — separate from security API |
| Platform gotchas | [COMMON-CORE.md § Gotchas](../../common/COMMON-CORE.md#gotchas-best-practices-troubleshooting) | Token expiry, 429 handling, pagination |
| Tool selection (az, curl, jq) | [COMMON-CLI.md § Tool Selection](../../common/COMMON-CLI.md#tool-selection-rationale) | `az rest` is primary — zero extra install |
| Authentication recipes | [COMMON-CLI.md § Authentication Recipes](../../common/COMMON-CLI.md#authentication-recipes) | `az login`, service principal, managed identity |
| `az rest` patterns for Fabric APIs | [COMMON-CLI.md § Fabric Control-Plane API](../../common/COMMON-CLI.md#fabric-control-plane-api-via-az-rest) | `az rest --method GET --resource <audience> --url <url>` |
| SQL / TDS data-plane access | [COMMON-CLI.md § SQL / TDS](../../common/COMMON-CLI.md#sql-tds-data-plane-access) | SQL Endpoint must be in User's Identity mode |
| OneLake shortcuts | [COMMON-CLI.md § OneLake Shortcuts](../../common/COMMON-CLI.md#onelake-shortcuts) | Security flows through to shortcut target |
| CLI gotchas | [COMMON-CLI.md § Gotchas](../../common/COMMON-CLI.md#gotchas-troubleshooting-cli-specific) | `--resource` required for token injection |
| Access control model (deny-by-default, roles, inheritance, ReadWrite, shortcuts) | [ONELAKE-SECURITY-CORE.md § 1. Access Control Model](../../common/ONELAKE-SECURITY-CORE.md#1-access-control-model) | **Read first** — workspace Admin/Member/Contributor bypass all roles |
| API error codes | [ONELAKE-SECURITY-CORE.md § 2.6 Common Error Responses](../../common/ONELAKE-SECURITY-CORE.md#26-common-error-responses) | 404 ItemNotFound, 404 RoleNotFound, 412 PreconditionFailed, 409 Conflict, 429 Rate Limit |
| DecisionRule structure | [ONELAKE-SECURITY-CORE.md § 3.1 DecisionRule](../../common/ONELAKE-SECURITY-CORE.md#31-decisionrule) | Each rule needs exactly two PermissionScope objects: Path + Action |
| Path values (table/folder scoping) | [ONELAKE-SECURITY-CORE.md § 3.2 Path Values](../../common/ONELAKE-SECURITY-CORE.md#32-path-values) | Case-sensitive. `"*"` = all, `"/Tables/Name"` = specific table |
| Members (Entra ID + virtual) | [ONELAKE-SECURITY-CORE.md § 3.3 Members](../../common/ONELAKE-SECURITY-CORE.md#33-members) | `microsoftEntraMembers` (explicit) vs `fabricItemMembers` (virtual by permission) |
| **RLS constraints (row-level security)** | [ONELAKE-SECURITY-CORE.md § 3.4 RLS Constraints](../../common/ONELAKE-SECURITY-CORE.md#34-rls-constraints) | Three fields must coordinate: `permission[].Path`, `constraints.rows[].tablePath`, and `constraints.rows[].value` (`SELECT * FROM TableName WHERE ...`). Examples table + common mistakes |
| CLS constraints (column-level security) | [ONELAKE-SECURITY-CORE.md § 3.5 CLS Constraints](../../common/ONELAKE-SECURITY-CORE.md#35-cls-constraints) | Column names are **case-sensitive**. Only listed columns are visible |
| Combined RLS + CLS | [ONELAKE-SECURITY-CORE.md § 3.6 Combined RLS + CLS](../../common/ONELAKE-SECURITY-CORE.md#36-combined-rls-cls) | Must be in the **same role**. Splitting across roles causes query errors |
| Engine enforcement and SQL endpoint modes | [ONELAKE-SECURITY-CORE.md § 4. Engine Enforcement](../../common/ONELAKE-SECURITY-CORE.md#4-engine-enforcement-and-sql-endpoint) | Switch SQL Endpoint to User's Identity mode |
| Best practices, gotchas, troubleshooting, latency, limits | [ONELAKE-SECURITY-CORE.md § 5. Best Practices](../../common/ONELAKE-SECURITY-CORE.md#5-best-practices-gotchas-and-monitoring) | POST over PUT, roleName not roleId, @file.json for payloads |
| Common patterns (table, RLS, CLS, ReadWrite, end-to-end worked example) | [ONELAKE-SECURITY-CORE.md § 6. Common Patterns](../../common/ONELAKE-SECURITY-CORE.md#6-common-patterns-and-decision-guide) | §6.7 has full worked example: user request → resolve identity → JSON → POST → verify |
| All `az rest` recipes + end-to-end worked example | [cli-invocation-patterns.md](references/cli-invocation-patterns.md) | Starts with worked example; POST upsert is default; all payloads use @file.json |
| Bash/PowerShell script templates | [cli-invocation-patterns.md § Script Templates](references/cli-invocation-patterns.md#script-templates) | Parameterized, with dry-run validation |
| Tool stack and connection setup | [§ Tool Stack and Connection](#tool-stack-and-connection) (below) | `az` CLI only — zero extra install |
| Agentic exploration/authoring workflow | [§ Agentic Workflows](#agentic-workflows) (below) | 5-step discover → inspect → build payload → POST upsert → verify |
| Agent integration (Copilot CLI, Claude Code) | [§ Agent Integration](#agent-integration) (below) | Always write JSON to temp file; always POST, never PUT |

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

# Upsert a role — ALWAYS use POST, ALWAYS write JSON to file first
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

### Authoring (Create/Modify Roles) — ALWAYS POST, NEVER PUT

1. **Ask** → What tables/folders? What permission (Read or ReadWrite)? Any RLS/CLS? Which users/groups?
2. **Resolve Entra IDs** → `az ad group show --group "<name>" --query id -o tsv` or `az ad user show --id "<email>" --query id -o tsv`
3. **Build payload JSON** → Write to temp file (e.g., `/tmp/role.json`). See [§3 Role Payload Anatomy](../../common/ONELAKE-SECURITY-CORE.md#3-role-payload-anatomy) for structure, [§6 Common Patterns](../../common/ONELAKE-SECURITY-CORE.md#6-common-patterns-and-decision-guide) for complete examples.
4. **Apply via POST upsert** → `az rest --method post --resource "$API" --url "$BASE?dataAccessRoleConflictPolicy=Overwrite" --headers "Content-Type=application/json" --body @/tmp/role.json`
5. **Verify** → `az rest --method get --resource "$API" --url "$BASE/<roleName>" | jq .`

> **NEVER use PUT to add or update a single role** — PUT replaces ALL roles and deletes any not in the payload. Always use POST with `dataAccessRoleConflictPolicy=Overwrite`.

### Script Generation

When the user wants a reusable script:
1. Determine bash vs PowerShell.
2. Generate using templates from [cli-invocation-patterns.md § Script Templates](references/cli-invocation-patterns.md#script-templates).
3. **Always use `@file.json` pattern** for the payload — write JSON to a file, then pass the file to `az rest`.
4. **Always use POST** (`--method post`) with `dataAccessRoleConflictPolicy=Overwrite`.
5. Include `az login` check, apply, and verification steps.

---

## Agent Integration

### GitHub Copilot CLI / GitHub Copilot

- Generate `az rest` commands for security operations.
- Ensure generated commands always include `--resource "$API"` for token injection.
- **Always use `--method post`** with `dataAccessRoleConflictPolicy=Overwrite` for creating/updating roles. Never `--method put`.
- **Always write JSON payloads to a temp file** and use `--body @file.json`.

### Claude Code / Cowork

- Use `bash` tool to execute `az rest` commands directly.
- **Always write JSON to a temp file first**, then call `az rest --body @/tmp/role.json`.
- **Always use `--method post`** for creating/updating roles. Never `--method put`.
- For exploration: run the 4-step workflow above, read JSON, present summary.
- For authoring: build JSON, write to file, POST upsert, verify.
- Always verify `az account show` before first API call.

### Common Agent Pattern

```
User: "Create a role named demo for Aaron Merrill with access to just the nyctlc table, restricted to rows where tripDistance > 10"
Agent:
1. az ad user show → get Aaron's objectId and tenantId
2. Write role JSON to /tmp/role.json:
   - name: "demo"
   - Path: ["/Tables/nyctlc"], Action: ["Read"]
   - RLS tablePath: "/Tables/nyctlc"
   - RLS value: "SELECT * FROM nyctlc WHERE tripDistance>10"
   - Member: {tenantId, objectId, objectType: "User"}
3. az rest --method post → POST upsert with Overwrite (NEVER PUT)
4. az rest --method get → verify role "demo" exists
5. Present summary to user
```

---

## CLI-Specific Gotchas

### MUST DO

- **Always `--resource "https://api.fabric.microsoft.com"`** on `az rest` — required for automatic token injection.
- **Always use `--method post` with `dataAccessRoleConflictPolicy=Overwrite`** for creating or updating a single role. Never `--method put`.
- **Always `--body @file.json`** — write JSON to temp file first. Inline JSON breaks in PowerShell and is fragile in bash.
- **Use role `name` in API paths** — never the `id` UUID.
- **`az login` first** — all operations use the logged-in session.
- **Wait ~5 minutes** after role changes before verifying access.

### AVOID

- **`--method put` for single-role changes** — PUT replaces ALL roles; any role not in the payload is permanently deleted. Use `--method post` instead.
- **Inline JSON in `--body '{...}'`** — especially in PowerShell. Use `@file.json`.
- **Using `id` field from list response in URL paths** — use `name` instead.
- **Assuming immediate effect** — role changes take ~5 min; group changes take ~1 hour.
- **RLS predicates without `SELECT * FROM TableName`** — the full statement is required.

### PREFER

- **`--method post`** with `dataAccessRoleConflictPolicy=Overwrite` as the default write operation.
- **`@file.json`** for all payloads — write to temp, pass file reference.
- **`jq` for output filtering** — keeps agent context window clean.
- **Entra security groups** over individual objectIds — simpler management.

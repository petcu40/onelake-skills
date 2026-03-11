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

## Prerequisite Knowledge

Read these companion documents before first use — they contain foundational context this skill depends on. The **Knowledge Map** below tells you which section to read for each task.

- [COMMON-CORE.md](../../common/COMMON-CORE.md) — Fabric REST API patterns, authentication, token audiences, item discovery.
- [COMMON-CLI.md](../../common/COMMON-CLI.md) — `az rest`, `az login`, token acquisition, Fabric REST via CLI.
- [ONELAKE-SECURITY-CORE.md](../../common/ONELAKE-SECURITY-CORE.md) — Access control model, REST API reference, role payloads, RLS/CLS, engine enforcement, best practices, gotchas, common patterns.

This skill adds: **how to invoke** all OneLake security scenarios from an agentic terminal using `az rest` (zero additional tooling).

---

## Table of Contents

| Task | Reference | Notes |
|---|---|---|
| Finding workspaces and items in Fabric | [COMMON-CLI.md](../../common/COMMON-CLI.md) § Finding Workspaces and Items in Fabric | Get workspace ID and item ID before security operations |
| Fabric topology, workspaces, items, OneLake | [COMMON-CORE.md](../../common/COMMON-CORE.md) § Fabric Topology & Key Concepts | Understand workspace → item → folder hierarchy before security |
| API endpoints and environment URLs | [COMMON-CORE.md](../../common/COMMON-CORE.md) § Environment URLs | Base URL: `https://api.fabric.microsoft.com/v1` |
| Authentication and token acquisition | [COMMON-CORE.md](../../common/COMMON-CORE.md) § Authentication & Token Acquisition | Scope: `https://api.fabric.microsoft.com/.default` |
| Core control-plane REST APIs | [COMMON-CORE.md](../../common/COMMON-CORE.md) § Core Control-Plane REST APIs | Item discovery: list workspaces, list items |
| OneLake data access (storage layer) | [COMMON-CORE.md](../../common/COMMON-CORE.md) § OneLake Data Access | DFS endpoint for file/table reads — separate from security API |
| Job execution | [COMMON-CORE.md](../../common/COMMON-CORE.md) § Job Execution | Not directly related; included for completeness |
| Capacity management | [COMMON-CORE.md](../../common/COMMON-CORE.md) § Capacity Management | Capacity region must match for shortcuts |
| Platform gotchas | [COMMON-CORE.md](../../common/COMMON-CORE.md) § Gotchas, Best Practices & Troubleshooting | Token expiry, 429 handling, pagination patterns |
| Tool selection (az, curl, jq) | [COMMON-CLI.md](../../common/COMMON-CLI.md) § Tool Selection Rationale | `az rest` is the primary tool — zero extra install |
| Authentication recipes | [COMMON-CLI.md](../../common/COMMON-CLI.md) § Authentication Recipes | `az login`, service principal, managed identity |
| Fabric control-plane via `az rest` | [COMMON-CLI.md](../../common/COMMON-CLI.md) § Fabric Control-Plane API via `az rest` | Pattern: `az rest --method GET --resource <audience> --url <url>` |
| OneLake data access via `curl` | [COMMON-CLI.md](../../common/COMMON-CLI.md) § OneLake Data Access via `curl` | For reading files/tables after security is set |
| SQL / TDS data-plane access | [COMMON-CLI.md](../../common/COMMON-CLI.md) § SQL / TDS Data-Plane Access | SQL Endpoint must be in User's Identity mode for OneLake security |
| Job execution (CLI) | [COMMON-CLI.md](../../common/COMMON-CLI.md) § Job Execution | — |
| OneLake shortcuts | [COMMON-CLI.md](../../common/COMMON-CLI.md) § OneLake Shortcuts | Security flows through internal shortcuts to target |
| Capacity management (CLI) | [COMMON-CLI.md](../../common/COMMON-CLI.md) § Capacity Management | — |
| Composite recipes | [COMMON-CLI.md](../../common/COMMON-CLI.md) § Composite Recipes | Multi-step workflows combining discovery + security |
| CLI gotchas | [COMMON-CLI.md](../../common/COMMON-CLI.md) § Gotchas & Troubleshooting (CLI-Specific) | `--resource` required for `az rest` token injection |
| Quick reference | [COMMON-CLI.md](../../common/COMMON-CLI.md) § Quick Reference | Cheat sheet for common `az rest` patterns |
| Access control model (deny-by-default, roles, inheritance, multi-role resolution) | [ONELAKE-SECURITY-CORE.md](../../common/ONELAKE-SECURITY-CORE.md) § 1. Access Control Model | **Read first** — covers opt-in, DefaultReader, workspace override, RLS/CLS interaction, ReadWrite, shortcuts |
| REST API reference (all 5 operations) | [ONELAKE-SECURITY-CORE.md](../../common/ONELAKE-SECURITY-CORE.md) § 2. REST API Reference | Verbs, URLs, payloads, responses, error codes, doc bug on POST |
| Role payload anatomy (DecisionRule, Path, Members, RLS, CLS) | [ONELAKE-SECURITY-CORE.md](../../common/ONELAKE-SECURITY-CORE.md) § 3. Role Payload Anatomy | Path values are case-sensitive; CLS column names are case-sensitive |
| Engine enforcement and SQL endpoint modes | [ONELAKE-SECURITY-CORE.md](../../common/ONELAKE-SECURITY-CORE.md) § 4. Engine Enforcement and SQL Endpoint | Switch SQL Endpoint to User's Identity mode for OneLake security |
| Best practices, gotchas, troubleshooting, latency, limits, monitoring | [ONELAKE-SECURITY-CORE.md](../../common/ONELAKE-SECURITY-CORE.md) § 5. Best Practices, Gotchas, and Monitoring | Latency: ~5 min role changes, ~1h group changes. Max 250 roles/item |
| Common patterns and decision guide | [ONELAKE-SECURITY-CORE.md](../../common/ONELAKE-SECURITY-CORE.md) § 6. Common Patterns and Decision Guide | End-to-end JSON examples for table, RLS, CLS, ReadWrite, bulk PUT |
| `az rest` recipes for all security API operations | [cli-invocation-patterns.md](references/cli-invocation-patterns.md) | List, get, create, update, delete roles; RLS/CLS examples; audit query; script templates |
| Tool stack and connection setup | [§ Tool Stack and Connection](#tool-stack-and-connection) (below) | `az` CLI only — zero extra install |
| Agentic exploration workflow | [§ Agentic Workflows](#agentic-workflows) (below) | 5-step discovery → inspect → modify → verify → generate script |
| Agent integration notes | [§ Agent Integration](#agent-integration) (below) | GitHub Copilot CLI, Claude Code/Cowork patterns |
| OneLake security CLI gotchas | [§ CLI-Specific Gotchas](#cli-specific-gotchas) (below) | MUST DO, AVOID, PREFER for CLI invocations |

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
WS_ID="<workspaceId>"         # from az rest --url .../workspaces | jq
ITEM_ID="<lakehouseId>"       # from az rest --url .../workspaces/$WS_ID/items | jq
API="https://api.fabric.microsoft.com"
BASE="$API/v1/workspaces/$WS_ID/items/$ITEM_ID/dataAccessRoles"
```

Discover IDs — see [COMMON-CLI.md](../../common/COMMON-CLI.md) § Finding Workspaces and Items in Fabric.

### Quick Operations

```bash
# List all roles
az rest --method get --resource "$API" --url "$BASE" | jq '.value[].name'

# Get one role
az rest --method get --resource "$API" --url "$BASE/DefaultReader" | jq .

# Delete a role
az rest --method delete --resource "$API" --url "$BASE/ObsoleteRole"
```

For full recipes (upsert, bulk PUT, RLS, CLS, audit, scripts): see [references/cli-invocation-patterns.md](references/cli-invocation-patterns.md).

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
3. **Build payload** → Construct JSON per [ONELAKE-SECURITY-CORE.md](../../common/ONELAKE-SECURITY-CORE.md) § 3.
4. **Dry run (if bulk PUT)** → `az rest --method put ... --url "$BASE?dryRun=true" --body @payload.json`
5. **Apply** → POST (single role upsert) or PUT (bulk replace).
6. **Verify** → Re-list roles and confirm.

### Script Generation

When the user wants a reusable script:
1. Determine bash vs PowerShell.
2. Generate using templates from [references/cli-invocation-patterns.md](references/cli-invocation-patterns.md) § Script Templates.
3. Parameterize `WS_ID`, `ITEM_ID`, role JSON file path.
4. Include `az login` check, dry run validation, apply, and verification steps.

---

## Agent Integration

### GitHub Copilot CLI / GitHub Copilot

- Generate `az rest` one-liners for security operations.
- Use `gh copilot suggest -t shell "list onelake security roles"` to get starting commands.
- Ensure generated commands always include `--resource "$API"` for token injection.

### Claude Code / Cowork

- Use `bash` tool to execute `az rest` commands directly.
- For exploration: run the 4-step workflow above, read JSON, present summary.
- For authoring: build JSON payload, write to temp file, execute with `az rest --body @file.json`.
- Always verify `az account show` before first API call.
- After modifications: re-list roles and confirm changes applied.

### Common Agent Pattern

```
User: "Restrict the Sales table to the EMEA team only"
Agent:
1. az rest → list current roles
2. az ad group show → get EMEA group objectId
3. Build role JSON with /Tables/Sales + RLS WHERE Region='EMEA'
4. az rest POST → upsert role with Overwrite policy
5. az rest GET → verify role exists
6. Present summary to user
```

---

## CLI-Specific Gotchas

### MUST DO

- **Always `--resource "https://api.fabric.microsoft.com"`** on `az rest` — required for automatic token injection.
- **`az login` first** — all operations use the logged-in session.
- **Use `--body @file.json`** for large payloads — inline JSON with single quotes and special characters is error-prone in shells.
- **Dry run before bulk PUT** — `?dryRun=true` validates without applying.
- **Read before bulk PUT** — it's full-replacement; omitted roles are deleted.
- **Wait ~5 minutes** after role changes before verifying access — propagation latency.

### AVOID

- **Inline JSON with single quotes inside single-quoted strings** — use `@file.json` or escape carefully with `'\''`.
- **Forgetting `--resource`** on `az rest` — results in 401 Unauthorized (wrong or missing token).
- **Using bulk PUT for single-role changes** — risk of deleting other roles. Use POST upsert instead.
- **Assuming immediate effect** — role changes take ~5 min; group membership changes take ~1 hour.

### PREFER

- **POST upsert** (`dataAccessRoleConflictPolicy=Overwrite`) for single-role changes — safest incremental approach.
- **`jq` for output filtering** — keeps agent context window clean.
- **`@file.json`** over inline `--body '{...}'` — avoids shell escaping issues.
- **Entra security groups** over individual objectIds — simpler management, fewer API calls.

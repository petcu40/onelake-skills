# ONELAKE-SECURITY-CORE.md

> **Scope**: OneLake security — data access roles, table/folder-level security, row-level security (RLS), column-level security (CLS), and the REST APIs that manage them — for **Lakehouse** (primary, Read + ReadWrite), **Mirrored Database SQLEP** (Read), and **Azure Databricks Mirrored Catalog** (Read).
> This document is *language-agnostic* — no C#, Python, az CLI, PowerShell, or SDK references. Only raw REST API verbs, payloads, responses, and status codes.
>
> **Companion files**:
> - `COMMON-CORE.md` — Fabric REST API patterns, authentication, token audiences, item discovery.
> - `COMMON-CLI.md` — CLI invocation patterns (az rest, curl, etc.).

---

## 1. Access Control Model

### 1.1 Feature Status and Opt-In

OneLake security is in **public preview**. It is **disabled by default** and must be enabled **per item**. Once enabled on an item, it **cannot be turned off**.

When enabled on a Lakehouse, a `DefaultReader` role is automatically created with:
- Permission: `Read` on `*` (all data).
- Members: all users with `ReadAll` item permission (virtual membership).

This ensures existing users retain access. To restrict access, delete or modify the `DefaultReader` role.

**Supported Items**:

| Item | Status | Supported Permissions |
|---|---|---|
| Lakehouse | Public Preview | Read, ReadWrite |
| Azure Databricks Mirrored Catalog | Public Preview | Read |
| Mirrored Database | Public Preview | Read |

### 1.2 Role Structure

Each OneLake security role has four components:

- **Name**: Alphanumeric, starts with a letter, case-insensitive, max 128 characters, unique per item.
- **DecisionRules**: Array of permission rules. Each rule has an `effect` (only `Permit` supported), a `permission` scope (Path + Action), and optional `constraints` (RLS/CLS).
- **Members**: Entra ID identities (users, groups, service principals, managed identities) or Fabric item permission-based virtual members.
- **Permission**: `Read` (view data + metadata) or `ReadWrite` (read + write; Lakehouse only).

### 1.3 Deny-by-Default

All users start with **no access** to data. Access is granted only via explicit role membership. Users not in any role see no data in the item.

### 1.4 Workspace Role Override

Workspace Admin, Member, and Contributor roles **always have full read/write access** to OneLake data, bypassing all OneLake security roles including RLS and CLS. Only Viewer-level users (or users with item-level Read/ReadAll) are subject to OneLake security enforcement.

### 1.5 Permission Inheritance

Permissions on a folder inherit recursively to all files and subfolders. Granting access to `/Tables/schema1` grants access to all tables under that schema.

### 1.6 Traversal

Granting access to a subfolder automatically grants list/traverse access to all parent directories up to the root — but not to sibling files or folders.

### 1.7 Multi-Role Resolution

Multiple roles combine using **UNION** (least-restrictive) semantics:
- If Role1 grants access to TableA and Role2 grants access to TableB, the user sees both.
- RLS predicates across roles combine with `OR` (union of rows).
- CLS across roles combines as union of permitted columns.
- **Within a single role**: effective access = OLS ∩ CLS ∩ RLS (intersection).
- **Across roles**: effective access = (R1_ols ∩ R1_cls ∩ R1_rls) ∪ (R2_ols ∩ R2_cls ∩ R2_rls).

**Critical exception**: If two roles combine such that columns and rows aren't aligned across the queries, access is **blocked** entirely to prevent data leakage.

**CLS in SQL Endpoint**: Uses **DENY** semantic (intersection, not union). CLS in SQL Endpoint operates using intersection of all roles a user is in, not union.

### 1.8 ReadWrite Permission (Lakehouse Only)

- Includes all Read privileges.
- Allows write operations via Spark notebooks, OneLake File Explorer, and OneLake APIs.
- Does **not** allow writes via Lakehouse UX for Viewers.
- Only meaningful for Viewer-level users (Admin/Member/Contributor already have write access).
- Roles with ReadWrite cannot contain RLS or CLS constraints.
- Write actions: create/delete/rename folders and tables, upload/edit files, create/delete/rename shortcuts.

### 1.9 Shortcuts and OneLake Security

**Internal Shortcuts (OneLake → OneLake)**: Security flows through — the user's identity is evaluated against the **target** item's OneLake security roles. Defining roles on the shortcut itself is not allowed — define them on the target.

**Exception**: In DirectLake-on-SQL and T-SQL delegated identity mode, the item **owner's** identity is used instead of the calling user's. Use DirectLake-on-OneLake mode or T-SQL User's Identity mode for proper pass-through.

**External Shortcuts (S3, ADLS, Dataverse)**: Both conditions must be true for access: (1) the delegated connection credential has access to the external source, AND (2) the user has OneLake security permissions in the Fabric item. Users accessing external shortcuts also need Fabric `Read` permission on the item (not just OneLake security membership).

**Listing Behavior**: When listing a directory, internal shortcuts are always returned regardless of the user's target access. Access is checked only when the shortcut is opened/read.

---

## 2. REST API Reference

**Base URL**: `https://api.fabric.microsoft.com/v1`

**Required token audience**: `https://api.fabric.microsoft.com`

**Required delegated scopes**: `OneLake.Read.All` (for GET operations) or `OneLake.ReadWrite.All` (for mutating operations).

All APIs support **User**, **Service Principal**, and **Managed Identity** callers.

### 2.1 List Data Access Roles

```
GET /workspaces/{workspaceId}/items/{itemId}/dataAccessRoles
```

Optional query parameter: `continuationToken` (for pagination).

**Response** (200 OK):
```json
{
  "value": [
    {
      "name": "RoleName",
      "id": "uuid",
      "eTag": "string",
      "decisionRules": [ ... ],
      "members": { ... }
    }
  ],
  "continuationToken": "...",
  "continuationUri": "..."
}
```

Response header: `ETag` (for the collection).

Pagination: If `continuationToken` is present in the response, call again with `?continuationToken=<value>` until absent.

### 2.2 Get Single Data Access Role

```
GET /workspaces/{workspaceId}/items/{itemId}/dataAccessRoles/{roleName}
```

**Response** (200 OK): Returns the role object **directly** (not wrapped in `{ "value": [...] }`):
```json
{
  "name": "DefaultReader",
  "decisionRules": [ ... ],
  "members": { ... }
}
```

Response header: `ETag` (for this role).

Supports `If-Match` / `If-None-Match` request headers for conditional operations.

Error codes: `ItemNotFound`, `RoleNotFound`, `PreconditionFailed`.

### 2.3 Create or Update All Roles (Bulk PUT)

```
PUT /workspaces/{workspaceId}/items/{itemId}/dataAccessRoles
```

Optional query parameter: `dryRun=true` (validate without applying).

**Request body**: Full set of roles. This is a **declarative/replace-all** operation — roles not in the payload are **deleted**.
```json
{
  "value": [
    {
      "name": "SalesReaders",
      "decisionRules": [
        {
          "effect": "Permit",
          "permission": [
            { "attributeName": "Path", "attributeValueIncludedIn": ["/Tables/SalesData"] },
            { "attributeName": "Action", "attributeValueIncludedIn": ["Read"] }
          ]
        }
      ],
      "members": {
        "microsoftEntraMembers": [
          {
            "tenantId": "72f988bf-...",
            "objectId": "aabbccdd-...",
            "objectType": "Group"
          }
        ]
      }
    }
  ]
}
```

**Response**: 200 OK with `ETag` header. No body.

Supports `If-Match` / `If-None-Match` for optimistic concurrency.

**Warning**: This operation is **full replacement**. Any existing roles not included in the payload are deleted. Always read-before-write if preserving existing roles.

### 2.4 Create or Update Single Role (POST — Upsert)

```
POST /workspaces/{workspaceId}/items/{itemId}/dataAccessRoles
    ?dataAccessRoleConflictPolicy={Overwrite|Abort}
```

**Request body**:
```json
{
  "name": "AnalystReaders",
  "decisionRules": [ ... ],
  "members": { ... }
}
```

> **Documentation Bug**: The official documentation shows the request body wrapped in `{ "value": [...] }` and the response wrapped similarly. In practice, the **request body is the role object directly** (no wrapper) and the **response is the role object directly** (no `value` array). See the correction notes in the prompt that generated this document.

**Conflict policies**:
- `Overwrite`: Creates the role or replaces an existing role with the same name.
- `Abort`: Fails with `Conflict` (409) if a role with that name already exists.

**Response**: 200 OK (updated) or 201 Created (new). Headers: `ETag`, `Location`.

### 2.5 Delete Single Role

```
DELETE /workspaces/{workspaceId}/items/{itemId}/dataAccessRoles/{roleName}
```

**Response**: 200 OK (no body).

Error codes: `ItemNotFound`, `RoleNotFound`.

### 2.6 Common Error Responses

| Status | Error Code | Meaning |
|---|---|---|
| 404 | ItemNotFound | Workspace or item ID is invalid or caller lacks access. |
| 404 | RoleNotFound | The named role does not exist. |
| 412 | PreconditionFailed | ETag mismatch (`If-Match` / `If-None-Match`). |
| 409 | Conflict | Role already exists and conflict policy is `Abort`. |
| 429 | Too Many Requests | Rate limit hit. Respect `Retry-After` header (seconds). |

---

## 3. Role Payload Anatomy

### 3.1 DecisionRule

Each role contains one or more `decisionRules`. Each rule has:

- `effect`: Only `"Permit"` is supported.
- `permission`: Array of **exactly two** `PermissionScope` objects:
  - One with `attributeName: "Path"` — specifies which tables/folders.
  - One with `attributeName: "Action"` — specifies `Read`, `ReadWrite`, or both.
- `constraints` (optional): RLS and/or CLS restrictions.

### 3.2 Path Values

| Path Pattern | Meaning |
|---|---|
| `"*"` | All data (Tables + Files). |
| `"/Tables/TableName"` | A specific table. |
| `"/Tables/schema/TableName"` | A table within a schema. |
| `"/Tables/schema"` | All tables in a schema. |
| `"/Files/folder"` | A specific folder under Files/. |

Path values are **case-sensitive**.

### 3.3 Members

Two member types can coexist in a single role:

**microsoftEntraMembers** — explicit identity assignment:
```json
{
  "tenantId": "72f988bf-...",
  "objectId": "aabbccdd-...",
  "objectType": "User"  // User | Group | ServicePrincipal | ManagedIdentity
}
```

**fabricItemMembers** — virtual membership based on item permissions:
```json
{
  "itemAccess": ["ReadAll"],
  "sourcePath": "{workspaceId}/{itemId}"
}
```

`itemAccess` values: `Read`, `Write`, `Reshare`, `Execute`, `ReadAll`. Multiple values mean the user must have **all** listed permissions.

### 3.4 RLS Constraints

```json
"constraints": {
  "rows": [
    {
      "tablePath": "/Tables/SalesData",
      "value": "SELECT * FROM SalesData WHERE Region='EMEA'"
    }
  ]
}
```

- `tablePath`: Must match a table in the role's `Path` scope. Format: `/Tables/{optionalSchema}/{tableName}`.
- `value`: T-SQL SELECT with WHERE predicate. Max 1000 characters.
- Supported operators: `=`, `<>`, `>`, `>=`, `<`, `<=`, `IN`, `NOT`, `AND`, `OR`, `TRUE`, `FALSE`, `IS NULL`, `IS BLANK`.
- String comparison is **case-insensitive** using collation `Latin1_General_100_CI_AS_KS_WS_SC_UTF8`.
- Only applies to Delta parquet tables. Non-Delta objects are **fully blocked** when RLS is defined.

### 3.5 CLS Constraints

```json
"constraints": {
  "columns": [
    {
      "tablePath": "/Tables/Customers",
      "columnNames": ["Name", "Email", "Region"],
      "columnEffect": "Permit",
      "columnAction": ["Read"]
    }
  ]
}
```

- `columnNames`: Case-sensitive. Use `"*"` for all columns.
- Only listed columns are visible. Unlisted columns are hidden.
- Removing a column from one role does **not** deny it if another role grants it (except in SQL Endpoint where CLS uses deny/intersection semantic).

### 3.6 Combined RLS + CLS

RLS and CLS **must be in the same role**. Combining RLS from one role and CLS from another role on the same table causes query errors.

---

## 4. Engine Enforcement and SQL Endpoint

### 4.1 Engine Support Matrix

| Engine | RLS/CLS Filtering | Status |
|---|---|---|
| Lakehouse (Spark) | Yes | Public Preview |
| Spark Notebooks | Yes | Public Preview |
| SQL Analytics Endpoint (User's Identity mode) | Yes | Public Preview |
| Semantic Models (DirectLake on OneLake mode) | Yes | Public Preview |
| Eventhouse | No | Planned |
| Data Warehouse external tables | No | Planned |

Non-supported engines accessing RLS/CLS-protected data: access is **blocked** (not filtered).

SQL Analytics Endpoint must be switched to **User's Identity** mode for OneLake security enforcement. In Delegated Identity mode, SQL-level GRANT/REVOKE governs access instead.

### 4.2 SQL Analytics Endpoint Modes

**User's Identity mode** (recommended for OneLake security):
- Passes user's Entra ID to OneLake for permission checks.
- Table access governed entirely by OneLake security roles.
- SQL GRANT/REVOKE on tables is **ignored**.
- RLS/CLS/OLS all defined in OneLake.
- SQL permissions still work for non-data objects (views, procedures, functions).

**Delegated Identity mode** (traditional SQL security):
- Uses workspace/item owner identity for OneLake access.
- Security governed by SQL GRANT/REVOKE, custom roles, SQL RLS, Dynamic Data Masking.
- OneLake security roles are **not evaluated** per-user.

**Requirement**: For OneLake security to work with SQL Endpoint, each user in a OneLake security role must also have Fabric `Read` permission on the Lakehouse.

---

## 5. Best Practices, Gotchas, and Monitoring

### 5.1 Security Architecture

- **Centralize data and security in a primary workspace.** Define OneLake security roles at the source Lakehouse. Share data to downstream workspaces via shortcuts — security policies flow automatically.
- **Use Entra security groups** for role membership, not individual users. Easier to manage and audit.
- **Prefer OneLake security over compute-level permissions** (SQL GRANT, Power BI RLS). OneLake security enforces consistently across all engines.
- **Use the `dryRun=true` parameter** on the bulk PUT API to validate role definitions before applying them.
- **Use ETag-based concurrency** (`If-Match`) on PUT operations to prevent race conditions when multiple administrators modify roles.
- **Keep the DefaultReader role under review.** It grants all `ReadAll` users full access. Delete it or narrow its scope when restricting access.

### 5.2 RLS Design

- Prefer **integer columns and `=` operators** for RLS predicates — most performant and least ambiguous.
- Avoid string comparisons with unknown formats, especially with unicode or accent-sensitive data.
- Keep predicates simple and under 1000 characters.
- Test predicates against the actual table schema — mismatched column names result in **no rows returned** or query errors.
- Remember: RLS string evaluation is **case-insensitive** (`Latin1_General_100_CI_AS_KS_WS_SC_UTF8`).

### 5.3 CLS Design

- Column names in CLS are **case-sensitive**. Ensure exact match with Delta log schema.
- CLS in SQL Endpoint uses **deny/intersection** semantics (stricter than other engines which use union).
- If a `SELECT *` is run on a CLS-protected table: Spark shows only permitted columns; SQL Endpoint and Semantic Models block column access entirely.

### 5.4 Principle of Least Privilege

- Only assign workspace roles (Admin/Member/Contributor) to users who need full access.
- For read-only consumers, grant Viewer workspace role + specific OneLake security roles.
- For write access without item management, use ReadWrite OneLake security roles (Lakehouse only).
- Use item-level sharing (`Read`/`ReadAll`) instead of workspace roles when users need access to a single item.

### 5.5 MUST DO

- **Enable OneLake security per item** — it is off by default. Once enabled, it cannot be disabled.
- **Remove users from DefaultReader** if they are also in a custom role that restricts access — DefaultReader grants full access and overrides restrictions.
- **Switch SQL Analytics Endpoint to User's Identity mode** for OneLake security to apply.
- **Include Fabric `Read` permission** for each user in a OneLake security role when using SQL Analytics Endpoint.
- **Use `dryRun=true`** before bulk PUT to validate role changes.
- **Read before write** on the bulk PUT API — it replaces all roles. Omitting an existing role deletes it.

### 5.6 AVOID

- **Distribution lists** in role membership — SQL Endpoint cannot resolve their members. Use Entra security groups instead.
- **Cross-region shortcuts** with OneLake security — results in 404 errors. Keep data and shortcuts in the same region.
- **Mixed-mode queries** — queries that access both OneLake-security-enabled and non-enabled items in a single query will fail.
- **RLS and CLS in separate roles on the same table** — causes query errors. Combine them in a single role.
- **Applying RLS/CLS to ReadWrite roles** — not supported. ReadWrite roles cannot have constraints.
- **Relying on metadata being hidden** — OneLake security doesn't guarantee table/column metadata won't appear in error messages or system views, even if data is blocked.
- **Private Link with OneLake security** — currently not compatible.
- **External Data Sharing** with OneLake security enabled — existing external shares may stop working.

### 5.7 PREFER

- **Entra security groups** over individual user assignments for scalability.
- **Single-role upsert (POST)** over bulk PUT for incremental changes — avoids accidentally deleting roles.
- **OneLake security** over SQL-level GRANT/REVOKE for consistent cross-engine enforcement.
- **Integer-based RLS predicates** over string comparisons for performance and reliability.
- **User's Identity mode** for SQL Analytics Endpoint when OneLake security is enabled.
- **DirectLake on OneLake mode** (not DirectLake on SQL) for Power BI to ensure user identity pass-through.

### 5.8 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| User sees all data despite custom role | DefaultReader still active with `ReadAll` membership | Delete DefaultReader or remove `ReadAll` virtual members |
| User sees no data | Not a member of any role (deny-by-default) | Add user to a role via API or portal |
| RLS returns no rows | Predicate references non-existent column or table name mismatch | Verify column names match Delta log schema exactly |
| CLS query error | RLS in one role + CLS in another role on same table | Combine RLS and CLS in a single role |
| 404 on shortcut access | Cross-region shortcut | Keep source and target in same capacity region |
| SQL Endpoint ignores OneLake roles | Endpoint in Delegated Identity mode | Switch to User's Identity mode |
| Group members not reflected | Entra group change propagation delay | Wait ~1 hour; some engines add another hour |
| Role changes not applied | Role definition propagation latency | Wait ~5 minutes |
| 412 PreconditionFailed | ETag mismatch on PUT | Re-read the current ETag and retry |
| 429 Too Many Requests | Rate limit exceeded | Respect `Retry-After` header; add backoff |
| Bulk PUT deleted a role | Role omitted from payload | Always read all roles first, modify, then PUT the full set |
| External shortcut access denied | User lacks Fabric `Read` permission on item | Grant `Read` permission in addition to OneLake role |

### 5.9 Latency and Propagation

| Change Type | Propagation Time |
|---|---|
| Role definition changes (create/update/delete) | ~5 minutes |
| Entra group membership changes | ~1 hour for OneLake; some engines add another hour |
| Virtual membership (item permission changes) | ~5 minutes (follows role definition propagation) |

Plan role deployments accordingly — avoid assuming immediate effect. For testing, wait the full propagation window before verifying access.

### 5.10 Limits

| Resource | Limit |
|---|---|
| Max roles per item | 250 (can request increase to 1000 via Azure Support) |
| Max members per role | 500 users or groups |
| Max permissions (decision rules) per role | 500 |
| Max RLS predicate length | 1000 characters |
| Role name max length | 128 characters |

### 5.11 Monitoring and Debuggability

**Verifying Effective Access**: There is no dedicated "test effective access" API. To debug:

1. **List roles**: `GET .../dataAccessRoles` — enumerate all roles and their path scopes.
2. **Get specific role**: `GET .../dataAccessRoles/{roleName}` — inspect members and constraints.
3. **Check item permissions**: Use Fabric Items API (`GET /workspaces/{wsId}/items/{itemId}`) and workspace roles to understand the user's control-plane permissions.
4. **Test with a Viewer account**: Create a test user with only Viewer/ReadAll access and verify access from Spark, SQL Endpoint, or the OneLake API.

**Auditing**: OneLake security role management operations (create, update, delete) appear in the **Microsoft Fabric audit log** (via Microsoft Purview compliance portal or Office 365 Management API). Look for operations on `dataAccessRoles`. Data access events (reads, writes) are logged through standard Fabric audit channels. Cross-reference with role definitions to audit who accessed what data.

**Debugging RLS/CLS**:
- If RLS returns 0 rows, the predicate likely has a column name or table name mismatch with the actual Delta log schema.
- If CLS blocks all columns, check for column name case mismatch (CLS column names are case-sensitive).
- If queries fail with "unsupported role combination" errors, check for RLS + CLS split across roles on the same table.
- Use `dryRun=true` on PUT to catch payload errors before applying.

---

## 6. Common Patterns and Decision Guide

### 6.1 Table-Level Access (Read)

Grant a group access to specific tables:
```
PUT .../dataAccessRoles
{
  "value": [{
    "name": "SalesTeam",
    "decisionRules": [{
      "effect": "Permit",
      "permission": [
        { "attributeName": "Path", "attributeValueIncludedIn": ["/Tables/Sales", "/Tables/Products"] },
        { "attributeName": "Action", "attributeValueIncludedIn": ["Read"] }
      ]
    }],
    "members": {
      "microsoftEntraMembers": [
        { "tenantId": "...", "objectId": "...", "objectType": "Group" }
      ]
    }
  }]
}
```

### 6.2 Table with RLS

```
POST .../dataAccessRoles?dataAccessRoleConflictPolicy=Overwrite
{
  "name": "EMEAAnalysts",
  "decisionRules": [{
    "effect": "Permit",
    "permission": [
      { "attributeName": "Path", "attributeValueIncludedIn": ["/Tables/Sales"] },
      { "attributeName": "Action", "attributeValueIncludedIn": ["Read"] }
    ],
    "constraints": {
      "rows": [{
        "tablePath": "/Tables/Sales",
        "value": "SELECT * FROM Sales WHERE Region='EMEA'"
      }]
    }
  }],
  "members": {
    "microsoftEntraMembers": [
      { "tenantId": "...", "objectId": "...", "objectType": "Group" }
    ]
  }
}
```

### 6.3 Table with CLS (Hide PII)

```
POST .../dataAccessRoles?dataAccessRoleConflictPolicy=Overwrite
{
  "name": "ExternalPartners",
  "decisionRules": [{
    "effect": "Permit",
    "permission": [
      { "attributeName": "Path", "attributeValueIncludedIn": ["/Tables/Customers"] },
      { "attributeName": "Action", "attributeValueIncludedIn": ["Read"] }
    ],
    "constraints": {
      "columns": [{
        "tablePath": "/Tables/Customers",
        "columnNames": ["CustomerId", "Region", "Segment"],
        "columnEffect": "Permit",
        "columnAction": ["Read"]
      }]
    }
  }],
  "members": {
    "microsoftEntraMembers": [
      { "tenantId": "...", "objectId": "...", "objectType": "Group" }
    ]
  }
}
```

### 6.4 Combined RLS + CLS in One Role

```json
{
  "name": "RestrictedAnalysts",
  "decisionRules": [{
    "effect": "Permit",
    "permission": [
      { "attributeName": "Path", "attributeValueIncludedIn": ["/Tables/Sales"] },
      { "attributeName": "Action", "attributeValueIncludedIn": ["Read"] }
    ],
    "constraints": {
      "rows": [{
        "tablePath": "/Tables/Sales",
        "value": "SELECT * FROM Sales WHERE Amount > 1000"
      }],
      "columns": [{
        "tablePath": "/Tables/Sales",
        "columnNames": ["SaleId", "Product", "Amount", "Region"],
        "columnEffect": "Permit",
        "columnAction": ["Read"]
      }]
    }
  }],
  "members": { ... }
}
```

### 6.5 ReadWrite Role (Lakehouse)

```json
{
  "name": "DataEngineers",
  "decisionRules": [{
    "effect": "Permit",
    "permission": [
      { "attributeName": "Path", "attributeValueIncludedIn": ["/Tables/Staging", "/Files/raw"] },
      { "attributeName": "Action", "attributeValueIncludedIn": ["ReadWrite"] }
    ]
  }],
  "members": {
    "microsoftEntraMembers": [
      { "tenantId": "...", "objectId": "...", "objectType": "Group" }
    ]
  }
}
```

No RLS/CLS allowed on ReadWrite roles.

### 6.6 Safe Read-Modify-Write Pattern (Bulk PUT)

1. `GET .../dataAccessRoles` → read all roles, capture `ETag` from response header.
2. Modify the `value` array (add/update/remove roles).
3. `PUT .../dataAccessRoles` with `If-Match: "<ETag>"` header and updated `value` array.
4. If 412 PreconditionFailed, re-read and retry.

This prevents accidental deletion and handles concurrent modifications.

### 6.7 Decision Guide

| Scenario | Recommended Approach |
|---|---|
| Restrict table access for Viewers | OneLake security role with specific `/Tables/...` paths |
| Hide sensitive columns | CLS constraint in the same role that grants table access |
| Filter rows by region/department | RLS constraint with `WHERE Region='...'` predicate |
| Grant write access to Viewers | ReadWrite role on specific folders/tables (Lakehouse only) |
| Share data to downstream workspace | Create shortcuts in downstream; security flows from source |
| Manage many roles programmatically | Use single-role POST (upsert) with `Overwrite` policy |
| Bulk deploy all roles | Use PUT with `dryRun=true` first, then PUT with `If-Match` |
| Test role changes | `dryRun=true` on PUT; test with a Viewer-level account |
| Audit role definitions | `GET .../dataAccessRoles` + Microsoft Fabric audit log |

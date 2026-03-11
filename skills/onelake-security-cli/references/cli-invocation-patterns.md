# OneLake Security — CLI Invocation Patterns

All operations use `az rest`. Requires `az login` with Admin or Member workspace role.

**Reusable variables** (set once per session):
```bash
WS_ID="<workspaceId>"
ITEM_ID="<lakehouseId>"
API="https://api.fabric.microsoft.com/v1"
BASE="$API/workspaces/$WS_ID/items/$ITEM_ID/dataAccessRoles"
```

> **CRITICAL**: Always use `--resource "$API"` on every `az rest` call for token injection.
> **CRITICAL**: Always write JSON payloads to a temp file and use `--body @file.json`. Never use inline JSON.
> **CRITICAL**: API paths use role **name** (string), never role **id** (UUID).

---

## End-to-End Worked Example

**User request**: "Create a role named `demo` for Aaron Merrill with access to just the `nyctlc` table, restricted to rows where `tripDistance` > 10."

```bash
# Step 1: Resolve user's Entra object ID
USER_OID=$(az ad user show --id "AaronMerrill@contoso.com" --query id -o tsv)
TENANT_ID=$(az account show --query tenantId -o tsv)
echo "User: $USER_OID  Tenant: $TENANT_ID"

# Step 2: Write the role JSON to a temp file
#   - Path /Tables/nyctlc → grants access to the table
#   - tablePath /Tables/nyctlc → must match Path above
#   - value "SELECT * FROM nyctlc WHERE tripDistance>10" → table name must match Delta log exactly
cat > /tmp/role_demo.json <<EOF
{
  "name": "demo",
  "decisionRules": [
    {
      "effect": "Permit",
      "permission": [
        {"attributeName": "Path", "attributeValueIncludedIn": ["/Tables/nyctlc"]},
        {"attributeName": "Action", "attributeValueIncludedIn": ["Read"]}
      ],
      "constraints": {
        "rows": [
          {
            "tablePath": "/Tables/nyctlc",
            "value": "SELECT * FROM nyctlc WHERE tripDistance>10"
          }
        ]
      }
    }
  ],
  "members": {
    "microsoftEntraMembers": [
      {"tenantId": "$TENANT_ID", "objectId": "$USER_OID", "objectType": "User"}
    ]
  }
}
EOF

# Step 3: Create the role via POST upsert (safe — only touches this role)
az rest --method post --resource "$API" \
  --url "$BASE?dataAccessRoleConflictPolicy=Overwrite" \
  --headers "Content-Type=application/json" \
  --body @/tmp/role_demo.json

# Step 4: Verify (by role NAME, not ID)
az rest --method get --resource "$API" --url "$BASE/demo" | jq .
```

The three fields that must stay coordinated:
```
permission[0].attributeValueIncludedIn  →  ["/Tables/nyctlc"]        ← grants table access
constraints.rows[0].tablePath           →  "/Tables/nyctlc"          ← must match Path
constraints.rows[0].value               →  "SELECT * FROM nyctlc WHERE tripDistance>10"
                                             ↑ table name must exactly match Delta log
```

---

## Create or Update a Single Role (POST Upsert) — DEFAULT OPERATION

This is the **safe, recommended** way to create or modify a role. It only affects the named role and never deletes other roles.

### Table-Level Read Access

```bash
cat > /tmp/role.json <<'EOF'
{
  "name": "SalesReaders",
  "decisionRules": [{
    "effect": "Permit",
    "permission": [
      {"attributeName": "Path", "attributeValueIncludedIn": ["/Tables/Sales", "/Tables/Products"]},
      {"attributeName": "Action", "attributeValueIncludedIn": ["Read"]}
    ]
  }],
  "members": {
    "microsoftEntraMembers": [
      {"tenantId": "YOUR_TENANT_ID", "objectId": "GROUP_OBJECT_ID", "objectType": "Group"}
    ]
  }
}
EOF

az rest --method post --resource "$API" \
  --url "$BASE?dataAccessRoleConflictPolicy=Overwrite" \
  --headers "Content-Type=application/json" \
  --body @/tmp/role.json
```

### Role with RLS (Row-Level Security)

```bash
cat > /tmp/role_rls.json <<'EOF'
{
  "name": "EMEAAnalysts",
  "decisionRules": [{
    "effect": "Permit",
    "permission": [
      {"attributeName": "Path", "attributeValueIncludedIn": ["/Tables/Sales"]},
      {"attributeName": "Action", "attributeValueIncludedIn": ["Read"]}
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
      {"tenantId": "YOUR_TENANT_ID", "objectId": "EMEA_GROUP_ID", "objectType": "Group"}
    ]
  }
}
EOF

az rest --method post --resource "$API" \
  --url "$BASE?dataAccessRoleConflictPolicy=Overwrite" \
  --headers "Content-Type=application/json" \
  --body @/tmp/role_rls.json
```

**More RLS predicate examples** (the `value` field):
```
"SELECT * FROM Sales WHERE Region='EMEA'"
"SELECT * FROM Transactions WHERE Amount>50000"
"SELECT * FROM Orders WHERE Region='US' AND Status='Active'"
"SELECT * FROM Customers WHERE Country='DE' OR Country='FR'"
"SELECT * FROM Products WHERE Category IN ('Electronics','Furniture')"
"SELECT * FROM Employees WHERE Department<>'HR'"
"SELECT * FROM Leads WHERE AssignedTo IS NOT NULL"
"SELECT * FROM [gold].[FactSales] WHERE Year=2025"
```

RLS rules: (1) always start with `SELECT * FROM TableName WHERE ...`, (2) table name must exactly match Delta log (case-sensitive), (3) max 1000 chars, (4) no LIKE, BETWEEN, or subqueries.

### Role with CLS (Column-Level Security — Hide PII)

```bash
cat > /tmp/role_cls.json <<'EOF'
{
  "name": "NoPII",
  "decisionRules": [{
    "effect": "Permit",
    "permission": [
      {"attributeName": "Path", "attributeValueIncludedIn": ["/Tables/Customers"]},
      {"attributeName": "Action", "attributeValueIncludedIn": ["Read"]}
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
      {"tenantId": "YOUR_TENANT_ID", "objectId": "PARTNERS_GROUP_ID", "objectType": "Group"}
    ]
  }
}
EOF

az rest --method post --resource "$API" \
  --url "$BASE?dataAccessRoleConflictPolicy=Overwrite" \
  --headers "Content-Type=application/json" \
  --body @/tmp/role_cls.json
```

CLS: Only listed `columnNames` are visible. Unlisted columns are hidden. Column names are **case-sensitive**.

### Role with Combined RLS + CLS (Must Be Same Role)

```bash
cat > /tmp/role_rls_cls.json <<'EOF'
{
  "name": "RestrictedAnalysts",
  "decisionRules": [{
    "effect": "Permit",
    "permission": [
      {"attributeName": "Path", "attributeValueIncludedIn": ["/Tables/Sales"]},
      {"attributeName": "Action", "attributeValueIncludedIn": ["Read"]}
    ],
    "constraints": {
      "rows": [{
        "tablePath": "/Tables/Sales",
        "value": "SELECT * FROM Sales WHERE Amount>1000"
      }],
      "columns": [{
        "tablePath": "/Tables/Sales",
        "columnNames": ["SaleId", "Product", "Amount", "Region"],
        "columnEffect": "Permit",
        "columnAction": ["Read"]
      }]
    }
  }],
  "members": {
    "microsoftEntraMembers": [
      {"tenantId": "YOUR_TENANT_ID", "objectId": "ANALYSTS_GROUP_ID", "objectType": "Group"}
    ]
  }
}
EOF

az rest --method post --resource "$API" \
  --url "$BASE?dataAccessRoleConflictPolicy=Overwrite" \
  --headers "Content-Type=application/json" \
  --body @/tmp/role_rls_cls.json
```

RLS + CLS must be in the **same role**. Splitting them across roles causes query errors.

### ReadWrite Role (Lakehouse Only)

```bash
cat > /tmp/role_rw.json <<'EOF'
{
  "name": "DataEngineers",
  "decisionRules": [{
    "effect": "Permit",
    "permission": [
      {"attributeName": "Path", "attributeValueIncludedIn": ["/Tables/Staging", "/Files/raw"]},
      {"attributeName": "Action", "attributeValueIncludedIn": ["ReadWrite"]}
    ]
  }],
  "members": {
    "microsoftEntraMembers": [
      {"tenantId": "YOUR_TENANT_ID", "objectId": "ENG_GROUP_ID", "objectType": "Group"}
    ]
  }
}
EOF

az rest --method post --resource "$API" \
  --url "$BASE?dataAccessRoleConflictPolicy=Overwrite" \
  --headers "Content-Type=application/json" \
  --body @/tmp/role_rw.json
```

No RLS/CLS allowed on ReadWrite roles.

---

## List All Roles

```bash
az rest --method get --resource "$API" --url "$BASE" | jq '.value[].name'
```

Detailed summary:
```bash
az rest --method get --resource "$API" --url "$BASE" | jq '.value[] | {
  name,
  paths: .decisionRules[0].permission[0].attributeValueIncludedIn,
  actions: .decisionRules[0].permission[1].attributeValueIncludedIn,
  hasRLS: (.decisionRules[0].constraints.rows // [] | length > 0),
  hasCLS: (.decisionRules[0].constraints.columns // [] | length > 0),
  entraMembers: (.members.microsoftEntraMembers // [] | length),
  virtualMembers: (.members.fabricItemMembers // [] | length)
}'
```

---

## Get Single Role (by NAME, not ID)

```bash
az rest --method get --resource "$API" --url "$BASE/DefaultReader" | jq .
```

Returns the role object directly (no `value` wrapper).

---

## Delete Single Role (by NAME)

```bash
az rest --method delete --resource "$API" --url "$BASE/ObsoleteRole"
```

---

## PowerShell Patterns

PowerShell requires special handling for JSON payloads. **Always write to a temp file.**

### Upsert a Role (PowerShell)

```powershell
$API = "https://api.fabric.microsoft.com/v1"
$BASE = "$API/workspaces/$env:WS_ID/items/$env:ITEM_ID/dataAccessRoles"

# Write payload to temp file — NEVER use inline JSON in PowerShell with az rest
$roleJson = @'
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
      {"tenantId": "YOUR_TENANT_ID", "objectId": "GROUP_ID", "objectType": "Group"}
    ]
  }
}
'@
$tmpFile = [System.IO.Path]::GetTempFileName() + ".json"
$roleJson | Out-File -FilePath $tmpFile -Encoding UTF8

az rest --method post --resource $API `
  --url "$BASE`?dataAccessRoleConflictPolicy=Overwrite" `
  --headers "Content-Type=application/json" `
  --body "@$tmpFile"

Remove-Item $tmpFile -Force
```

### List Roles (PowerShell)

```powershell
az rest --method get --resource $API --url $BASE | ConvertFrom-Json | Select-Object -ExpandProperty value | Select-Object name
```

---

## Bulk Replace All Roles (PUT) — ⚠️ DANGEROUS

> **⚠️ This replaces ALL roles. Roles not in the payload are DELETED.** Only use when deploying a complete role set from scratch (e.g., CI/CD). For single-role changes, use POST upsert above.

Safe read-modify-write pattern:
```bash
# 1. Read current roles
CURRENT=$(az rest --method get --resource "$API" --url "$BASE")
ROLES=$(echo "$CURRENT" | jq '.value')

# 2. Modify the array (e.g., add a role)
cat > /tmp/new_role.json <<'EOF'
{"name":"NewRole","decisionRules":[{"effect":"Permit","permission":[{"attributeName":"Path","attributeValueIncludedIn":["*"]},{"attributeName":"Action","attributeValueIncludedIn":["Read"]}]}],"members":{"microsoftEntraMembers":[{"tenantId":"...","objectId":"...","objectType":"Group"}]}}
EOF
UPDATED=$(echo "$ROLES" | jq --slurpfile nr /tmp/new_role.json '. + $nr')

# 3. Write complete payload to file
echo "{\"value\": $UPDATED}" > /tmp/all_roles.json

# 4. Dry run first
az rest --method put --resource "$API" --url "$BASE?dryRun=true" \
  --headers "Content-Type=application/json" --body @/tmp/all_roles.json

# 5. Apply
az rest --method put --resource "$API" --url "$BASE" \
  --headers "Content-Type=application/json" --body @/tmp/all_roles.json
```

---

## Script Templates

### Bash — Upsert Role from JSON File

```bash
#!/usr/bin/env bash
set -euo pipefail
WS_ID="${WS_ID:?Set WS_ID}"; ITEM_ID="${ITEM_ID:?Set ITEM_ID}"
ROLE_FILE="${1:?Usage: $0 <role.json>}"
API="https://api.fabric.microsoft.com/v1"
BASE="$API/workspaces/$WS_ID/items/$ITEM_ID/dataAccessRoles"
az account show >/dev/null 2>&1 || { echo "Run 'az login' first."; exit 1; }

ROLE_NAME=$(jq -r '.name' "$ROLE_FILE")
echo "Upserting role '$ROLE_NAME' ..."
az rest --method post --resource "$API" \
  --url "$BASE?dataAccessRoleConflictPolicy=Overwrite" \
  --headers "Content-Type=application/json" \
  --body @"$ROLE_FILE"

echo "Verifying ..."
az rest --method get --resource "$API" --url "$BASE/$ROLE_NAME" | jq '{name, paths: .decisionRules[0].permission[0].attributeValueIncludedIn}'
echo "✓ Done"
```

### PowerShell — Upsert Role from JSON File

```powershell
#Requires -Version 5.1
param([Parameter(Mandatory)][string]$RoleFile)
$WS_ID = $env:WS_ID; $ITEM_ID = $env:ITEM_ID
if (-not $WS_ID -or -not $ITEM_ID) { Write-Error "Set WS_ID and ITEM_ID env vars"; exit 1 }
$API = "https://api.fabric.microsoft.com/v1"
$BASE = "$API/workspaces/$WS_ID/items/$ITEM_ID/dataAccessRoles"
$null = az account show 2>$null
if ($LASTEXITCODE -ne 0) { Write-Error "Run 'az login' first"; exit 1 }

$roleName = (Get-Content $RoleFile | ConvertFrom-Json).name
Write-Host "Upserting role '$roleName' ..."
az rest --method post --resource $API `
  --url "$BASE`?dataAccessRoleConflictPolicy=Overwrite" `
  --headers "Content-Type=application/json" `
  --body "@$RoleFile"

Write-Host "Verifying ..."
az rest --method get --resource $API --url "$BASE/$roleName"
Write-Host "Done"
```

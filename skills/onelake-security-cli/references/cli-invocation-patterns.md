# OneLake Security — CLI Invocation Patterns

`az rest` recipes for all OneLake Data Access Security API operations. Requires `az login` session with Admin or Member workspace role.

**Reusable variables** (set once per session):
```bash
WS_ID="<workspaceId>"
ITEM_ID="<lakehouseId>"
API="https://api.fabric.microsoft.com"
BASE="$API/v1/workspaces/$WS_ID/items/$ITEM_ID/dataAccessRoles"
```

---

## List All Roles

```bash
az rest --method get --resource "$API" --url "$BASE" | jq '.value[] | {name, paths: .decisionRules[0].permission[0].attributeValueIncludedIn}'
```

With pagination:
```bash
TOKEN=""
while true; do
  URL="$BASE"
  [ -n "$TOKEN" ] && URL="$BASE?continuationToken=$TOKEN"
  RESP=$(az rest --method get --resource "$API" --url "$URL")
  echo "$RESP" | jq '.value[]'
  TOKEN=$(echo "$RESP" | jq -r '.continuationToken // empty')
  [ -z "$TOKEN" ] && break
done
```

---

## Get Single Role

```bash
ROLE_NAME="DefaultReader"
az rest --method get --resource "$API" --url "$BASE/$ROLE_NAME" | jq .
```

Returns the role object directly (no `value` wrapper).

---

## Create/Update Single Role (Upsert — POST)

```bash
az rest --method post --resource "$API" \
  --url "$BASE?dataAccessRoleConflictPolicy=Overwrite" \
  --headers "Content-Type=application/json" \
  --body '{
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
  }'
```

For large payloads, use `--body @role.json` with a file.

---

## Create/Update All Roles (Bulk PUT — Replace-All)

**WARNING**: This replaces ALL roles. Roles not in the payload are **deleted**.

Safe pattern — read-modify-write:
```bash
# 1. Read current roles + capture ETag
RESP=$(az rest --method get --resource "$API" --url "$BASE" --output-file /dev/stdout -i 2>/dev/null)
ETAG=$(echo "$RESP" | grep -i "^etag:" | awk '{print $2}' | tr -d '\r')
ROLES=$(az rest --method get --resource "$API" --url "$BASE" | jq '.value')

# 2. Modify (e.g., add a role)
NEW_ROLE='{"name":"NewRole","decisionRules":[{"effect":"Permit","permission":[{"attributeName":"Path","attributeValueIncludedIn":["*"]},{"attributeName":"Action","attributeValueIncludedIn":["Read"]}]}],"members":{"microsoftEntraMembers":[{"tenantId":"...","objectId":"...","objectType":"Group"}]}}'
UPDATED=$(echo "$ROLES" | jq --argjson nr "$NEW_ROLE" '. + [$nr]')

# 3. PUT with If-Match
echo "{\"value\": $UPDATED}" > /tmp/roles_payload.json
az rest --method put --resource "$API" --url "$BASE" \
  --headers "Content-Type=application/json" "If-Match=\"$ETAG\"" \
  --body @/tmp/roles_payload.json
```

Dry run (validate without applying):
```bash
az rest --method put --resource "$API" --url "$BASE?dryRun=true" \
  --headers "Content-Type=application/json" \
  --body @/tmp/roles_payload.json
```

---

## Delete Single Role

```bash
ROLE_NAME="ObsoleteRole"
az rest --method delete --resource "$API" --url "$BASE/$ROLE_NAME"
```

Returns 200 OK with no body.

---

## Role with RLS

```bash
az rest --method post --resource "$API" \
  --url "$BASE?dataAccessRoleConflictPolicy=Overwrite" \
  --headers "Content-Type=application/json" \
  --body '{
    "name": "EMEAOnly",
    "decisionRules": [{
      "effect": "Permit",
      "permission": [
        {"attributeName": "Path", "attributeValueIncludedIn": ["/Tables/Sales"]},
        {"attributeName": "Action", "attributeValueIncludedIn": ["Read"]}
      ],
      "constraints": {
        "rows": [{
          "tablePath": "/Tables/Sales",
          "value": "SELECT * FROM Sales WHERE Region='\''EMEA'\''"
        }]
      }
    }],
    "members": {
      "microsoftEntraMembers": [
        {"tenantId": "...", "objectId": "...", "objectType": "Group"}
      ]
    }
  }'
```

---

## Role with CLS (Hide PII)

```bash
az rest --method post --resource "$API" \
  --url "$BASE?dataAccessRoleConflictPolicy=Overwrite" \
  --headers "Content-Type=application/json" \
  --body '{
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
        {"tenantId": "...", "objectId": "...", "objectType": "Group"}
      ]
    }
  }'
```

---

## Audit: List Roles with Members Summary

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

## Script Templates

### Bash — Provision Roles from JSON File

```bash
#!/usr/bin/env bash
set -euo pipefail
WS_ID="${WS_ID:?Set WS_ID}"; ITEM_ID="${ITEM_ID:?Set ITEM_ID}"
ROLE_FILE="${1:?Usage: $0 <role-definition.json>}"
API="https://api.fabric.microsoft.com"
BASE="$API/v1/workspaces/$WS_ID/items/$ITEM_ID/dataAccessRoles"
az account show >/dev/null 2>&1 || { echo "Run 'az login' first."; exit 1; }

echo "Validating (dry run) ..."
az rest --method put --resource "$API" --url "$BASE?dryRun=true" \
  --headers "Content-Type=application/json" --body @"$ROLE_FILE"
echo "✓ Validation passed. Applying ..."
az rest --method put --resource "$API" --url "$BASE" \
  --headers "Content-Type=application/json" --body @"$ROLE_FILE"
echo "✓ Roles applied."
```

### PowerShell — Provision Roles from JSON File

```powershell
#Requires -Version 5.1
param([Parameter(Mandatory)][string]$RoleFile)
$WS_ID = $env:WS_ID; $ITEM_ID = $env:ITEM_ID
if (-not $WS_ID -or -not $ITEM_ID) { Write-Error "Set WS_ID and ITEM_ID env vars"; exit 1 }
$API = "https://api.fabric.microsoft.com"
$BASE = "$API/v1/workspaces/$WS_ID/items/$ITEM_ID/dataAccessRoles"
$null = az account show 2>$null
if ($LASTEXITCODE -ne 0) { Write-Error "Run 'az login' first"; exit 1 }

Write-Host "Validating (dry run) ..."
az rest --method put --resource $API --url "$BASE`?dryRun=true" `
  --headers "Content-Type=application/json" --body "@$RoleFile"
Write-Host "Applying ..."
az rest --method put --resource $API --url $BASE `
  --headers "Content-Type=application/json" --body "@$RoleFile"
Write-Host "Done"
```

# Microsoft Fabric OneLake Skills

AI coding assistant skills for Microsoft Fabric OneLake developers. Optimized for GitHub Copilot CLI, with cross-compatibility for Claude Code, VS Code Copilot, Cursor, and other AI coding tools.

## Installation

### GitHub Copilot CLI (Recommended)

**ALWAYS START WITH THIS: connect to the OneLake Skills Marketplace:**
```bash
/plugin marketplace add petcu40/onelake-skills
```

**Full bundle (all skills):**
```bash
/plugin install onelake-skills@onelake-collection 
```

> [!IMPORTANT]
> After installation **quit and restart** github copilot CLI.

## Skills Overview

### Authentication

All Fabric operations require Azure AD authentication:

```bash
az login
az account get-access-token --resource https://api.fabric.microsoft.com
```


### Developer Skills

For developers writing code - uses REST APIs for management, protocol-specific connections for data access.

| Skill | Pattern |
|-------|---------|
| `onelake-security-cli` | Develop OneLake security in Microsoft Fabric items from CLI environments |

## Cross-Tool Compatibility

These skills work with multiple AI coding tools:

| Tool | Configuration |
|------|---------------|
| GitHub Copilot CLI | Automatic via plugin system |
| VS Code Copilot | Automatic via `.github/skills/` |

### Data Handling

- Skills process data locally or through authenticated Fabric APIs
- No data sent to third parties
- Credentials managed through Azure AD / GitHub Secrets
- Audit logging for tool executions

### Reference
- [Fabric REST APIs](https://learn.microsoft.com/en-us/rest/api/fabric/articles/)
- [Microsoft Fabric Documentation](https://learn.microsoft.com/en-us/fabric/)
- [Microsoft Fabric Documentation](https://learn.microsoft.com/en-us/fabric/)
- [Microsoft OneLake Security Documentation](https://learn.microsoft.com/en-us/fabric/onelake/security/get-started-onelake-security/)
- [Microsoft OneLake Security REST APIs Documentation](https://learn.microsoft.com/en-us/rest/api/fabric/core/onelake-data-access-security)

## License

MIT

# Infisical Integration for BlackGate

This document describes how BlackGate integrates with Infisical for secure secret management.

## Overview

BlackGate now supports storing sensitive authentication data (API keys, client secrets, etc.) in Infisical instead of directly in the database. This provides better security and centralized secret management.

## Configuration

Set the following environment variables to enable Infisical integration:

```bash
INFISICAL_URL=http://localhost:8080
INFISICAL_CLIENT_ID=your-client-id
INFISICAL_CLIENT_SECRET=your-client-secret
INFISICAL_PROJECT_ID=your-project-id
INFISICAL_ENVIRONMENT=dev
```

## How It Works

1. **Secret Storage**: When adding routes through the web UI, sensitive values can be stored in Infisical
2. **Reference Generation**: BlackGate generates a reference string like `infisical://project-123:dev/api-key`
3. **Runtime Retrieval**: During request processing, BlackGate retrieves the actual secret value from Infisical
4. **Caching**: Retrieved secrets are cached in memory with TTL for performance

## Secret Reference Format

Secret references use the format: `infisical://PROJECT_ID:ENVIRONMENT/SECRET_KEY`

Examples:
- `infisical://my-project:production/stripe-api-key`
- `infisical://my-project:dev/oauth-client-secret`

## Usage in Route Configuration

### API Key Authentication
Instead of storing the API key directly:
```
auth_value: "sk-1234567890abcdef"
```

Store a reference:
```
auth_value: "infisical://my-project:prod/stripe-api-key"
```

### OAuth Client Credentials
Instead of:
```
oauth_client_secret: "very-secret-value"
```

Use:
```
oauth_client_secret: "infisical://my-project:prod/oauth-client-secret"
```

## Security Features

- **Encryption**: All secrets are encrypted at rest in Infisical
- **Access Control**: Infisical provides granular access controls
- **Audit Logging**: All secret access is logged by Infisical
- **TTL Caching**: Secrets are cached with configurable TTL (default 5 minutes)
- **Automatic Refresh**: Cache automatically refreshes expired secrets

## API Operations

The security module provides the following operations:

- `store_secret(key, value, description)` - Store a new secret
- `get_secret(reference)` - Retrieve a secret value
- `update_secret(reference, new_value)` - Update an existing secret
- `delete_secret(reference)` - Delete a secret
- `refresh_cache()` - Refresh all cached secrets

## Error Handling

- If Infisical is unavailable, routes with secret references will fail with 500 errors
- Invalid secret references return configuration errors
- Missing secrets return 404-style errors from Infisical

## Performance Considerations

- First access to a secret requires an API call to Infisical
- Subsequent accesses within the TTL period use cached values
- Cache cleanup runs periodically to remove expired entries
- Failed secret retrievals are not cached to allow for retry

## Docker Deployment

When deploying with docker-compose, Infisical can be included as a service:

```yaml
services:
  blackgate:
    # ... blackgate configuration
    environment:
      - INFISICAL_URL=http://infisical:8080
      # ... other env vars
    depends_on:
      - infisical

  infisical:
    image: infisical/infisical:latest
    # ... infisical configuration
```

## Migration Strategy

1. Deploy Infisical alongside BlackGate
2. Create machine identity and project in Infisical
3. Gradually migrate sensitive route configurations to use secret references
4. Remove plaintext secrets from database once migration is complete
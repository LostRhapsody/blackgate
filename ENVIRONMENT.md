# Environment Variables

Black Gate API Gateway uses environment variables for configuration. This document describes all available environment variables and their usage.

## Quick Start

1. Copy the example configuration:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` with your specific values

3. Generate a fresh example file anytime:
   ```bash
   ./blackgate generate-env --output .env.example
   ```

## Environment Validation

Black Gate validates all environment variables at startup and provides detailed feedback:

- ✅ **Valid configuration**: Server starts normally
- ⚠️ **Warnings**: Server starts but logs potential issues
- ❌ **Critical errors**: Server exits with error details

### Validation Example

```bash
# Invalid configuration
BLACKGATE_PORT=invalid BLACKGATE_HOST=not-an-ip ./blackgate start

# Output:
Environment validation failed with 2 critical error(s):
  ❌ CRITICAL - BLACKGATE_HOST: Invalid IP address: not-an-ip
  ❌ CRITICAL - BLACKGATE_PORT: Invalid port number: invalid
Critical environment validation errors found. Cannot start server.
```

## Database Configuration

### `BLACKGATE_DB_URL`
- **Description**: Database connection URL
- **Default**: `sqlite://blackgate.db`
- **Examples**:
  - `sqlite://blackgate.db` (relative path)
  - `sqlite:///var/lib/blackgate/blackgate.db` (absolute path)
- **Required**: No

## Server Configuration

### `BLACKGATE_HOST`
- **Description**: Server bind address
- **Default**: `0.0.0.0` (all interfaces)
- **Examples**:
  - `0.0.0.0` - Bind to all network interfaces
  - `127.0.0.1` - Bind to localhost only
  - `192.168.1.100` - Bind to specific IP
- **Validation**: Must be a valid IP address
- **Required**: No

### `BLACKGATE_PORT`
- **Description**: Server port number
- **Default**: `3000`
- **Range**: 1-65535
- **Note**: Ports below 1024 may require root privileges
- **Validation**: Must be a valid port number
- **Required**: No

## Logging Configuration

### `RUST_LOG`
- **Description**: Rust standard logging configuration
- **Default**: `blackgate=info,tower_http=debug`
- **Examples**:
  - `debug` - Everything at debug level
  - `blackgate=debug,tower_http=info` - Custom per-module levels
  - `error` - Only error messages
- **Required**: No

### `BLACKGATE_LOG_LEVEL`
- **Description**: Application-specific log level override
- **Default**: Uses `RUST_LOG` value
- **Examples**: `debug`, `info`, `warn`, `error`
- **Note**: Takes precedence over `RUST_LOG` if set
- **Required**: No

## Backup Configuration

### `BLACKGATE_BACKUP_ENABLED`
- **Description**: Enable automatic database backups
- **Default**: `true`
- **Values**: `true`, `false`, `1`, `0`, `yes`, `no`, `on`, `off`
- **Required**: No

### `BLACKGATE_BACKUP_INTERVAL_HOURS`
- **Description**: Backup interval in hours
- **Default**: `24` (daily backups)
- **Range**: 1-8760 (1 hour to 1 year)
- **Validation**: Must be a positive integer
- **Required**: No

## S3 Backup Configuration (Optional)

### `BLACKGATE_S3_BUCKET`
- **Description**: S3 bucket name for backup storage
- **Default**: None (S3 backups disabled)
- **Example**: `my-blackgate-backups`
- **Note**: Requires AWS credentials if set
- **Required**: No

### `BLACKGATE_S3_REGION`
- **Description**: AWS S3 region
- **Default**: `us-east-1`
- **Examples**: `us-west-2`, `eu-west-1`, `ap-southeast-1`
- **Required**: No (if using S3)

### `AWS_ACCESS_KEY_ID`
- **Description**: AWS access key for S3 operations
- **Default**: None
- **Note**: Can also be provided via IAM roles or AWS CLI configuration
- **Security**: Never commit this to version control
- **Required**: Yes (if using S3 backups)

### `AWS_SECRET_ACCESS_KEY`
- **Description**: AWS secret key for S3 operations
- **Default**: None
- **Note**: Can also be provided via IAM roles or AWS CLI configuration
- **Security**: Never commit this to version control
- **Required**: Yes (if using S3 backups)

### `AWS_SESSION_TOKEN`
- **Description**: AWS session token for temporary credentials
- **Default**: None
- **Use case**: When using temporary AWS credentials
- **Required**: No

### `AWS_PROFILE`
- **Description**: AWS CLI profile name
- **Default**: None
- **Example**: `blackgate-profile`
- **Note**: Alternative to explicit AWS credentials
- **Required**: No

## Docker Configuration

When running in Docker, you may also want to configure resource limits:

### `BLACKGATE_CPU_LIMIT`
- **Description**: CPU limit for Docker container
- **Default**: `1.0`
- **Examples**: `0.5`, `2.0`, `4.0`
- **Unit**: CPU cores

### `BLACKGATE_MEMORY_LIMIT`
- **Description**: Memory limit for Docker container
- **Default**: `1G`
- **Examples**: `512M`, `2G`, `4G`
- **Unit**: Bytes (with suffix: K, M, G)

### `BLACKGATE_CPU_RESERVATION`
- **Description**: Guaranteed minimum CPU allocation
- **Default**: `0.5`
- **Examples**: `0.25`, `1.0`
- **Unit**: CPU cores

### `BLACKGATE_MEMORY_RESERVATION`
- **Description**: Guaranteed minimum memory allocation
- **Default**: `512M`
- **Examples**: `256M`, `1G`
- **Unit**: Bytes (with suffix: K, M, G)

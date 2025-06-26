# Security Module

The security module provides security configuration and utilities. It handles secret management, HTTP security config, CORS policies, and security middleware.

Recommendations for Slimming:
1. **Split `config.rs`** into smaller files like `request_config.rs`, `cors_config.rs`, `auth_config.rs`
2. **Make middleware layers optional** with feature flags
3. **Consider removing the cache** if secret lookups are infrequent
4. **Remove unused configuration options** and keep only what you actually need
5. **Simplify the middleware stack** to only include essential security checks

## Overview

This module is designed to provide multiple layers of security controls:
- **Secret Management**: Secure storage and retrieval using Infisical
- **Request Security**: Input validation, size limits, and attack prevention
- **Authentication & Authorization**: Auth method validation and enforcement
- **Transport Security**: TLS/HTTPS configuration and enforcement
- **Cross-Origin Security**: CORS policy management
- **Rate Limiting**: Request throttling and burst protection
- **Security Headers**: Automatic security header injection
- **Audit & Monitoring**: Security event logging and tracking

## Module Files

### Core Components

#### `mod.rs` - Module Coordinator
**Purpose**: Main entry point and coordination layer for the security module.
- Exports all sub-modules and core types
- Provides `SecretManager` - the main orchestrator for secret operations
- Coordinates between Infisical client and secret caching
- High-level API for secret CRUD operations

**Key Features**:
- Unified secret management API
- Automatic caching with TTL support
- Cache refresh and cleanup operations
- Error handling and logging

#### `types.rs` - Core Data Structures
**Purpose**: Fundamental data types and structures used throughout the security module.
- `SecurityError` - Comprehensive error types for security operations
- `SecretReference` - Reference to secrets stored in Infisical
- `SecretValue` - Cached secret values with TTL and metadata
- `InfisicalConfig` - Configuration structure for Infisical connections

**Key Features**:
- Serializable secret references with URI format
- TTL-aware secret values with expiration checking
- Structured error handling for different failure modes

### Secret Management

#### `client.rs` - Infisical API Client
**Purpose**: Direct integration with Infisical secret management service.
- RESTful API wrapper for Infisical operations
- Authentication handling (Universal Auth)
- CRUD operations for secrets (create, read, update, delete)
- Bulk operations and connection testing

**Key Features**:
- Automatic authentication and token management
- Comprehensive error handling with retry logic
- Support for multiple secrets and batch operations
- Connection validation and health checks

#### `cache.rs` - Secret Caching Layer
**Purpose**: In-memory caching for secrets to improve performance and reduce API calls.
- TTL-based expiration management
- Cache hit/miss statistics tracking
- Automatic cleanup of expired entries
- Thread-safe operations with proper locking

**Key Features**:
- Configurable TTL per secret
- Performance metrics (hit rate, cache size)
- Expiration-based cleanup routines
- Memory-efficient storage with automatic pruning

### HTTP Security

#### `http.rs` - HTTP Security Configuration
**Purpose**: Security configuration for HTTP communications (NOT client creation).
- URL validation for upstream services
- Request/response header sanitization
- Security-focused HTTP client configuration structures
- Protection against SSRF and local network access

**Key Features**:
- Upstream URL validation (blocks private IPs, local domains)
- Header sanitization (removes sensitive/debug headers)
- Secure HTTP client configuration templates
- Anti-SSRF protection mechanisms

#### `cors.rs` - CORS Policy Management
**Purpose**: Cross-Origin Resource Sharing configuration and enforcement.
- Origin validation with wildcard support
- Header configuration for CORS responses
- Environment-based configuration loading
- Production vs development policy presets

**Key Features**:
- Flexible origin matching (exact, wildcard, patterns)
- Configurable allowed headers and exposed headers
- Credential handling for cross-origin requests
- Environment variable configuration support

### Security Middleware

#### `middleware.rs` - Security Middleware Stack
**Purpose**: Comprehensive middleware layers for request/response security.
- Multi-layer security controls (request → CORS → rate limiting → headers)
- Request validation and sanitization
- Attack pattern detection (SQL injection, XSS, path traversal)
- Rate limiting and IP-based access control
- Security header injection

**Key Features**:
- Layered middleware architecture
- Real-time attack detection and blocking
- Rate limiting with burst control
- IP and user-agent based filtering
- Security event logging and monitoring
- Authentication failure tracking with lockout

#### `config.rs` - Security Configuration Management
**Purpose**: Centralized configuration for all security policies and settings.
- Environment-based configuration loading
- Validation of security settings
- Development vs production configuration presets
- Comprehensive security policy definitions

**Key Features**:
- **Request Security**: Body size, path length, timeout limits
- **Rate Limiting**: RPM/RPH limits, burst controls, whitelisting
- **Authentication**: JWT settings, failure handling, lockout policies
- **TLS Configuration**: HTTPS enforcement, certificate settings, HSTS
- **Security Headers**: CSP, frame options, content type protection
- **Input Validation**: XSS/SQL injection protection, file upload controls
- **Logging Security**: Audit logging, sensitive data exclusion

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   SecretManager │    │ SecurityConfig   │    │ Middleware Stack│
│                 │    │                  │    │                 │
│ ┌─────────────┐ │    │ ┌──────────────┐ │    │ ┌─────────────┐ │
│ │ Infisical   │ │    │ │ Request      │ │    │ │ Request     │ │
│ │ Client      │ │    │ │ Security     │ │    │ │ Validation  │ │
│ └─────────────┘ │    │ └──────────────┘ │    │ └─────────────┘ │
│                 │    │                  │    │                 │
│ ┌─────────────┐ │    │ ┌──────────────┐ │    │ ┌─────────────┐ │
│ │ Secret      │ │    │ │ CORS         │ │    │ │ CORS        │ │
│ │ Cache       │ │    │ │ Config       │ │    │ │ Handler     │ │
│ └─────────────┘ │    │ └──────────────┘ │    │ └─────────────┘ │
└─────────────────┘    │                  │    │                 │
                       │ ┌──────────────┐ │    │ ┌─────────────┐ │
                       │ │ Rate         │ │    │ │ Rate        │ │
                       │ │ Limiting     │ │    │ │ Limiter     │ │
                       │ └──────────────┘ │    │ └─────────────┘ │
                       │                  │    │                 │
                       │ ┌──────────────┐ │    │ ┌─────────────┐ │
                       │ │ Headers &    │ │    │ │ Security    │ │
                       │ │ TLS Config   │ │    │ │ Headers     │ │
                       │ └──────────────┘ │    │ └─────────────┘ │
                       └──────────────────┘    └─────────────────┘
```

## Usage Examples

### Secret Management
```rust
use crate::security::SecretManager;

// Initialize secret manager
let manager = SecretManager::new(
    "https://infisical.example.com".to_string(),
    client_id,
    client_secret,
    "project-123".to_string(),
    "production".to_string(),
).await?;

// Store and retrieve secrets
let secret_ref = manager.store_secret("api-key", "secret-value", None).await?;
let value = manager.get_secret(&secret_ref).await?;
```

### Security Configuration
```rust
use crate::security::config::SecurityConfig;

// Production configuration
let config = SecurityConfig::production();

// Load from environment
let config = SecurityConfig::from_env()?;
config.validate()?;
```

### Middleware Stack
```rust
use crate::security::middleware::SecurityMiddleware;

let security = SecurityMiddleware::new(config)?;
let app = Router::new()
    .route("/api/*path", get(handler))
    .layer(security_layers);
```

## Security Considerations

1. **Secret Storage**: Secrets are encrypted in transit and cached with TTL
2. **Network Security**: URL validation prevents SSRF attacks
3. **Rate Limiting**: Protects against DoS and brute force attacks
4. **Input Validation**: Prevents injection attacks and malicious input
5. **CORS Policy**: Prevents unauthorized cross-origin access
6. **Security Headers**: Adds defense-in-depth through HTTP headers

## Potential Optimizations

This module is currently comprehensive but may be over-engineered for some use cases. Consider:

1. **Configuration Consolidation**: The `config.rs` file could be split into domain-specific configs
2. **Middleware Simplification**: Some middleware layers may be unnecessary depending on deployment
3. **Cache Optimization**: Consider if full secret caching is needed or if simple API calls suffice
4. **Feature Flags**: Add feature flags to disable unused security components
5. **Performance Tuning**: Some validations could be made optional for high-throughput scenarios

## Dependencies

- `reqwest`: HTTP client for Infisical API
- `serde`: Serialization for configuration and API responses
- `axum`: Web framework integration for middleware
- `tokio`: Async runtime and synchronization primitives
- `tracing`: Logging and instrumentation
- `chrono`: Date/time handling for TTL and expiration
- `regex`: Pattern matching for validation and filtering
- `url`: URL parsing and validation

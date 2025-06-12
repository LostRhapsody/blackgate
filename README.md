# The Black Gate Project - An Open Source API Gateway

The Black Gate Project, or Black Gate for short, is a rust API Gateway that handles common API-management tasks such as managing routes, upstreams, authentication, authorization, metrics, logging, and documentation, controlled through a CLI or Web User Interface.

Current Progress: 65%

# Gateway Features
- Manage API routes, their upstreams, authentication, HTTP Methods, and rate limits.
- Support for most Authentication schemes (Basic, OAuth2.0, API Key, OIDC, JWT).
- Royute collections to help organize similar API routes and share authentication between them.
- OpenAPI v3.0 Support automatically creates route collections and routes based on the document.
- Collect route metrics such as path hit, HTTP method, timestamps, duration, HTTP status, request and response size, and auth type.
- Web based user interface includes a minimalist-dashboard, and visual management for collections, routes, metrics, and settings.
- Rate limiting by route collection or route, per-minute and per-hour.
- Automated background health checks for routes, with configurable frequency, default is 60 seconds.
- Smart backup routing, if a route is unhealthy, re-route the request to it's pre-configured backup route.
- Containerized load tests to ensure the gateway's performance is not degraded throughout continued development.
- A Rust HTTP web server for upstreams during load tests and an oAuth test server for testing the oAuth Client Credential flow
- Production docker file included for containerization to self-host
- Database schema migrations, mostly for developers on The Black Gate Project, useful for customized forks as well

# Immediate Goals

- Black Gate needs a dedicated location for documentation, tutorials, etc. This is the project's current primary concern, as this Read Me file is not the best for navigation and I'm trying to keep it succinct.
- For improved benchmarking, re-run the benchmarks with various CPU and memory allocations.
  - 1 cpu, 512 mb
  - 2 cpu, 4 gb
  - 3 cpu, 8 gb
  - 4 cpu, 16 gb
- Current benchmark is 1 cpu, 512 mb, topping out at around 6,000 req/s.

# Contact for Inquiries

I'm a solo-developer building Black Gate. Contact me via `evan.robertson77@gmail.com` for questions about Black Gate, it's features, or contributing.

# Deployment

## Production Deployment with Docker Compose

Black Gate includes a production-ready Docker Compose configuration that supports configurable resource limits.

### Quick Start

1. Copy the environment configuration template:
   ```bash
   cp .env.example .env
   ```

2. Edit the `.env` file to customize resource limits and other settings:
   ```bash
   # CPU and Memory Limits
   BLACKGATE_CPU_LIMIT=1.0
   BLACKGATE_MEMORY_LIMIT=1G
   BLACKGATE_CPU_RESERVATION=0.5
   BLACKGATE_MEMORY_RESERVATION=512M
   ```

3. Deploy with Docker Compose:
   ```bash
   docker compose -f docker-compose.production.yml up -d
   ```

### Deployment Scripts

For easier deployment, you can use the provided deployment scripts:

**Bash:**
```bash
# Deploy with defaults
./deploy.sh

# Deploy with custom resources
./deploy.sh -c 2.0 -m 2G

# Deploy with minimal resources
./deploy.sh --cpu-limit 0.5 --memory-limit 512M
```

### Resource Configuration

You can configure CPU and memory limits in several ways:

**Option 1: Environment File (.env)**
```bash
BLACKGATE_CPU_LIMIT=2.0
BLACKGATE_MEMORY_LIMIT=2G
BLACKGATE_CPU_RESERVATION=1.0
BLACKGATE_MEMORY_RESERVATION=1G
```

**Option 2: Environment Variables**
```bash
export BLACKGATE_CPU_LIMIT=2.0
export BLACKGATE_MEMORY_LIMIT=2G
docker compose -f docker-compose.production.yml up -d
```

**Option 3: Inline with Docker Compose**
```bash
BLACKGATE_CPU_LIMIT=2.0 BLACKGATE_MEMORY_LIMIT=2G docker compose -f docker-compose.production.yml up -d
```

### Default Resource Limits

- **CPU Limit**: 1.0 (1 full CPU core)
- **Memory Limit**: 1G (1 gigabyte)
- **CPU Reservation**: 0.5 (guaranteed minimum: half a CPU core)
- **Memory Reservation**: 512M (guaranteed minimum: 512 megabytes)

### Recommended Resource Allocations

Based on load testing goals:

- **Light Load (< 1,000 req/s)**: 0.5 CPU, 512MB memory
- **Medium Load (1,000-3,000 req/s)**: 1.0 CPU, 1GB memory  
- **Heavy Load (3,000-6,000 req/s)**: 2.0 CPU, 2GB memory
- **Very Heavy Load (> 6,000 req/s)**: 4.0 CPU, 4GB+ memory

### Health Checks

The production deployment includes built-in health checks that verify the service is running correctly. The health check endpoint is available at `http://localhost:3000/health`.

# Upcoming features

**Response Caching**

Black Gate currently caches routes and health checks to minimize database reads. To take this a step further, Black Gate will cache requests and responses for a path. If a path is requested with the same parameters and request body as a previous request, we'll serve the cached response directly, cutting out the overhead of the HTTP request entirely. If it's a cache miss, we'll process the request like normal. The Time To Live (TTL) for this cache would be low, 5-30 seconds, to ensure freshness and balance performance and accuracy.

**Database Backups**

Currently, no backup solution exists. Currently debating these options, one or a mix of them.
- Host machine backups
- s3 bucket backups
- remote server backups (via SSH keys)

**Production Docker Improvements**

After a brief review, there are a few things we could do to improve the production-readiness of Black Gate. Despite these, the system is currently considered production ready, and these are mostly operational concerns, not show-stoppers.
- ✅ Configurable CPU/Memory limits
- Integration with a secret management service like Docker secrets
- Basic graceful shutdown script
- Validate required env variables on startup, all have defaults so not a huge concern
- Multi-stage deployment support (dev/staging/production) via feature flags or environment-based routing
- Network security (TLS/SSL termination, CORS policy config, IP allow/block list)
- Webhooks for monitoring
- Data persistance and recovery (backups, corruption detection, migration rollbacks)

**Tenant-based Authorization Implementation**
- Restric route access based on tenant ID
- Include tenants in metrics for tracking
- Recieve the tenant ID in the client request and validate it during the authentication pipeline

**Metrics Updates**
- Update metrics view so we can view ALL the metrics from within a certain window of time.
- Currently, limited to the last 200 metric logs. Useful, but doesn't provide much helpful info for long-term windows.
- Support for payload logging, currently payload is not included in metrics. This is more of a debugging/logging feature, but would fit well into the metrics module. Logging may receive it's own module.

**OpenAPI v3.0 Support Updates**
- Extract auth info, like the token URL and scopes, from the spec and add it to the collection.
- Conversion tool to convert 2.0 to 3.0 specs. I don't plan on creating a new pipeline for 2.0, as it's a lot of additional tools. `swagger2openapi` is a mature, well maintained tool that will be suitable for this.
- Code Stub Generation - Generate code based on OpenAPI Specs or your Gateway's routes
- OpenAPI Specification Generation - Generate barebones OpenAPI Sepcs based on your routes

**API route collections Updates**
- Bulk actions such as adding/removing entire collections, or many route configs at once
- When you delete a collection, it will either prevent you from deleting it while routes are in it, OR, you can cascade the table and delete all the assocaited routes. Currently returns a 500 error if you attempt to delete a collection with routes attached. Deleting the routes first allows you to delete the collection.

**Health Check Updates**
- Additional states such as degraded performance
- Integration with the metrics system
- Alerts via a webhook or other notification system for unhealthy upstreams

**Rate Limiting Updates**
- Enhanced rate limiting features (IP-based limiting, custom time windows)

**Throttling Implementation**

Instead of applying a hard-cap on traffic via rate limits, the gateway can *throttle* specific routes, limiting the number of requests coming through at a time. This can help prevent your backend services from being overwhelmed with unexpected traffic.

**API Composition Implementation**
- Aggregate data from multiple services into a single response, simplifying client-side logic
- Simplify responses from services so you only receive the information you actually needed, simplifying client-side logic.

**Protocol Translation Implementation**
- Bridge the gap between HTTP, WebSocket, gRPC, etc, simplifying client-side logic

**Data Transformation and Orchestration Implementation**
- Convert requests and responses to and from JSON and XML (and other common syntaxes for data representation)
- Modify request/response data and manage complex workflows

**Secure Credential Management Implementation**
- Currently, credentials are added per-route or per-collection as plain-text. This should be handled using a secrets service. TBD.

**Documentation**
- Include API documentation for routes in the Gateway itself, centralizing both API management AND documentation. This can either be a link to existing documentation or some sort of markdown file/documentation style website. TBD.
- The Black Gate Project needs a documentation website.

**First-Class Payment Gateway Support Implementation**

This Gateway's primary audience will typically use similar APIs, like payment processors. Black Gate aims to offer "First-Class Support" for certain APIs, making integration with them much easier. To start, the project will focus on payment processors.

- Built-in support for easily adding PayPal, Stripe, and Braintree in your gateway.
- Intuitive solutions for check-out form integration

**Import/Export Implementation**
- Provide Import/Export functions for collections, routes, and metrics.

**Improved Logging**

Currently, the application's logging is a bit all over the place. While the logs are detailed and helpful, the log-levels are often not set correctly. The usage of `info` or `debug` log-levels is not consistent.

**Nginx Integration**

Implement an Nginx container to act as a reverse proxy to handle request queues and load-balancing for multiple Black Gate Instances. This could help prevent time outs on resource-constrained Black Gate instances, and cache static-resources, reducing Black Gate hits.

**Plugins and Middleware**

Once the MVP features are completed, Black Gate hopes to develop an easy and extensible framework for adding middleware and plugins. This has not even reached planning stages and is just a concept of a plan.

**Generate Credentials API Keys**

Currently, you can provide Black Gate's routes and collections with authentication details, such as API Keys. You cannot create and store keys for use with applications though. For instance, if you wanted to generate an API key for one of your services to communicate with another service, you would need to generate the key elsewhere and add it to your routes manually. In the future, an API Key Vault to store these keys, track who is using them, when they were created, give them certain permissions, give them names, and provide an easy way to add them to rotues would be ideal.

**Automatic Route and Configuration Discovery**

We're is investigating how to let Black Gate automatically detect routes and configurations based on the services deployed on your infrastructure. This has a low-priority for a few reasons. 
1. Black Gate is developed with simplified client logic in-mind. Black Gate should take the strain off of your services when sending API requests. Auto-discovery, on the other hand, assumes this is your inbound API that other services are hitting. This isn't Black Gate's core goal at the moment. It can still route inbound traffic.
2. Auto-discovery typically means your services need to be deployed with some sort of configuration meta-data. This means you'll need to change how your application is deployed. While not a deal breaker, we're aiming to reduce application complexity, not add to it.
3. We're assuming anyone who is adding auto-discovery attributes to their software probably already has an OpenAPI v3.0 specification for their APIs. If this is the case, you can simply import that document into Black Gate, and all your services will be set up automatically, somewhat (but not entirely) negating the usefulness of this feature.

# Authentication Schemes Supported
- oAuth2.0 Client Credentials flow
- API Keys
- JWT
- OIDC (un-tested)
- Basic Authentication (username:password base64 encoded)

# Example (Using httpbin.org)
```bash
$ cargo run -- add-route --path /post --upstream https://httpbin.org/post --auth-type api-key --auth-value "Bearer warehouse_key" --rate-limit-per-minute 30 --rate-limit-per-hour 500
$ cargo run -- start
# in a second terminal
$ curl -X POST http://localhost:3000/post -d '{"payload": "test"}' -H "Content-Type: application/json"
# Response
{
  "args": {},
  "data": "test",
  "files": {},
  "form": {},
  "headers": {
    "Accept": "*/*",
    "Authorization": "Bearer warehouse_key",
    "Content-Length": "4",
    "Host": "httpbin.org",
    "X-Amzn-Trace-Id": "Root=1-683e373d-2b4ce83e644124823b5e60a7"
  },
  "json": null,
  "origin": "142.113.116.210",
  "url": "https://httpbin.org/post"
}
```

# Metrics and Monitoring

Black Gate includes comprehensive metrics tracking for all requests passing through the gateway:

## Features
- Track all incoming requests and responses
- Measure request duration from start to finish, including upstream response times
- Track authentication failures, routing errors, upstream failures, and rate limit violations
- Track which authentication method was used for each request
- Monitor request and response payload sizes
- Track rate limit violations with detailed error messages

## Metrics Data
Each request tracks:
- Unique request ID
- Path and HTTP method
- Request/response timestamps
- Total duration in milliseconds
- Request and response sizes in bytes
- HTTP status codes
- Upstream URL
- Authentication type used
- Client IP and User-Agent (when available)
- Error messages for failed requests

## Log Levels
Set logging level with the `RUST_LOG` environment variable:
```bash
# Show all info and above
$env:RUST_LOG = "blackgate=info"
cargo run -- start

# Show debug information including OAuth token caching
$env:RUST_LOG = "blackgate=debug"
cargo run -- start
```

# Rate Limiting

Black Gate includes built-in rate limiting functionality to protect your upstream services from overuse and ensure fair resource allocation.

## Features
- Each route can have its own rate limiting settings
- Separate limits for per-minute and per-hour windows
- Returns HTTP 429 (Too Many Requests) when limits are exceeded
- Uses precise timestamp tracking for accurate rate limiting
- Rate limit violations are logged in the metrics system

## Default Limits

Both per-minute and per-hour rate limits are set to 0 by default, which means "off", no rate limits.

When adding a new route or collection, the rate limits can be set manually.

You can configure new defaults (for example 60 per minute and 1000 per hour) in the settings page.

## Adding Routes with Rate Limits

**Basic route with default rate limits:**
```bash
cargo run -- add-route --path /api/data --upstream https://api.example.com/data
```

**Route with custom rate limits:**
```bash
cargo run -- add-route \
  --path /api/restricted \
  --upstream https://api.example.com/restricted \
  --rate-limit-per-minute 10 \
  --rate-limit-per-hour 100
```

## Viewing Route Rate Limits

List all routes with their rate limiting configuration:
```bash
cargo run -- list-routes
```

Old requests are automatically cleaned up from the tracking system as they expire.

# OIDC (Needs More Support)

This section is for contributors, as I don't really know how OIDC works and this was added mostly by Claude.

The OIDC authentication works as follows:

* Configuration: Creates OIDC config from route settings (issuer, client_id, client_secret, etc.)
* Discovery: Fetches the OpenID Connect discovery document from {issuer}/.well-known/openid_configuration
* Token Validation:
  * First tries token introspection if available
  * Validates audience if configured
  * Falls back to simplified JWT validation if introspection fails
* Request Forwarding: Forwards the validated token in the Authorization header

Features Supported

* Multiple validation methods: Token introspection (primary) + JWT validation (fallback)
* Audience verification: Validates token audience against configured value
* Flexible token format: Accepts both Bearer {token} and raw token formats
* Comprehensive error handling: Proper HTTP status codes and error messages
* Structured logging: Debug/info/warn logs for monitoring and troubleshooting

# Load Testing Commands
1. `rebuild-loadtest.sh` will teardown existing containers, rebuild them, and start them up.
2. `setup-routes.sh` set's up defaults, but, this is run by the containers.
3. `run-loadtest.sh` run's the `wrk` load tests.
4. `cleanup-loadtest.sh` will teardown and remove the containers.

If needed, these commands will help with container teardown and re-building
```bash
docker compose -f docker-compose.loadtest.yml down --volumes --remove-orphans
docker compose -f docker-compose.loadtest.yml down --rmi all
docker compose -f docker-compose.loadtest.yml build --no-cache
docker compose -f docker-compose.loadtest.yml up -d
```

# Settings

These are the settings that come pre-configured. Settings are database records and can be added via the Web interface, which is convienient for adding new settings to a customized version of Black Gate.

Health Check Interval
- key: `health_check_interval_seconds`
- value: `60`
- description: `Seconds between health checks`

Default Rate Limits Per Mintues
- key: `default_rate_limit_per_minute`
- value: `0`
- description: `Default rate limit per minute for new routes, 0 means no limit`

Default Rate Limits Per Hour
- key: `default_rate_limit_per_hour`
- value: `0`
- description: `Default rate limit per hour for new routes, 0 means no limit`

# Web to CLI Feature Parity

Generally, the web interface and the command-line interface offer similar functionality. They both all you to add, remove, update and list routes, view metrics, add, remove, update, and list route collections, etc.

However, Black Gate's primary focus will be to use it as a Web App. The CLI, currently, can only be used when the server itself is down, just due to the way the application is structured. Thus, the CLI will be getting limited support, and is mostly here to make testing easier.

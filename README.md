# The Black Gate Project

**An Open Source API Gateway**

---

The Black Gate Project, or Black Gate for short, is an open source API Gateway.

The goal is simple: A rust server that handles common API tasks such as managing routes, upstreams, authentication, authorization, metrics, logging, and documentation, controlled through a CLI or Web User Interface.

Current Progress: 45%

## Features
- Authentication (Basic, OAuth2.0, API Key, OIDC, JWT)
- Store routes' paths and their upstreams in a database
- Add, remove, and list routes via the CLI
- Add, remove, edit and list routes via the Web UI
- Create collections of routes for sharing authentication and organization
- Use OpenAPI 3.0 Documents to automatically create collections and add all of the paths from the document as routes.
- oAuth test server for testing oAuth Client Credential flows
- HTTP Method Validation per-path
- Detailed metrics for each request via the CLI and Web UI
- A convienient dashboard page for the Web UI
- Rate Limiting - Configurable per-minute and per-hour rate limits for each route
- Database schema migrations, mostly for developers on The Black Gate Project, useful for customized forks as well
- Health Checks for endpoints
- Automatically switch to pre-configured backup routes if the primary upstream is unhealthy
- Customizable defaults for health check interval and rate limites
- Dockerfile included for containerization to self-host

## Performance Improvements

There are quite a few bottlenecks right now. Blocking database queries and health checks mostly. We're improving things one at a time. Currently we're looking at about and extra 90ms per request, just for those processes, while the request itself has a near 3ms latency in reality. This is due to all our database queries and checks.

✅ Step 1. Route caching. We'll cache routes the first time we fetch them from the database into a simple hashmap to make lookup faster.
Step 2. Health check caching. Same idea.
Step 3. Ensure health checks are only ever done async and never blocking. Don't run health checks in the main request logic, just rely on whatever the last check in the DB or cache was.
Step 4. Improve the method validation, rate limit check, and store metrics async so we don't block the response.
✅ Step 5. Update the database defaults to create more open connections and keep them warm.
✅ Step 6. HTTP Connection pooling, don't create a new reqwest::Client every request
✅ Step 7. We're setting rate limits by default! These should be turned off by default, actually. Set everything to 0!
Step 8. Ensure we're not performing any complex auth setup when no auth is configured, so we can skip that step.


## Current WIP Features

**OpenAPI v3.0 Support**
By submitting an OpenAPI v3.0 URL when creating a collection, Black Gate automatically creates a collection and routes for all the paths in the collection. All that needs to be setup is the authentication in the collection, and all routes should be ready to go.

Stil missing:
- Extract auth info, like the token URL and scopes, from the spec and add it to the collection.
- Conversion tool to convert 2.0 to 3.0 specs. I don't plan on creating a new pipeline for 2.0, as it's a lot of additional tools. `swagger2openapi` is a mature, well maintained tool that will be suitable for this.


**API route collections**

Organize API routes into collections.
- ✅ Manage routes authentication by collection or route
- authorization either by collection or by route
- Bulk actions such as adding/removing entire collections, or many route configs at once
- ✅ When adding a new route, if it is part of a collection, a message is displayed: "Added authentication to this route will override the route's inherited collection authentication"
- When you delete a collection, it will either prevent you from deleting it while routes are in it, OR, you can cascade the table and delete all the assocaited routes. Currentl spits out a 500 error.

**Health Check Updates**

We currently support health checks every 60 seconds, using either a dedicated health check endpoint or a "HEAD" request. The status of the check is displayed on the routes page. Remaining features to implement:
- Additional states (degraded performance, only applicable to endpoints with real health checks)
- Integration with the metrics system
- Alerts via a webhook or other notification system (TBD)

## Upcoming features

**Tenant-based Authorization**

- Restric route access based on tenant ID
- Include tenants in metrics for tracking
- Recieve the tenant ID in the client request and validate it during the authentication pipeline

**Sections with detailed information on features below**

### Authentication Schemes Supported
- oAuth2.0 Client Credentials
- API Keys
- JWT
- OIDC (un-tested)
- Basic Authentication (username:password base64 encoded)

## Example (Using httpbin.org)
```bash
$ cargo run -- add-route --path /warehouse --upstream https://httpbin.org/post --auth-type api-key --auth-value "Bearer warehouse_key" --rate-limit-per-minute 30 --rate-limit-per-hour 500
$ cargo run -- start
# in second terminal
$ curl -X POST http://localhost:3000/warehouse -d '{"payload": "test"}' -H "Content-Type: application/json"
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

---

## Next Steps
- Tenant based Authorization (Restrict routes and actions based on the client we recceive the request from)
- Enhanced rate limiting features (IP-based limiting, custom time windows)
- API Composition - aggregate data from multiple services into a single response, simplifying client-side logic
- Protocol translation - bridge the gap between HTTP, WebSocket, gRPC, etc, simplifying client-side logic
- Data transloation - convert requests and responses to and from JSON and XML (and other common syntaxes for data representation)
- Data transformation and orchestration - modify request/response data and manage complex workflows
- Code Stub Generation - Generate code based on OpenAPI Specs or your Gateway's routes
- OpenAPI Specification Generation - Generate barebones OpenAPI Sepcs based on your routes
- Secure Credential Management - Currently, credentials are added per-route, but could be stored outside the route schema and managed independantly
- Documentation support - include API documentation (or at the least, links to it) in the Gateway
- Payment Gateway support - Make it easy to set up PayPal, Stripe, and Braintree in your Gateway, switch between them during outages, and provide intuitive check-out form solutions
- Import/Export for routes and metrics

---

## Metrics and Monitoring

Black Gate includes comprehensive metrics tracking for all requests passing through the gateway:

### Features
- **Request/Response Logging**: Track all incoming requests with detailed information
- **Timing Metrics**: Measure request duration from start to finish, including upstream response times
- **Error Tracking**: Log authentication failures, routing errors, upstream failures, and rate limit violations
- **Authentication Metrics**: Track which authentication method was used for each request
- **Data Size Tracking**: Monitor request and response payload sizes
- **Rate Limit Monitoring**: Track rate limit violations with detailed error messages

### Viewing Metrics

**View recent requests:**
```bash
cargo run -- metrics --limit 10
```

**View statistics summary:**
```bash
cargo run -- metrics --stats
```

**View both stats and recent requests:**
```bash
cargo run -- metrics --stats --limit 5
```

### Metrics Data
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

### Log Levels
Set logging level with the `RUST_LOG` environment variable:
```bash
# Show all info and above
$env:RUST_LOG = "blackgate=info"
cargo run -- start

# Show debug information including OAuth token caching
$env:RUST_LOG = "blackgate=debug"
cargo run -- start
```

## Rate Limiting

Black Gate includes built-in rate limiting functionality to protect your upstream services from overuse and ensure fair resource allocation.

### Features
- **Per-Route Configuration**: Each route can have its own rate limiting settings
- **Dual Time Windows**: Separate limits for per-minute and per-hour windows
- **Automatic Enforcement**: Returns HTTP 429 (Too Many Requests) when limits are exceeded
- **Sliding Window**: Uses precise timestamp tracking for accurate rate limiting
- **Integration with Metrics**: Rate limit violations are logged in the metrics system

### Default Limits
- **Per-Minute**: 60 requests per minute (default)
- **Per-Hour**: 1000 requests per hour (default)

### Adding Routes with Rate Limits

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

**Route with authentication and rate limits:**
```bash
cargo run -- add-route \
  --path /api/secure \
  --upstream https://api.example.com/secure \
  --auth-type api-key \
  --auth-value "Bearer secret_key" \
  --rate-limit-per-minute 5 \
  --rate-limit-per-hour 50
```

### Viewing Route Rate Limits

List all routes with their rate limiting configuration:
```bash
cargo run -- list-routes
```

Output includes rate limiting information:
```
Path: /api/data
Upstream: https://api.example.com/data
Method: Any
Auth Type: None
Rate/Min: 60
Rate/Hour: 1000
```

### Rate Limit Behavior

When a client exceeds the rate limit:
- **HTTP Status**: 429 (Too Many Requests)
- **Retry-After Header**: Indicates when the client can retry (60 seconds)
- **Metrics Logging**: Violation is recorded with "Rate limit exceeded" error message

### Rate Limit Reset

Rate limits use sliding time windows:
- **Per-Minute**: Resets on a rolling 60-second basis
- **Per-Hour**: Resets on a rolling 3600-second basis

Old requests are automatically cleaned up from the tracking system as they expire.

### Examples of Rate Limiting in Action

**Testing rate limits:**
```bash
# Add a route with strict limits for testing
cargo run -- add-route --path /test --upstream https://httpbin.org/get --rate-limit-per-minute 2 --rate-limit-per-hour 5

# Start the server
cargo run -- start

# Test rapid requests (will hit rate limit after 2 requests)
curl http://localhost:3000/test  # Success
curl http://localhost:3000/test  # Success
curl http://localhost:3000/test  # 429 Too Many Requests
```

**Rate limit response:**
```json
{
  "error": "Rate limit exceeded. Try again later."
}
```

## Authentication Information

This section outlines some info about how the different authentication schemes are implemented.

### OIDC (Needs Testing)

This section is more for contributors, as I don't really know how OIDC works and this was added mostly by Claude.

🔧 Implementation Details

The OIDC authentication now works as follows:

* Configuration: Creates OIDC config from route settings (issuer, client_id, client_secret, etc.)
* Discovery: Fetches the OpenID Connect discovery document from {issuer}/.well-known/openid_configuration
* Token Validation:
  * First tries token introspection if available
  * Validates audience if configured
  * Falls back to simplified JWT validation if introspection fails
* Request Forwarding: Forwards the validated token in the Authorization header

🚀 Features Supported

* Multiple validation methods: Token introspection (primary) + JWT validation (fallback)
* Audience verification: Validates token audience against configured value
* Flexible token format: Accepts both Bearer {token} and raw token formats
* Comprehensive error handling: Proper HTTP status codes and error messages
* Structured logging: Debug/info/warn logs for monitoring and troubleshooting

## Tests
Additional tests

test POST request
```bash
curl -X POST http://localhost:3000/post-test -d '{"payload": "test"}' -H "Content-Type: application/json"
```
test GET request
```bash
curl -X GET http://localhost:3000/get-test
```
test OAuth request
```bash
curl -X GET http://localhost:3000/oauth-test
```
test OAuth request directly on the oauth test server
```bash
curl -X POST http://localhost:3001/oauth/token -d '{"grant_type":"client_credentials","client_id":"test","client_secret":"test","scope":"test"}' -H "content-type: application/json"
```
test rate limiting
```bash
# Add a test route with low limits
cargo run -- add-route --path /rate-test --upstream https://httpbin.org/get --rate-limit-per-minute 2 --rate-limit-per-hour 5

# Test multiple requests to trigger rate limiting
curl http://localhost:3000/rate-test  # Should succeed
curl http://localhost:3000/rate-test  # Should succeed
curl http://localhost:3000/rate-test  # Should return 429 Too Many Requests
```

# Load Testing Commands

1. Start everything
`./setup-loadtest.sh`

2. Run tests
`./run-loadtest.sh`

3. Clean up when done
`./cleanup-loadtest.sh`

If needed, these commands will help with container teardown and re-building
```bash
docker compose -f docker-compose.loadtest.yml down --volumes --remove-orphans
docker compose -f docker-compose.loadtest.yml down --rmi all
docker compose -f docker-compose.loadtest.yml build --no-cache
docker compose -f docker-compose.loadtest.yml up -d
```

# Settings

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
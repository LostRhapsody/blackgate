# The Black Gate Project

**An Open Source API Gateway**

---

The Black Gate Project, or Black Gate for short, is an open source API Gateway.

The goal is simple: A rust server that handles common API tasks such as managing routes, upstreams, authentication, authorization, metrics, logging, and documentation, controlled through a CLI or Web User Interface.

Current Progress: 7%

## Features
- Authentication
- Store paths and their upstreams in a database
- Add, remove, and list routes via the CLI
- Add, remove, and list routes via the Web UI
- Test Coverage
- oAuth test server for testing oAuth Client Credential flows
- HTTP Method Validation per-path
- Detailed metrics for each request
- Rate Limiting - Configurable per-minute and per-hour rate limits for each route
- Dockerfile included for containerization to self-host

## Current WIP Feature

**OIDC Authentication**
Status: Fields have been added to structs, commands, fields, and inputs. Partial logic and functions have been implemented, but not tested or validated, just scaffolded.
Next step: More OIDC research and implementation planning and testing. Claude Sonnet 4 couldn't handle this one entirely solo. 


**Sections with detailed information on features below**

### Authentication Schemes Supported
- oAuth2.0 Client Credentials
- API Keys
- JWT

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
- User/Password Authentication
- OIDC Authentication
- Tenant based Authorization (Restrict routes and actions based on the client we recceive the request from)
- Enhanced rate limiting features (IP-based limiting, custom time windows)
- Enhanced web UI
- API Composition - aggregate data from multiple services into a single response, simplifying client-side logic
- Protocol translation - bridge the gap between HTTP, WebSocket, gRPC, etc, simplifying client-side logic
- Data transloation - convert requests and responses to and from JSON and XML (and other common syntaxes for data representation)
- Data transformation and orchestration - modify request/response data and manage complex workflows
- OpenAPI Specification Support - Automatically add all the routes from an OpenAPI spec to your Gateway
- Code Stub Generation - Generate code based on OpenAPI Specs or your Gateway's routes
- OpenAPI Specification Generation - Generate barebones OpenAPI Sepcs based on your routes
- API Health checks - confirm the status and uptime of an API and display it
- Automatic API route backups - provide 'backup' routes for specific routes if that route's API is not available
- Secure Credential Management - Currently, credentials are added per-route, but could be stored outside the route schema and managed independantly
- Documentation support - include API documentation (or at the least, links to it) in the Gateway
- Collections - combine related routes into a single API collection to keep routes organized
- Payment Gateway support - Make it easy to set up PayPal, Stripe, and Braintree in your Gateway, switch between them during outages, and provide intuitive check-out form solutions

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

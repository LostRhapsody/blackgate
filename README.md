# The Black Gate Project

**An Open Source API Gateway**

---

The Black Gate Project, or Black Gate for short, is an open source project API Gateway.

The goal is simple: A rust server that handles common API tasks such as managing routes, upstreams, authentication, authorization, metrics, logging, and documentation.

Current Progress: 5%

Status:
- Black Gate can accept a new route record, which includes an upstream and path, along with optional values for authentication and HTTP method.
- Black Gate adds this route record to the database.
- When the HTTP server is run and we send a request to that path, a request for the upstream URI is built using any authentication stored in the record.
- The HTTP request is executed and the response is returned to the client.
- The request and response metrics are logged.
- Black Gate can list the route records in the DB.
- Black Gate can remove routes from the DB.
- This is all controlled via a CLI
- Dockerfile included for containerization to self-host

Authentication Schemes Supported:
- oAuth2.0 Client Credentials
- API Keys
- JWT

Features:
- Authentication
- Store paths and their upstreams in a database
- Add, remove, and list routes via the CLI
- Test Coverage
- oAuth test server for testing oAuth Client Credential flows
- HTTP Method Validation per-path
- Detailed metrics for each request
- Rate Limiting - Configurable per-minute and per-hour rate limits for each route

Example (Using httpbin.org):
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

Next Steps:
- More Authentication schemes
- Enhanced rate limiting features (IP-based limiting, custom time windows)
- A web based user interface with HTMX for speed and simplicity

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

Long Term Goals:
- Black Gate will be self-hosted or hosted by "Black Gate" in the cloud for a subscription fee.
- Payment Processing Gateway centric features, with the goal of providing flexible payment provider support to B2B and retail websites.

Tests:
test POST request
```bash
curl -X POST http://localhost:3000/warehouse -d '{"payload": "test"}' -H "Content-Type: application/json"
```
test GET request
```bash
curl -X GET http://localhost:3000/warehouse-get
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
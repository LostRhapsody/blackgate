# The Black Gate Project

**An Open Source API Gateway**

---

The Black Gate Project, or Black Gate for short, is an open source project API Gateway.

The goal is simple: A rust server that handles common API tasks such as managing routes, upstreams, authentication, authorization, metrics, logging, and documentation.

Current Progress: 2%

Status:
- Black Gate can accept a new route record, which includes an upstream and path, along with optional values for authentication and HTTP method.
- Black Gate adds this route record to the database.
- When the HTTP server is run and we navigate to that path, a request for the upstream URI is built using any authentication stored in the record.
- The HTTP request is executed and the response is returned to the client.
- Black Gate can list the route records in the DB.
- Black Gate can remove routes from the DB.
- This is all controlled via a CLI
- Dockerfile included for containerization to self-host

Authentication Schemes Supported:
- oAuth2.0 Client Credentials
- API Keys

Features:
- Authentication
- Store paths and their upstreams in a database
- Add, remove, and list routes via the CLI
- Test Coverage
- oAuth test server for testing oAuth Client Credential flows
- HTTP Method Validation per-path

Example (Using httpbin.org):
```bash
$ cargo run -- add-route --path /warehouse --upstream https://httpbin.org/post --auth-type api-key --auth-value "Bearer warehouse_key"
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
- Metrics, track the timing of each request and store it in a table for auditing.
- A web based user interface with HTMX for speed and simplicity.

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
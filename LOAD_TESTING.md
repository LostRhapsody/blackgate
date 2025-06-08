# BlackGate Load Testing Setup

This directory contains everything you need to perform comprehensive load testing on your BlackGate API gateway.

## Quick Start

1. **Setup the environment:**
   ```bash
   ./setup-loadtest.sh
   ```

2. **Run load tests:**
   ```bash
   ./run-loadtest.sh
   ```

## Components

### 🔧 Services

- **BlackGate** (Port 3000) - Your API gateway
- **Upstream Test Server** (Port 8080) - Simple Rust server for testing

### 📁 Files

- `docker-compose.loadtest.yml` - Docker setup with resource limits
- `setup-loadtest.sh` - Initialize services and configure routes
- `run-loadtest.sh` - Comprehensive test runner
- `upstream-test-server/` - Simple Rust upstream server
- `scripts/` - wrk Lua scripts for advanced testing

## Test Scenarios

### Baseline Tests
Test the upstream server directly to establish baseline performance:
```bash
./run-loadtest.sh baseline
```

### Gateway Tests
Test through BlackGate to measure overhead:
```bash
./run-loadtest.sh gateway
```

### Stress Tests
Find breaking points with high load:
```bash
./run-loadtest.sh stress
```

### Full Test Suite
Run everything:
```bash
./run-loadtest.sh full
```

## Manual Testing

### Basic wrk Commands

```bash
# Light load test
wrk -t2 -c10 -d30s http://localhost:3000/fast

# Medium load test
wrk -t4 -c50 -d60s http://localhost:3000/fast

# Heavy load test
wrk -t8 -c100 -d60s http://localhost:3000/fast

# POST requests with JSON
wrk -t4 -c25 -d30s -s scripts/post-test.lua http://localhost:3000/json

# Mixed workload
wrk -t4 -c50 -d60s -s scripts/mixed-load.lua http://localhost:3000
```

### Available Endpoints

#### Through BlackGate (Port 3000)
- `GET /fast` - Fast response endpoint
- `GET /slow?delay=100` - Configurable delay endpoint
- `GET /echo/{param}` - Echo parameter back
- `POST /json` - Accept JSON payload

#### Direct Upstream (Port 8080) - For Baseline
- `GET /health` - Health check
- `GET /fast` - Fast response
- `GET /slow?delay=100` - Slow response
- `GET /echo/{param}` - Echo endpoint
- `POST /json` - JSON endpoint
- `GET /error/{code}` - Return specific HTTP status
- `GET /large/{size_kb}` - Large response testing
- CRUD endpoints: `/resource/{id}`

## Resource Management

The Docker setup includes resource limits:

- **BlackGate**: 1 CPU, 512MB RAM
- **Upstream**: 0.5 CPU, 256MB RAM

This prevents resource cannibalization and provides consistent test conditions.

## Results

Test results are saved to `./load-test-results/` with timestamps:
- Individual test outputs
- Summary report in Markdown format

## Customization

### Adding New Test Endpoints

1. Add endpoint to `upstream-test-server/src/main.rs`
2. Update route configuration in `setup-loadtest.sh`
3. Add test scenarios to `run-loadtest.sh`

### Custom wrk Scripts

Create new `.lua` files in the `scripts/` directory. Examples:

```lua
-- custom-test.lua
wrk.method = "POST"
wrk.headers["Authorization"] = "Bearer your-token"

function request()
    return wrk.format("POST", "/api/endpoint", 
                     {["Content-Type"] = "application/json"}, 
                     '{"custom": "payload"}')
end
```

## Troubleshooting

### Services Not Starting
```bash
# Check logs
docker compose -f docker-compose.loadtest.yml logs

# Restart services
docker compose -f docker-compose.loadtest.yml down
./setup-loadtest.sh
```

### Route Configuration Issues
The setup script makes assumptions about your BlackGate API. You may need to adjust the route configuration commands in `setup-loadtest.sh` based on your actual API endpoints.

### Performance Issues
1. Check Docker resource limits
2. Verify host system resources
3. Adjust test parameters (threads, connections, duration)

## Best Practices

1. **Warm-up**: Run a small test first to warm up services
2. **Baseline**: Always test upstream directly for comparison
3. **Gradual Load**: Increase load gradually to find limits
4. **Multiple Runs**: Run tests multiple times for consistency
5. **Monitor**: Watch system resources during tests

## Example Test Flow

```bash
# 1. Setup environment
./setup-loadtest.sh

# 2. Quick smoke test
wrk -t1 -c1 -d10s http://localhost:3000/fast

# 3. Run baseline tests
./run-loadtest.sh baseline

# 4. Run gateway tests
./run-loadtest.sh gateway

# 5. Compare results and adjust

# 6. Clean up
docker compose -f docker-compose.loadtest.yml down
```

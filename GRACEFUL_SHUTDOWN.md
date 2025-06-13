# Graceful Shutdown & Reload

This document describes the graceful shutdown and reload functionality implemented in Black Gate API Gateway.

## Overview

Black Gate includes comprehensive graceful shutdown and reload capabilities that ensure:

- **Clean termination** of all background services
- **Zero downtime** during reload operations
- **Proper resource cleanup** including database connections and file handles
- **Signal-based control** for integration with process managers and containers

## Architecture

### Shutdown Coordinator

The graceful shutdown system is built around a centralized `ShutdownCoordinator` that manages:

- **Signal handling** for SIGTERM and SIGINT
- **Background task coordination** via broadcast channels
- **Timeout management** for shutdown operations
- **Resource cleanup** tracking

### Background Services

Three main background services are managed during shutdown:

1. **Health Check Service** - Monitors upstream service health
2. **Database Backup Service** - Performs scheduled database backups  
3. **Response Cache Cleanup** - Manages expired cache entry removal

Each service implements shutdown-aware task wrappers that can gracefully stop processing when signaled.

## Usage

### Graceful Shutdown

#### Using the Script

```bash
# Normal graceful shutdown (30 second timeout)
./graceful-shutdown.sh

# Custom timeout
./graceful-shutdown.sh --timeout 60

# Force shutdown (skip graceful period)
./graceful-shutdown.sh --force

# Shutdown specific PID
./graceful-shutdown.sh --pid 12345
```

#### Using Signals

```bash
# Send SIGTERM for graceful shutdown
kill -TERM <blackgate_pid>

# Send SIGINT (Ctrl+C)
kill -INT <blackgate_pid>
```

### Graceful Reload

The reload script implements a blue-green deployment pattern:

```bash
# Normal graceful reload
./graceful-reload.sh

# Custom timeouts
./graceful-reload.sh --timeout 60 --startup-timeout 30

# Use specific binary
./graceful-reload.sh --binary /path/to/blackgate

# Skip health checks
./graceful-reload.sh --no-health-check
```

#### Reload Process

1. **Pre-reload checks** - Validate environment and permissions
2. **Start new instance** - Launch new Black Gate process
3. **Health verification** - Wait for new instance to become healthy
4. **Traffic cutover** - New instance begins handling requests
5. **Graceful shutdown** - Stop old instance cleanly
6. **Post-reload verification** - Confirm successful reload

## Docker Integration

### Docker Compose

```yaml
services:
  blackgate:
    image: blackgate:latest
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    stop_grace_period: 30s
```

### Docker Commands

```bash
# Graceful shutdown (uses SIGTERM)
docker stop blackgate-container

# Force shutdown after timeout
docker kill blackgate-container

# Rolling update with zero downtime
docker-compose up -d --no-deps --scale blackgate=2 blackgate
docker-compose up -d --no-deps --scale blackgate=1 blackgate
```

## Configuration

### Environment Variables

- `BLACKGATE_DB_URL` - Database connection string
- `BLACKGATE_SHUTDOWN_TIMEOUT` - Override default shutdown timeout
- `BLACKGATE_HEALTH_CHECK_TIMEOUT` - Health check timeout during reload

## Script Options

### graceful-shutdown.sh

| Option | Description | Default |
|--------|-------------|---------|
| `--timeout SECONDS` | Maximum time to wait for graceful shutdown | 30 |
| `--force` | Skip graceful shutdown, force kill immediately | false |
| `--pid PID` | Shutdown specific process ID | auto-detect |
| `--help` | Show usage information | - |

### graceful-reload.sh

| Option | Description | Default |
|--------|-------------|---------|
| `--timeout SECONDS` | Time to wait for old instance shutdown | 30 |
| `--startup-timeout SECONDS` | Time to wait for new instance startup | 15 |
| `--binary PATH` | Path to Black Gate binary | auto-detect |
| `--no-health-check` | Skip health checks during reload | false |
| `--help` | Show usage information | - |

## Process Management Integration

### systemd

```ini
[Unit]
Description=Black Gate API Gateway
After=network.target

[Service]
Type=forking
User=blackgate
Group=blackgate
ExecStart=/usr/local/bin/blackgate start
ExecReload=/usr/local/bin/graceful-reload.sh
ExecStop=/usr/local/bin/graceful-shutdown.sh
TimeoutStopSec=30
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Supervisor

```ini
[program:blackgate]
command=/usr/local/bin/blackgate start
directory=/opt/blackgate
user=blackgate
autostart=true
autorestart=true
stopsignal=TERM
stopwaitsecs=30
stdout_logfile=/var/log/blackgate/stdout.log
stderr_logfile=/var/log/blackgate/stderr.log
```

## Troubleshooting

### Common Issues

#### Shutdown Timeout

```bash
# Check for hung background tasks
ps aux | grep blackgate

# Force shutdown if needed
./graceful-shutdown.sh --force

# Check system resources
df -h
free -m
```

#### Reload Failures

```bash
# Check logs
tail -f /tmp/blackgate-reload.log

# Verify binary permissions
ls -la $(which blackgate)

# Test health endpoint manually
curl -v http://localhost:3000/health
```

#### PID File Issues

```bash
# Remove stale PID file
rm -f /tmp/blackgate.pid

# Check for running processes
pgrep -f "blackgate.*start"

# Clean up manually if needed
pkill -f "blackgate.*start"
```

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
# Verbose shutdown
RUST_LOG=debug ./graceful-shutdown.sh --verbose

# Verbose reload  
RUST_LOG=debug ./graceful-reload.sh --verbose
```

## Testing

### Automated Tests

Run the test suite to validate shutdown functionality:

```bash
# Run all graceful shutdown tests
./test-graceful-shutdown.sh

# Verbose test output
./test-graceful-shutdown.sh --verbose

# Skip cleanup for debugging
./test-graceful-shutdown.sh --no-cleanup
```

### Manual Testing

```bash
# Start Black Gate
cargo run -- start &
BLACKGATE_PID=$!

# Test graceful shutdown
kill -TERM $BLACKGATE_PID

# Verify clean shutdown
wait $BLACKGATE_PID
echo "Exit code: $?"
```

## Security Considerations

### Signal Handling

- Only SIGTERM and SIGINT trigger graceful shutdown
- SIGKILL is reserved for force termination
- Process runs with minimal privileges

### File Permissions

```bash
# Recommended permissions
chmod 755 graceful-shutdown.sh graceful-reload.sh
chmod 644 /tmp/blackgate.pid
```

### Network Security

- Health checks use localhost only
- No external shutdown triggers
- Process isolation via user/group

## Performance Impact

### Shutdown Performance

- Typical graceful shutdown: 2-5 seconds
- Maximum with timeout: 30 seconds (configurable)
- Background task cleanup: <1 second each

### Reload Performance

- Zero-downtime reload achievable
- Typical reload time: 10-15 seconds
- Memory usage during reload: ~2x normal (briefly)

## Best Practices

### Production Deployment

1. **Always use graceful shutdown** in production
2. **Set appropriate timeouts** based on workload
3. **Monitor shutdown logs** for issues
4. **Test reload procedures** regularly
5. **Use health checks** to verify status

## Contributing

When adding new background services:

1. **Implement ShutdownAwareTask** for new services
2. **Register with ShutdownCoordinator** in server startup
3. **Add appropriate logging** for shutdown events
4. **Update test suite** to cover new functionality
5. **Document configuration options** in this file

## References

- [Server Module Documentation](src/server/mod.rs)
- [Shutdown Coordinator](src/server/shutdown.rs)
- [Health Check Service](src/health/mod.rs)
- [Backup Service](src/database/backup.rs)
- [Response Cache](src/cache/mod.rs)
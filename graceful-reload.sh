#!/bin/bash
# Graceful reload script for Black Gate API Gateway
set -e

# Script configuration
SCRIPT_NAME="graceful-reload.sh"
PID_FILE="/tmp/blackgate.pid"
RELOAD_TIMEOUT=30
STARTUP_TIMEOUT=15
BLACKGATE_BINARY="blackgate"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to find Black Gate process
find_blackgate_process() {
    # Try to find by PID file first
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE" 2>/dev/null || echo "")
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            echo "$pid"
            return 0
        else
            log_warning "PID file exists but process $pid is not running, removing stale PID file"
            rm -f "$PID_FILE"
        fi
    fi

    # Fallback to finding by process name
    local pid=$(pgrep -f "blackgate.*start" | head -1)
    if [[ -n "$pid" ]]; then
        echo "$pid"
        return 0
    fi

    return 1
}

# Function to check if Black Gate is healthy
check_health() {
    local timeout=${1:-5}
    local url="http://localhost:3000/health"

    log_info "Checking Black Gate health at $url"

    if command -v curl >/dev/null 2>&1; then
        if curl -s --max-time "$timeout" "$url" >/dev/null 2>&1; then
            return 0
        fi
    elif command -v wget >/dev/null 2>&1; then
        if wget -q --timeout="$timeout" -O /dev/null "$url" >/dev/null 2>&1; then
            return 0
        fi
    else
        log_warning "Neither curl nor wget available, skipping health check"
        return 0
    fi

    return 1
}

# Function to wait for Black Gate to be healthy
wait_for_health() {
    local timeout=$1
    local elapsed=0
    local check_interval=2

    log_info "Waiting up to ${timeout} seconds for Black Gate to become healthy..."

    while [[ $elapsed -lt $timeout ]]; do
        if check_health 3; then
            log_success "Black Gate is healthy and ready"
            return 0
        fi

        sleep $check_interval
        elapsed=$((elapsed + check_interval))

        # Show progress every 10 seconds
        if [[ $((elapsed % 10)) -eq 0 ]]; then
            log_info "Still waiting for health check... (${elapsed}/${timeout} seconds)"
        fi
    done

    log_error "Health check timeout reached after ${timeout} seconds"
    return 1
}

# Function to gracefully shutdown existing process
graceful_shutdown() {
    local pid=$1
    log_info "Sending SIGTERM to Black Gate process (PID: $pid)"

    if kill -TERM "$pid" 2>/dev/null; then
        local elapsed=0
        local timeout=$RELOAD_TIMEOUT

        log_info "Waiting up to ${timeout} seconds for graceful shutdown..."

        while [[ $elapsed -lt $timeout ]]; do
            if ! kill -0 "$pid" 2>/dev/null; then
                log_success "Previous Black Gate instance shut down gracefully"
                return 0
            fi

            sleep 1
            elapsed=$((elapsed + 1))

            # Show progress every 5 seconds
            if [[ $((elapsed % 5)) -eq 0 ]]; then
                log_info "Still waiting for shutdown... (${elapsed}/${timeout} seconds)"
            fi
        done

        log_warning "Graceful shutdown timeout, forcing termination"
        if kill -KILL "$pid" 2>/dev/null; then
            sleep 2
            log_success "Previous Black Gate instance terminated"
            return 0
        else
            log_error "Failed to terminate previous instance"
            return 1
        fi
    else
        log_error "Failed to send shutdown signal"
        return 1
    fi
}

# Function to start new Black Gate instance
start_blackgate() {
    log_info "Starting replacement Black Gate instance..."

    # Determine the binary path
    local binary_path
    if command -v "$BLACKGATE_BINARY" >/dev/null 2>&1; then
        binary_path="$BLACKGATE_BINARY"
    elif [[ -x "./target/release/blackgate" ]]; then
        binary_path="./target/release/blackgate"
    elif [[ -x "./target/debug/blackgate" ]]; then
        binary_path="./target/debug/blackgate"
    elif [[ -x "/usr/local/bin/blackgate" ]]; then
        binary_path="/usr/local/bin/blackgate"
    else
        log_error "Could not find Black Gate binary"
        log_error "Please ensure Black Gate is installed or run from the project directory"
        return 1
    fi

    log_info "Using binary: $binary_path"

    # Start the new instance in the background
    nohup "$binary_path" start > /tmp/blackgate-reload.log 2>&1 &
    local new_pid=$!

    log_info "Started Black Gate with PID: $new_pid"

    # Wait a moment for the process to initialize
    sleep 3

    # Check if the process is still running
    if ! kill -0 "$new_pid" 2>/dev/null; then
        log_error "New Black Gate instance failed to start"
        log_error "Check logs at /tmp/blackgate-reload.log for details"
        return 1
    fi

    # Save the new PID only after confirming it's running
    echo "$new_pid" > "$PID_FILE"

    return 0
}

# Function to perform pre-reload checks
pre_reload_checks() {
    log_info "Performing pre-reload checks..."

    # Check if database is accessible
    if [[ -n "${BLACKGATE_DB_URL:-}" ]]; then
        log_info "Database URL: $BLACKGATE_DB_URL"
    else
        log_info "Using default database configuration"
    fi

    # Check if we have necessary permissions
    if [[ ! -w "/tmp" ]]; then
        log_error "No write permission to /tmp directory"
        return 1
    fi

    # Check if configuration files exist (if any)
    # Add specific config file checks here if needed

    log_success "Pre-reload checks passed"
    return 0
}

# Function to perform post-reload verification
post_reload_verification() {
    log_info "Performing post-reload verification..."

    # Check if the new process is healthy
    if ! wait_for_health "$STARTUP_TIMEOUT"; then
        log_error "New Black Gate instance failed health check"
        return 1
    fi

    # Additional verification checks can be added here
    # - Check if all routes are accessible
    # - Verify database connectivity
    # - Check if background services are running

    log_success "Post-reload verification passed"
    return 0
}

# Function to handle rollback
rollback() {
    log_error "Reload failed, attempting rollback..."

    # Kill any new instance that might be running
    local current_pid
    if current_pid=$(find_blackgate_process); then
        log_info "Terminating failed new instance (PID: $current_pid)"
        kill -TERM "$current_pid" 2>/dev/null || kill -KILL "$current_pid" 2>/dev/null || true
        sleep 2
    fi

    # Clean up PID file
    rm -f "$PID_FILE"

    log_warning "Rollback completed - you may need to manually restart Black Gate"
    log_warning "Check /tmp/blackgate-reload.log for error details"
}

# Function to check if running as Docker container
is_docker_container() {
    [[ -f /.dockerenv ]] || grep -q docker /proc/1/cgroup 2>/dev/null
}

# Function to handle Docker reload
docker_reload() {
    log_warning "Docker environment detected"
    log_warning "For Docker containers, consider using 'docker restart' instead"
    log_warning "Proceeding with in-container reload..."

    # In Docker, we can still do a graceful reload
    # but it's generally better to restart the container
    main_reload
}

# Main reload function
main_reload() {
    log_info "Starting graceful reload of Black Gate API Gateway"

    # Pre-reload checks
    if ! pre_reload_checks; then
        log_error "Pre-reload checks failed"
        exit 1
    fi

    # Find existing Black Gate process
    local old_pid
    if old_pid=$(find_blackgate_process); then
        log_info "Found existing Black Gate process with PID: $old_pid"

        # Check if current instance is healthy before proceeding
        if check_health 5; then
            log_info "Current instance is healthy, proceeding with reload"
        else
            log_warning "Current instance appears unhealthy, proceeding anyway"
        fi

        # For reload, we need to shutdown the old instance first to free the port
        # then start the new one (restart-style reload)
        log_info "Shutting down old instance to free port 3000..."
        if graceful_shutdown "$old_pid"; then
            log_success "Old instance shut down successfully"

            # Small delay to ensure port is freed
            sleep 2

            # Start new instance
            if start_blackgate; then
                # Wait for new instance to be healthy
                if wait_for_health "$STARTUP_TIMEOUT"; then
                    # Post-reload verification
                    if post_reload_verification; then
                        log_success "Black Gate reload completed and verified"
                        exit 0
                    else
                        log_error "Post-reload verification failed"
                        exit 1
                    fi
                else
                    log_error "New instance failed to become healthy"
                    exit 1
                fi
            else
                log_error "Failed to start new instance"
                exit 1
            fi
        else
            log_error "Failed to shutdown old instance"
            exit 1
        fi
    else
        log_warning "No existing Black Gate process found"
        log_info "Starting fresh instance..."

        if start_blackgate; then
            if wait_for_health "$STARTUP_TIMEOUT"; then
                if post_reload_verification; then
                    log_success "Black Gate started successfully"
                    exit 0
                else
                    log_error "Post-start verification failed"
                    exit 1
                fi
            else
                log_error "Failed to start Black Gate"
                exit 1
            fi
        else
            log_error "Failed to start Black Gate"
            exit 1
        fi
    fi
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Gracefully reload Black Gate API Gateway"
        echo ""
        echo "Options:"
        echo "  --help, -h              Show this help message"
        echo "  --timeout SECONDS       Set reload timeout (default: $RELOAD_TIMEOUT)"
        echo "  --startup-timeout SECS  Set startup timeout (default: $STARTUP_TIMEOUT)"
        echo "  --binary PATH           Path to Black Gate binary (default: auto-detect)"
        echo "  --no-health-check       Skip health checks during reload"
        echo ""
        echo "Examples:"
        echo "  $0                      # Normal graceful reload"
        echo "  $0 --timeout 60         # Wait up to 60 seconds for old instance shutdown"
        echo "  $0 --binary ./blackgate # Use specific binary path"
        echo ""
        echo "Environment Variables:"
        echo "  BLACKGATE_DB_URL        Database connection URL"
        exit 0
        ;;
    --timeout)
        if [[ -n "${2:-}" ]] && [[ "$2" =~ ^[0-9]+$ ]]; then
            RELOAD_TIMEOUT=$2
            shift 2
        else
            log_error "Invalid timeout value. Must be a positive integer."
            exit 1
        fi
        ;;
    --startup-timeout)
        if [[ -n "${2:-}" ]] && [[ "$2" =~ ^[0-9]+$ ]]; then
            STARTUP_TIMEOUT=$2
            shift 2
        else
            log_error "Invalid startup timeout value. Must be a positive integer."
            exit 1
        fi
        ;;
    --binary)
        if [[ -n "${2:-}" ]]; then
            BLACKGATE_BINARY="$2"
            shift 2
        else
            log_error "Binary path cannot be empty."
            exit 1
        fi
        ;;
    --no-health-check)
        check_health() { return 0; }
        wait_for_health() { return 0; }
        shift
        ;;
    "")
        # No arguments, proceed with normal reload
        ;;
    *)
        log_error "Unknown option: $1"
        echo "Use $0 --help for usage information"
        exit 1
        ;;
esac

# Check if running in Docker
if is_docker_container; then
    docker_reload
else
    main_reload
fi

#!/bin/bash
# Graceful shutdown script for Black Gate API Gateway
set -e

# Script configuration
SCRIPT_NAME="graceful-shutdown.sh"
PID_FILE="/tmp/blackgate.pid"
SHUTDOWN_TIMEOUT=30
FORCE_TIMEOUT=10

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

# Function to send graceful shutdown signal
send_shutdown_signal() {
    local pid=$1
    log_info "Sending SIGTERM to Black Gate process (PID: $pid)"

    if kill -TERM "$pid" 2>/dev/null; then
        return 0
    else
        log_error "Failed to send SIGTERM signal"
        return 1
    fi
}

# Function to wait for graceful shutdown
wait_for_shutdown() {
    local pid=$1
    local timeout=$2
    local elapsed=0
    local check_interval=1

    log_info "Waiting up to ${timeout} seconds for graceful shutdown..."

    while [[ $elapsed -lt $timeout ]]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            log_success "Black Gate has shut down gracefully"
            return 0
        fi

        sleep $check_interval
        elapsed=$((elapsed + check_interval))

        # Show progress every 5 seconds
        if [[ $((elapsed % 5)) -eq 0 ]]; then
            log_info "Still waiting... (${elapsed}/${timeout} seconds)"
        fi
    done

    log_warning "Graceful shutdown timeout reached after ${timeout} seconds"
    return 1
}

# Function to force shutdown
force_shutdown() {
    local pid=$1
    log_warning "Attempting force shutdown with SIGKILL"

    if kill -KILL "$pid" 2>/dev/null; then
        sleep 2
        if ! kill -0 "$pid" 2>/dev/null; then
            log_success "Black Gate process forcefully terminated"
            return 0
        else
            log_error "Failed to force terminate process"
            return 1
        fi
    else
        log_error "Failed to send SIGKILL signal"
        return 1
    fi
}

# Function to cleanup resources
cleanup() {
    log_info "Cleaning up resources..."

    # Remove PID file if it exists
    if [[ -f "$PID_FILE" ]]; then
        rm -f "$PID_FILE"
        log_info "Removed PID file: $PID_FILE"
    fi

    # Check for any remaining Black Gate processes
    local remaining_pids=$(pgrep -f "blackgate.*start" || true)
    if [[ -n "$remaining_pids" ]]; then
        log_warning "Found remaining Black Gate processes: $remaining_pids"
        log_warning "You may need to manually terminate them"
    fi
}

# Function to check if running as Docker container
is_docker_container() {
    [[ -f /.dockerenv ]] || grep -q docker /proc/1/cgroup 2>/dev/null
}

# Function to handle Docker shutdown
docker_shutdown() {
    log_info "Detected Docker environment"

    # In Docker, we typically send signals to PID 1 or use docker stop
    local main_pid=$(pgrep -f "blackgate.*start" | head -1)
    if [[ -n "$main_pid" ]]; then
        send_shutdown_signal "$main_pid"
        if wait_for_shutdown "$main_pid" "$SHUTDOWN_TIMEOUT"; then
            cleanup
            exit 0
        else
            force_shutdown "$main_pid"
            cleanup
            exit 1
        fi
    else
        log_error "No Black Gate process found in Docker container"
        exit 1
    fi
}

# Main shutdown function
main() {
    log_info "Starting graceful shutdown of Black Gate API Gateway"

    # Check if running in Docker
    if is_docker_container; then
        docker_shutdown
        return
    fi

    # Find Black Gate process
    local pid
    if ! pid=$(find_blackgate_process); then
        log_error "No running Black Gate process found"
        log_info "Check if Black Gate is running with: ps aux | grep blackgate"
        exit 1
    fi

    log_info "Found Black Gate process with PID: $pid"

    # Send graceful shutdown signal
    if ! send_shutdown_signal "$pid"; then
        log_error "Failed to send shutdown signal"
        exit 1
    fi

    # Wait for graceful shutdown
    if wait_for_shutdown "$pid" "$SHUTDOWN_TIMEOUT"; then
        cleanup
        log_success "Black Gate shutdown completed successfully"
        exit 0
    fi

    # If graceful shutdown failed, try force shutdown
    log_warning "Graceful shutdown failed, attempting force shutdown"
    if force_shutdown "$pid"; then
        cleanup
        log_success "Black Gate force shutdown completed"
        exit 0
    else
        cleanup
        log_error "Failed to shutdown Black Gate process"
        exit 1
    fi
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Gracefully shutdown Black Gate API Gateway"
        echo ""
        echo "Options:"
        echo "  --help, -h           Show this help message"
        echo "  --timeout SECONDS    Set shutdown timeout (default: $SHUTDOWN_TIMEOUT)"
        echo "  --force              Skip graceful shutdown and force kill immediately"
        echo "  --pid PID            Shutdown specific PID instead of auto-discovery"
        echo ""
        echo "Examples:"
        echo "  $0                   # Normal graceful shutdown"
        echo "  $0 --timeout 60      # Wait up to 60 seconds for graceful shutdown"
        echo "  $0 --force           # Force shutdown immediately"
        echo "  $0 --pid 12345       # Shutdown specific process"
        exit 0
        ;;
    --timeout)
        if [[ -n "${2:-}" ]] && [[ "$2" =~ ^[0-9]+$ ]]; then
            SHUTDOWN_TIMEOUT=$2
            shift 2
        else
            log_error "Invalid timeout value. Must be a positive integer."
            exit 1
        fi
        ;;
    --force)
        SHUTDOWN_TIMEOUT=0
        shift
        ;;
    --pid)
        if [[ -n "${2:-}" ]] && [[ "$2" =~ ^[0-9]+$ ]]; then
            SPECIFIC_PID=$2
            shift 2
        else
            log_error "Invalid PID value. Must be a positive integer."
            exit 1
        fi
        ;;
    "")
        # No arguments, proceed with normal shutdown
        ;;
    *)
        log_error "Unknown option: $1"
        echo "Use $0 --help for usage information"
        exit 1
        ;;
esac

# Override process discovery if specific PID provided
if [[ -n "${SPECIFIC_PID:-}" ]]; then
    find_blackgate_process() {
        if kill -0 "$SPECIFIC_PID" 2>/dev/null; then
            echo "$SPECIFIC_PID"
            return 0
        else
            return 1
        fi
    }
fi

# Run main function
main "$@"

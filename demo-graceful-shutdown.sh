#!/bin/bash
# Demonstration script for Black Gate graceful shutdown functionality
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
DEMO_DIR="/tmp/blackgate-demo"
DEMO_DB="$DEMO_DIR/demo.db"
PID_FILE="/tmp/blackgate.pid"
LOG_FILE="$DEMO_DIR/demo.log"

# Cleanup function
cleanup() {
    echo -e "${YELLOW}🧹 Cleaning up demo resources...${NC}"

    # Kill any remaining processes
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE" 2>/dev/null || echo "")
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
        rm -f "$PID_FILE"
    fi

    # Kill any remaining blackgate processes
    pkill -f "blackgate.*start" 2>/dev/null || true

    # Clean up demo directory
    rm -rf "$DEMO_DIR"

    echo -e "${GREEN}✅ Demo cleanup complete${NC}"
}

# Set up trap for cleanup
trap cleanup EXIT

# Logging functions
print_header() {
    echo
    echo -e "${BOLD}${CYAN}=====================================${NC}"
    echo -e "${BOLD}${CYAN} $1 ${NC}"
    echo -e "${BOLD}${CYAN}=====================================${NC}"
    echo
}

print_step() {
    echo -e "${BLUE}🔷 $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_info() {
    echo -e "${CYAN}ℹ️  $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Wait with dots animation
wait_with_dots() {
    local duration=$1
    local message=$2

    echo -n -e "${BLUE}$message${NC}"
    for ((i=1; i<=duration; i++)); do
        echo -n "."
        sleep 1
    done
    echo
}

# Setup demo environment
setup_demo() {
    print_step "Setting up demo environment"

    mkdir -p "$DEMO_DIR"
    export BLACKGATE_DB_URL="sqlite://$DEMO_DB"

    # Check for binary
    if command -v blackgate >/dev/null 2>&1; then
        BLACKGATE_BIN="blackgate"
    elif [[ -x "./target/release/blackgate" ]]; then
        BLACKGATE_BIN="./target/release/blackgate"
    elif [[ -x "./target/debug/blackgate" ]]; then
        BLACKGATE_BIN="./target/debug/blackgate"
    else
        print_error "Black Gate binary not found. Please build first with: cargo build --release"
        exit 1
    fi

    print_success "Demo environment ready"
    print_info "Using binary: $BLACKGATE_BIN"
    print_info "Database: $DEMO_DB"
}

# Initialize database
init_database() {
    print_step "Initializing database"

    if "$BLACKGATE_BIN" migrate apply-all > "$LOG_FILE" 2>&1; then
        print_success "Database initialized successfully"
    else
        print_error "Failed to initialize database"
        cat "$LOG_FILE"
        exit 1
    fi
}

# Start Black Gate
start_blackgate() {
    print_step "Starting Black Gate API Gateway"

    # Start in background
    nohup "$BLACKGATE_BIN" start > "$LOG_FILE" 2>&1 &
    local pid=$!

    # Save PID
    echo "$pid" > "$PID_FILE"

    print_info "Started with PID: $pid"

    # Wait for startup
    wait_with_dots 3 "Waiting for startup"

    # Check if healthy
    local max_attempts=10
    local attempt=0

    while [[ $attempt -lt $max_attempts ]]; do
        if curl -s -f "http://localhost:3000/health" >/dev/null 2>&1; then
            print_success "Black Gate is healthy and ready!"
            print_info "🌐 Web interface: http://localhost:3000"
            print_info "🔍 Health check: http://localhost:3000/health"
            return 0
        fi

        if ! kill -0 "$pid" 2>/dev/null; then
            print_error "Black Gate process died during startup"
            cat "$LOG_FILE"
            exit 1
        fi

        sleep 1
        attempt=$((attempt + 1))
    done

    print_error "Black Gate failed to become healthy"
    exit 1
}

# Show running services
show_status() {
    print_step "Checking running services"

    local pid=$(cat "$PID_FILE" 2>/dev/null || echo "")
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        print_info "Main process: PID $pid"

        # Check for background tasks
        local bg_tasks=$(pgrep -P "$pid" 2>/dev/null || echo "")
        if [[ -n "$bg_tasks" ]]; then
            print_info "Background tasks: $(echo $bg_tasks | wc -w) running"
        fi

        # Show process tree
        if command -v pstree >/dev/null 2>&1; then
            echo -e "${CYAN}Process tree:${NC}"
            pstree -p "$pid" 2>/dev/null || ps --forest -p "$pid" 2>/dev/null || true
        fi

        # Test endpoints
        echo -e "${CYAN}Testing endpoints:${NC}"
        if curl -s "http://localhost:3000/health" | grep -q "OK"; then
            print_success "Health endpoint: OK"
        else
            print_warning "Health endpoint: Not responding"
        fi

        if curl -s "http://localhost:3000/" >/dev/null 2>&1; then
            print_success "Web interface: Accessible"
        else
            print_info "Web interface: Default response"
        fi
    else
        print_error "No Black Gate process found"
        return 1
    fi
}

# Demonstrate graceful shutdown
demo_graceful_shutdown() {
    print_step "Demonstrating graceful shutdown with SIGTERM"

    local pid=$(cat "$PID_FILE" 2>/dev/null || echo "")
    if [[ -z "$pid" ]] || ! kill -0 "$pid" 2>/dev/null; then
        print_error "No running Black Gate process found"
        return 1
    fi

    print_info "Sending SIGTERM to PID $pid"

    # Send SIGTERM
    kill -TERM "$pid"

    # Monitor shutdown
    local max_wait=15
    local elapsed=0

    while [[ $elapsed -lt $max_wait ]]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            print_success "Graceful shutdown completed in ${elapsed} seconds"

            # Check that endpoints are no longer accessible
            if ! curl -s -f "http://localhost:3000/health" >/dev/null 2>&1; then
                print_success "Server stopped accepting connections"
            fi

            return 0
        fi

        # Show progress
        if [[ $((elapsed % 3)) -eq 0 ]]; then
            print_info "Still shutting down... (${elapsed}/${max_wait}s)"
        fi

        sleep 1
        elapsed=$((elapsed + 1))
    done

    print_error "Graceful shutdown timeout after ${max_wait} seconds"
    return 1
}

# Demonstrate shutdown script
demo_shutdown_script() {
    print_step "Demonstrating graceful shutdown script"

    # Start Black Gate again
    start_blackgate

    print_info "Testing ./graceful-shutdown.sh script"

    if [[ -x "./graceful-shutdown.sh" ]]; then
        if timeout 20 ./graceful-shutdown.sh; then
            print_success "Shutdown script completed successfully"

            # Verify process is gone
            if [[ -f "$PID_FILE" ]]; then
                local pid=$(cat "$PID_FILE" 2>/dev/null || echo "")
                if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                    print_error "Process still running after shutdown script"
                    return 1
                fi
            fi

            return 0
        else
            print_error "Shutdown script failed or timed out"
            return 1
        fi
    else
        print_error "Graceful shutdown script not found or not executable"
        return 1
    fi
}

# Show logs
show_logs() {
    print_step "Showing recent logs"

    if [[ -f "$LOG_FILE" ]]; then
        echo -e "${CYAN}Last 20 lines of logs:${NC}"
        tail -20 "$LOG_FILE" || true
    else
        print_info "No log file found"
    fi
}

# Main demonstration
main() {
    print_header "BLACK GATE GRACEFUL SHUTDOWN DEMO"

    echo -e "${BOLD}This demo shows Black Gate's graceful shutdown capabilities:${NC}"
    echo "• Background service coordination"
    echo "• Signal-based shutdown (SIGTERM/SIGINT)"
    echo "• Graceful shutdown script"
    echo "• Clean resource cleanup"
    echo

    # Setup
    setup_demo
    init_database

    # Demo 1: Basic startup and status
    print_header "DEMO 1: STARTUP & STATUS"
    start_blackgate
    show_status

    # Demo 2: Signal-based shutdown
    print_header "DEMO 2: SIGNAL-BASED SHUTDOWN"
    demo_graceful_shutdown

    # Demo 3: Script-based shutdown
    print_header "DEMO 3: SCRIPT-BASED SHUTDOWN"
    demo_shutdown_script

    # Show logs
    print_header "LOGS"
    show_logs

    # Summary
    print_header "DEMO COMPLETE"
    print_success "🎉 All graceful shutdown demonstrations completed successfully!"
    echo
    echo -e "${BOLD}Key takeaways:${NC}"
    echo "• Black Gate responds to SIGTERM and SIGINT signals"
    echo "• Background services shut down cleanly"
    echo "• Graceful shutdown typically takes 2-5 seconds"
    echo "• Scripts provide additional automation and error handling"
    echo
    echo -e "${BOLD}Next steps:${NC}"
    echo "• Try the reload script: ./graceful-reload.sh"
    echo "• Integrate with your process manager (systemd, supervisor, etc.)"
    echo "• Configure appropriate timeouts for your environment"
    echo
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo
        echo "Demonstrate Black Gate graceful shutdown functionality"
        echo
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --verbose      Show verbose output"
        echo "  --no-cleanup   Skip cleanup after demo"
        echo
        exit 0
        ;;
    --verbose)
        set -x
        shift
        ;;
    --no-cleanup)
        trap - EXIT
        shift
        ;;
    "")
        # No arguments, proceed with demo
        ;;
    *)
        print_error "Unknown option: $1"
        echo "Use $0 --help for usage information"
        exit 1
        ;;
esac

# Run the demo
main "$@"

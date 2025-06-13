#!/bin/bash
# Test script for Black Gate graceful shutdown functionality
# To test this, the PID file must exist, which is only created when the server is started with the startup.sh script
# So build a release of Blackgate, move it to /usr/local/bin/blackgate and run ./startup.sh, then ./test-graceful-shutdown.sh
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
TEST_DIR="/tmp/blackgate-test"
TEST_DB="$TEST_DIR/test.db"
PID_FILE="/tmp/blackgate.pid"
LOG_FILE="$TEST_DIR/test.log"

# Cleanup function
cleanup() {
    echo -e "${YELLOW}Cleaning up test resources...${NC}"

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

    # Clean up test directory
    rm -rf "$TEST_DIR"
}

# Set up trap for cleanup
trap cleanup EXIT

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

# Test setup
setup_test_environment() {
    log_info "Setting up test environment..."

    mkdir -p "$TEST_DIR"

    # Set test database URL
    export BLACKGATE_DB_URL="sqlite://$TEST_DB"

    log_success "Test environment setup complete"
}

# Check if Black Gate binary exists
check_binary() {
    log_info "Checking for Black Gate binary..."

    if command -v blackgate >/dev/null 2>&1; then
        BLACKGATE_BIN="blackgate"
    elif [[ -x "./target/release/blackgate" ]]; then
        BLACKGATE_BIN="./target/release/blackgate"
    elif [[ -x "./target/debug/blackgate" ]]; then
        BLACKGATE_BIN="./target/debug/blackgate"
    else
        log_error "Black Gate binary not found"
        log_error "Please build the project first: cargo build --release"
        exit 1
    fi

    log_success "Found Black Gate binary: $BLACKGATE_BIN"
}

# Initialize test database
init_database() {
    log_info "Initializing test database..."

    # Run migrations
    if ! "$BLACKGATE_BIN" migrate apply-all > "$LOG_FILE" 2>&1; then
        log_error "Failed to initialize database"
        cat "$LOG_FILE"
        exit 1
    fi

    log_success "Database initialized successfully"
}

# Start Black Gate in background
start_blackgate() {
    log_info "Starting Black Gate for testing..."

    # Start Black Gate in background
    nohup "$BLACKGATE_BIN" start > "$LOG_FILE" 2>&1 &
    local pid=$!

    # Save PID
    echo "$pid" > "$PID_FILE"

    log_info "Started Black Gate with PID: $pid"

    # Wait for startup
    local max_wait=15
    local waited=0

    while [[ $waited -lt $max_wait ]]; do
        if kill -0 "$pid" 2>/dev/null; then
            # Check if health endpoint is responsive
            if curl -s -f "http://localhost:3000/health" >/dev/null 2>&1; then
                log_success "Black Gate is healthy and ready"
                return 0
            fi
        else
            log_error "Black Gate process died during startup"
            cat "$LOG_FILE"
            exit 1
        fi

        sleep 1
        waited=$((waited + 1))
    done

    log_error "Black Gate failed to become healthy within $max_wait seconds"
    cat "$LOG_FILE"
    exit 1
}

# Test basic functionality
test_basic_functionality() {
    log_info "Testing basic functionality..."

    # Test health endpoint
    if curl -s -f "http://localhost:3000/health" | grep -q "OK"; then
        log_success "Health endpoint responding correctly"
    else
        log_error "Health endpoint not responding"
        return 1
    fi

    # Test web interface
    if curl -s -f "http://localhost:3000/" >/dev/null 2>&1; then
        log_success "Web interface accessible"
    else
        log_warning "Web interface not accessible (this might be expected)"
    fi

    return 0
}

# Test graceful shutdown
test_graceful_shutdown() {
    log_info "Testing graceful shutdown..."

    # Get the current PID
    local pid
    if ! pid=$(cat "$PID_FILE" 2>/dev/null); then
        log_error "Could not read PID file"
        return 1
    fi

    log_info "Sending graceful shutdown signal to PID: $pid"

    # Send SIGTERM
    if ! kill -TERM "$pid" 2>/dev/null; then
        log_error "Failed to send SIGTERM signal"
        return 1
    fi

    # Wait for graceful shutdown
    local max_wait=10
    local waited=0

    while [[ $waited -lt $max_wait ]]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            log_success "Black Gate shut down gracefully in ${waited} seconds"
            return 0
        fi

        sleep 1
        waited=$((waited + 1))
    done

    log_error "Graceful shutdown timeout after $max_wait seconds"
    return 1
}

# Test shutdown script
test_shutdown_script() {
    log_info "Testing graceful shutdown script..."

    # Start Black Gate again
    start_blackgate

    # Test the shutdown script
    if [[ -x "./graceful-shutdown.sh" ]]; then
        log_info "Running graceful shutdown script..."

        if timeout 15 ./graceful-shutdown.sh; then
            log_success "Graceful shutdown script completed successfully"

            # Verify process is gone
            if [[ -f "$PID_FILE" ]]; then
                local pid=$(cat "$PID_FILE" 2>/dev/null || echo "")
                if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                    log_error "Process still running after shutdown script"
                    return 1
                fi
            fi

            return 0
        else
            log_error "Graceful shutdown script failed or timed out"
            return 1
        fi
    else
        log_error "Graceful shutdown script not found or not executable"
        return 1
    fi
}

# Test reload script
test_reload_script() {
    log_info "Testing graceful reload script..."

    # Start Black Gate
    start_blackgate
    local original_pid=$(cat "$PID_FILE")

    # Test the reload script
    if [[ -x "./graceful-reload.sh" ]]; then
        log_info "Running graceful reload script..."

        if timeout 30 ./graceful-reload.sh; then
            log_success "Graceful reload script completed successfully"

            # Verify new process is running
            if [[ -f "$PID_FILE" ]]; then
                local new_pid=$(cat "$PID_FILE" 2>/dev/null || echo "")
                if [[ -n "$new_pid" ]] && kill -0 "$new_pid" 2>/dev/null; then
                    if [[ "$new_pid" != "$original_pid" ]]; then
                        log_success "New process started with PID: $new_pid"

                        # Test that new instance is healthy
                        sleep 2
                        if curl -s -f "http://localhost:3000/health" >/dev/null 2>&1; then
                            log_success "New instance is healthy"
                            return 0
                        else
                            log_error "New instance is not healthy"
                            return 1
                        fi
                    else
                        log_error "PID did not change during reload"
                        return 1
                    fi
                else
                    log_error "No healthy process running after reload"
                    return 1
                fi
            else
                log_error "No PID file after reload"
                return 1
            fi
        else
            log_error "Graceful reload script failed or timed out"
            return 1
        fi
    else
        log_error "Graceful reload script not found or not executable"
        return 1
    fi
}

# Main test function
run_tests() {
    local failed_tests=0

    log_info "Starting Black Gate graceful shutdown tests"
    echo

    # Setup
    setup_test_environment
    check_binary
    init_database

    # Test 1: Basic functionality
    echo -e "${BLUE}=== Test 1: Basic Functionality ===${NC}"
    if test_basic_functionality; then
        log_success "✅ Basic functionality test passed"
    else
        log_error "❌ Basic functionality test failed"
        failed_tests=$((failed_tests + 1))
    fi
    echo

    # Test 2: Graceful shutdown signal
    echo -e "${BLUE}=== Test 2: Graceful Shutdown Signal ===${NC}"
    if test_graceful_shutdown; then
        log_success "✅ Graceful shutdown signal test passed"
    else
        log_error "❌ Graceful shutdown signal test failed"
        failed_tests=$((failed_tests + 1))
    fi
    echo

    # Test 3: Shutdown script
    echo -e "${BLUE}=== Test 3: Shutdown Script ===${NC}"
    if test_shutdown_script; then
        log_success "✅ Shutdown script test passed"
    else
        log_error "❌ Shutdown script test failed"
        failed_tests=$((failed_tests + 1))
    fi
    echo

    # Test 4: Reload script
    echo -e "${BLUE}=== Test 4: Reload Script ===${NC}"
    if test_reload_script; then
        log_success "✅ Reload script test passed"
    else
        log_error "❌ Reload script test failed"
        failed_tests=$((failed_tests + 1))
    fi
    echo

    # Summary
    echo -e "${BLUE}=== Test Summary ===${NC}"
    if [[ $failed_tests -eq 0 ]]; then
        log_success "🎉 All tests passed! Graceful shutdown functionality is working correctly."
        exit 0
    else
        log_error "💥 $failed_tests test(s) failed. Please check the implementation."
        exit 1
    fi
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Test Black Gate graceful shutdown functionality"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --verbose      Show verbose output"
        echo "  --no-cleanup   Skip cleanup after tests"
        echo ""
        echo "Environment Variables:"
        echo "  BLACKGATE_DB_URL   Override database URL for testing"
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
        # No arguments, proceed with tests
        ;;
    *)
        log_error "Unknown option: $1"
        echo "Use $0 --help for usage information"
        exit 1
        ;;
esac

# Run the tests
run_tests

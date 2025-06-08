#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Test configuration
GATEWAY_URL="http://localhost:3000"
UPSTREAM_URL="http://localhost:8080"
RESULTS_DIR="./load-test-results"

# Create results directory
mkdir -p "$RESULTS_DIR"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

echo -e "${BLUE}🔥 Starting BlackGate Load Testing Suite${NC}"
echo -e "${CYAN}Results will be saved to: $RESULTS_DIR${NC}"
echo ""

# Function to run a wrk test and save results
run_wrk_test() {
    local test_name=$1
    local url=$2
    local threads=$3
    local connections=$4
    local duration=$5
    local script=$6
    
    echo -e "${YELLOW}🧪 Running test: $test_name${NC}"
    echo "   URL: $url"
    echo "   Threads: $threads, Connections: $connections, Duration: $duration"
    
    local output_file="$RESULTS_DIR/${TIMESTAMP}_${test_name}.txt"
    
    if [ -n "$script" ]; then
        echo "   Script: $script"
        wrk -t"$threads" -c"$connections" -d"$duration" -s "$script" "$url" | tee "$output_file"
    else
        wrk -t"$threads" -c"$connections" -d"$duration" "$url" | tee "$output_file"
    fi
    
    echo -e "${GREEN}✅ Test completed: $test_name${NC}"
    echo ""
}

# Function to check if services are running
check_services() {
    echo -e "${BLUE}🔍 Checking services...${NC}"
    
    if ! curl -s -f "$UPSTREAM_URL/health" > /dev/null; then
        echo -e "${RED}❌ Upstream service not available at $UPSTREAM_URL${NC}"
        echo "Please run './setup-loadtest.sh' first"
        exit 1
    fi
    
    if ! curl -s -f "$GATEWAY_URL/health" > /dev/null; then
        echo -e "${RED}❌ Gateway service not available at $GATEWAY_URL${NC}"
        echo "Please run './setup-loadtest.sh' first"
        exit 1
    fi
    
    echo -e "${GREEN}✅ All services are running${NC}"
    echo ""
}

# Function to run baseline tests (direct to upstream)
run_baseline_tests() {
    echo -e "${CYAN}📊 Running baseline tests (direct upstream)...${NC}"
    
    run_wrk_test "baseline_fast_light" "$UPSTREAM_URL/fast" 2 10 "30s"
    run_wrk_test "baseline_fast_medium" "$UPSTREAM_URL/fast" 4 50 "60s"
    run_wrk_test "baseline_fast_heavy" "$UPSTREAM_URL/fast" 8 100 "60s"
    run_wrk_test "baseline_slow" "$UPSTREAM_URL/slow?delay=50" 4 25 "30s"
}

# Function to run gateway tests
run_gateway_tests() {
    echo -e "${CYAN}🚪 Running gateway tests...${NC}"
    
    run_wrk_test "gateway_fast_light" "$GATEWAY_URL/fast" 2 10 "30s"
    run_wrk_test "gateway_fast_medium" "$GATEWAY_URL/fast" 4 50 "60s"
    run_wrk_test "gateway_fast_heavy" "$GATEWAY_URL/fast" 8 100 "60s"
    run_wrk_test "gateway_slow" "$GATEWAY_URL/slow?delay=50" 4 25 "30s"
    
    # Test with scripts if they exist
    if [ -f "scripts/post-test.lua" ]; then
        run_wrk_test "gateway_post_json" "$GATEWAY_URL/json" 4 25 "30s" "scripts/post-test.lua"
    fi
    
    if [ -f "scripts/mixed-load.lua" ]; then
        run_wrk_test "gateway_mixed_load" "$GATEWAY_URL" 4 50 "60s" "scripts/mixed-load.lua"
    fi
}

# Function to run stress tests
run_stress_tests() {
    echo -e "${CYAN}💥 Running stress tests...${NC}"
    echo -e "${YELLOW}⚠️  These tests are designed to find breaking points${NC}"
    
    # Gradual increase in load
    run_wrk_test "stress_ramp_up_1" "$GATEWAY_URL/fast" 4 100 "30s"
    run_wrk_test "stress_ramp_up_2" "$GATEWAY_URL/fast" 8 200 "30s"
    run_wrk_test "stress_ramp_up_3" "$GATEWAY_URL/fast" 12 300 "30s"
    run_wrk_test "stress_ramp_up_4" "$GATEWAY_URL/fast" 16 500 "30s"
}

# Function to generate summary report
generate_summary() {
    echo -e "${BLUE}📋 Generating summary report...${NC}"
    
    local summary_file="$RESULTS_DIR/${TIMESTAMP}_summary.md"
    
    cat > "$summary_file" << EOF
# BlackGate Load Test Summary

**Test Run:** $(date)
**Gateway URL:** $GATEWAY_URL
**Upstream URL:** $UPSTREAM_URL

## Test Results

EOF
    
    # Process each result file
    for result_file in "$RESULTS_DIR"/${TIMESTAMP}_*.txt; do
        if [ -f "$result_file" ]; then
            local test_name=$(basename "$result_file" .txt | sed "s/${TIMESTAMP}_//")
            echo "### $test_name" >> "$summary_file"
            echo "\`\`\`" >> "$summary_file"
            head -20 "$result_file" >> "$summary_file"
            echo "\`\`\`" >> "$summary_file"
            echo "" >> "$summary_file"
        fi
    done
    
    echo -e "${GREEN}✅ Summary report generated: $summary_file${NC}"
}

# Main execution
main() {
    case "${1:-all}" in
        "baseline")
            # check_services
            run_baseline_tests
            ;;
        "gateway")
            # check_services
            run_gateway_tests
            ;;
        "stress")
            # check_services
            run_stress_tests
            ;;
        "all")
            # check_services
            run_baseline_tests
            run_gateway_tests
            generate_summary
            ;;
        "full")
            # check_services
            run_baseline_tests
            run_gateway_tests
            run_stress_tests
            generate_summary
            ;;
        *)
            echo -e "${YELLOW}Usage: $0 [baseline|gateway|stress|all|full]${NC}"
            echo ""
            echo "  baseline - Test upstream server directly (baseline performance)"
            echo "  gateway  - Test through BlackGate (measure overhead)"
            echo "  stress   - Run stress tests to find breaking points"
            echo "  all      - Run baseline + gateway tests (default)"
            echo "  full     - Run all tests including stress tests"
            exit 1
            ;;
    esac
}

# Run main function with arguments
main "$@"

echo -e "${GREEN}🎉 Load testing complete!${NC}"
echo -e "${CYAN}Check results in: $RESULTS_DIR${NC}"

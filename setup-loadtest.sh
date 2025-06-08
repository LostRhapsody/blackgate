#!/bin/bash

set -e

echo "🔧 Setting up BlackGate load testing environment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to wait for service to be ready
wait_for_service() {
    local service_name=$1
    local service_id=$2
    local max_attempts=30
    local attempt=1

    echo -e "${BLUE}⏳ Waiting for $service_name to be ready...${NC}"
    
    while [ $attempt -le $max_attempts ]; do
        if docker compose -f docker-compose.loadtest.yml ps --format json | jq -r --arg service "$service_id" '.[] | select(.Service == $service) | .Health' 2>/dev/null | grep -q "healthy"; then
            echo -e "${GREEN}✅ $service_name is ready!${NC}"
            return 0
        fi
        echo -e "${YELLOW}   Attempt $attempt/$max_attempts: $service_name not ready yet...${NC}"
        sleep 2
        ((attempt++))
    done
    
    echo -e "${RED}❌ $service_name failed to become ready after $max_attempts attempts${NC}"
    return 1
}

# Start the services
echo -e "${BLUE}🚀 Starting services with docker-compose...${NC}"
docker compose -f docker-compose.loadtest.yml up -d

# Wait for services to be healthy
# wait_for_service "Upstream Test Server" "upstream" || exit 1
# wait_for_service "BlackGate" "blackgate" || exit 1

echo -e "${GREEN}✅ Load testing environment is ready!${NC}"
echo ""
echo -e "${BLUE}📊 Available test endpoints (routes pre-configured):${NC}"
echo "  http://localhost:3000/fast      - Fast response endpoint"
echo "  http://localhost:3000/slow      - Slow response endpoint (configurable delay)"
echo "  http://localhost:3000/echo/*    - Echo endpoint"
echo "  http://localhost:3000/json      - JSON POST endpoint"
echo "  http://localhost:3000/error/*   - Error simulation endpoint"
echo "  http://localhost:3000/large/*   - Large response endpoint"
echo "  http://localhost:3000/resource/* - CRUD resource endpoint"
echo ""
echo -e "${BLUE}🧪 Direct upstream endpoints (for baseline testing):${NC}"
echo "  http://localhost:8080/fast      - Direct upstream fast"
echo "  http://localhost:8080/slow      - Direct upstream slow"
echo "  http://localhost:8080/health    - Upstream health"
echo ""
echo -e "${BLUE}🔥 Example wrk load test commands:${NC}"
echo "  # Test gateway fast endpoint"
echo "  wrk -t4 -c50 -d30s http://localhost:3000/fast"
echo ""
echo "  # Test direct upstream (baseline)"
echo "  wrk -t4 -c50 -d30s http://localhost:8080/fast"
echo ""
echo "  # Heavy load test"
echo "  wrk -t8 -c100 -d60s http://localhost:3000/fast"
echo ""
echo "  # POST test with JSON"
echo "  wrk -t4 -c50 -d30s -s scripts/post-test.lua http://localhost:3000/json"
echo ""
echo "  # Error endpoint test"
echo "  wrk -t4 -c50 -d30s http://localhost:3000/error/500"
echo ""
echo -e "${GREEN}🎯 Ready for load testing!${NC}"

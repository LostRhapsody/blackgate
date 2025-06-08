#!/bin/bash

set -e

echo "🔧 Tearing down and rebuilding BlackGate load test environment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🗑️  Stopping and removing containers, networks, and volumes...${NC}"
docker compose -f docker-compose.loadtest.yml down --volumes --remove-orphans

echo -e "${BLUE}🗑️  Removing associated images...${NC}"
docker compose -f docker-compose.loadtest.yml down --rmi all || echo -e "${YELLOW}⚠️  Some images may not exist yet${NC}"

echo -e "${BLUE}🧹 Cleaning up dangling images...${NC}"
docker image prune -f

echo -e "${BLUE}🔨 Building fresh containers with no cache...${NC}"
docker compose -f docker-compose.loadtest.yml build --no-cache

echo -e "${BLUE}🚀 Starting fresh containers...${NC}"
docker compose -f docker-compose.loadtest.yml up -d

echo -e "${GREEN}✅ Rebuild complete! Containers are starting up...${NC}"
echo -e "${YELLOW}ℹ️  Run ./setup-loadtest.sh to wait for services and see testing instructions${NC}"

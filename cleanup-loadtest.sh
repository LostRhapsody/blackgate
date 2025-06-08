#!/bin/bash

echo "🧹 Cleaning up load testing environment..."

# Stop and remove containers
docker compose -f docker-compose.loadtest.yml down --volumes --remove-orphans

# Remove any dangling images
docker image prune -f

# Optional: Remove test results (uncomment if desired)
# read -p "Remove test results? (y/N): " -n 1 -r
# echo
# if [[ $REPLY =~ ^[Yy]$ ]]; then
#     rm -rf ./load-test-results
#     echo "Test results removed"
# fi

echo "✅ Cleanup complete!"

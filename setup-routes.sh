#!/bin/bash

set -e

echo "🔧 Setting up BlackGate routes..."

# Initialize and clean database
echo "🗄️  Initializing database..."
mkdir -p /app/data
rm -f /app/data/blackgate.db /app/data/blackgate.db-shm /app/data/blackgate.db-wal
rm -f /app/blackgate.db /app/blackgate.db-shm /app/blackgate.db-wal
echo "   Database files cleaned"

echo "   Applying database migrations..."
blackgate migrate apply-all

# Configure BlackGate routes using CLI
echo "   Adding /fast route..."
blackgate add-route \
  --path "/fast" \
  --upstream "http://upstream:8080/fast" \
  --allowed-methods "GET" \
  --rate-limit-per-minute 0 \
  --rate-limit-per-hour 0

echo "   Adding /slow route..."
blackgate add-route \
  --path "/slow" \
  --upstream "http://upstream:8080/slow" \
  --allowed-methods "GET" \
  --rate-limit-per-minute 0 \
  --rate-limit-per-hour 0

echo "   Adding /echo route..."
blackgate add-route \
  --path "/echo/*" \
  --upstream "http://upstream:8080/echo/*" \
  --allowed-methods "GET" \
  --rate-limit-per-minute 0 \
  --rate-limit-per-hour 0

echo "   Adding /json route..."
blackgate add-route \
  --path "/json" \
  --upstream "http://upstream:8080/json" \
  --allowed-methods "POST" \
  --rate-limit-per-minute 0 \
  --rate-limit-per-hour 0

echo "   Adding /error route..."
blackgate add-route \
  --path "/error/*" \
  --upstream "http://upstream:8080/error/*" \
  --allowed-methods "GET" \
  --rate-limit-per-minute 0 \
  --rate-limit-per-hour 0

echo "   Adding /large route..."
blackgate add-route \
  --path "/large/*" \
  --upstream "http://upstream:8080/large/*" \
  --allowed-methods "GET" \
  --rate-limit-per-minute 0 \
  --rate-limit-per-hour 0

echo "   Adding /resource route..."
blackgate add-route \
  --path "/resource/*" \
  --upstream "http://upstream:8080/resource/*" \
  --allowed-methods "GET,POST,PUT,DELETE" \
  --rate-limit-per-minute 0 \
  --rate-limit-per-hour 0

echo "✅ Routes configured successfully!"

echo "🚀 Starting BlackGate server..."
blackgate start

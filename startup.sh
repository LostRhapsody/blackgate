#!/bin/bash
# Start up script used by the production docker file
set -e

echo "🔧 Starting Black Gate..."
echo "📍 Database URL: $BLACKGATE_DB_URL"

# Apply migrations
echo "🗄️ Status of database migrations..."
/usr/local/bin/blackgate migrate status

# Start the server
echo "🚀 Starting Black Gate server..."

# Create PID file for graceful shutdown support
PID_FILE="/tmp/blackgate.pid"

# Start the server and capture PID
/usr/local/bin/blackgate start &
BLACKGATE_PID=$!

# Save PID to file for graceful shutdown scripts
echo $BLACKGATE_PID > "$PID_FILE"
echo "📝 PID $BLACKGATE_PID saved to $PID_FILE"

# Wait for the process to complete
wait $BLACKGATE_PID

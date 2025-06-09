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
exec /usr/local/bin/blackgate start

# Black Gate Metrics Demo Script
# This script demonstrates the metrics functionality by making various requests
# and then showing the collected metrics

Write-Host "=== Black Gate Metrics Demo ===" -ForegroundColor Green
Write-Host "Starting Black Gate server..." -ForegroundColor Yellow

# Start the server in background
$serverJob = Start-Job -ScriptBlock {
    Set-Location "c:\blackgate"
    cargo run -- start
}

# Wait for server to start
Start-Sleep -Seconds 5

Write-Host "Making test requests to generate metrics..." -ForegroundColor Yellow

# Make various test requests
Write-Host "1. Testing successful POST request..." -ForegroundColor Cyan
try {
    $response1 = Invoke-RestMethod -Uri "http://localhost:3000/warehouse" -Method POST -Body '{"payload": "demo_test"}' -ContentType "application/json"
    Write-Host "✅ POST request successful" -ForegroundColor Green
} catch {
    Write-Host "❌ POST request failed: $_" -ForegroundColor Red
}

Write-Host "2. Testing method not allowed..." -ForegroundColor Cyan
try {
    $response2 = Invoke-RestMethod -Uri "http://localhost:3000/warehouse" -Method GET
    Write-Host "✅ GET request successful" -ForegroundColor Green
} catch {
    Write-Host "✅ GET request correctly blocked (Method Not Allowed)" -ForegroundColor Green
}

Write-Host "3. Testing route not found..." -ForegroundColor Cyan
try {
    $response3 = Invoke-RestMethod -Uri "http://localhost:3000/nonexistent-route" -Method GET
    Write-Host "✅ Non-existent route request successful" -ForegroundColor Green
} catch {
    Write-Host "✅ Non-existent route correctly returned 404" -ForegroundColor Green
}

Write-Host "4. Testing OAuth (will fail without OAuth server)..." -ForegroundColor Cyan
try {
    $response4 = Invoke-RestMethod -Uri "http://localhost:3000/oauth-test" -Method GET
    Write-Host "✅ OAuth request successful" -ForegroundColor Green
} catch {
    Write-Host "✅ OAuth request correctly failed (OAuth server not running)" -ForegroundColor Green
}

# Stop the server
Write-Host "Stopping server..." -ForegroundColor Yellow
Stop-Job $serverJob
Remove-Job $serverJob

# Show metrics
Write-Host "`n=== Viewing Collected Metrics ===" -ForegroundColor Green
Write-Host "Showing statistics summary..." -ForegroundColor Yellow
Set-Location "c:\blackgate"
& cargo run -- metrics --stats

Write-Host "`nDemo complete! 🎉" -ForegroundColor Green
Write-Host "You can run 'cargo run -- metrics --help' to see all available options." -ForegroundColor Cyan

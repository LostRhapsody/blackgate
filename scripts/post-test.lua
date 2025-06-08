-- post-test.lua
-- wrk script for testing POST endpoints with JSON payload

wrk.method = "POST"
wrk.body = '{"test": "data", "timestamp": "2025-06-08T12:00:00Z", "load_test": true}'
wrk.headers["Content-Type"] = "application/json"

-- Optional: Add some randomness to the payload
local random = math.random
math.randomseed(os.time())

function request()
    local id = random(1, 10000)
    local body = string.format('{"test": "data", "id": %d, "timestamp": "%s", "load_test": true}', 
                              id, os.date("!%Y-%m-%dT%H:%M:%SZ"))
    return wrk.format("POST", nil, {["Content-Type"] = "application/json"}, body)
end

function response(status, headers, body)
    if status ~= 200 and status ~= 201 then
        print("Unexpected status: " .. status)
        print("Response body: " .. body)
    end
end

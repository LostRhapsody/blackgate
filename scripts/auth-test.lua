-- auth-test.lua
-- wrk script for testing authenticated endpoints

wrk.headers["Authorization"] = "Bearer test-token-123"
wrk.headers["User-Agent"] = "BlackGate-LoadTest/1.0"

local requests = {
    "/fast",
    "/slow?delay=50",
    "/echo/test123",
    "/resource/user123"
}

local counter = 0

function request()
    counter = counter + 1
    local path = requests[(counter % #requests) + 1]
    return wrk.format("GET", path)
end

function response(status, headers, body)
    if status >= 400 then
        print("Error " .. status .. " for request: " .. wrk.path)
    end
end

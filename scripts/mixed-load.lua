-- mixed-load.lua
-- wrk script that simulates mixed workload with different endpoints

local requests = {
    {method = "GET", path = "/fast", weight = 50},
    {method = "GET", path = "/slow?delay=100", weight = 20},
    {method = "GET", path = "/echo/loadtest", weight = 15},
    {method = "POST", path = "/json", body = '{"load": "test"}', weight = 10},
    {method = "GET", path = "/resource/test123", weight = 5}
}

-- Build weighted request list
local weighted_requests = {}
for _, req in ipairs(requests) do
    for i = 1, req.weight do
        table.insert(weighted_requests, req)
    end
end

local counter = 0
math.randomseed(os.time())

function request()
    counter = counter + 1
    local req = weighted_requests[math.random(#weighted_requests)]
    
    if req.method == "POST" then
        return wrk.format(req.method, req.path, {["Content-Type"] = "application/json"}, req.body or "")
    else
        return wrk.format(req.method, req.path)
    end
end

function response(status, headers, body)
    if status >= 500 then
        print("Server error " .. status .. " - " .. body)
    end
end

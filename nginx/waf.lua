local ngx = ngx
local cjson = require "cjson.safe"

local _M = {}

math.randomseed(os.time())

-- Shared dicts expected:
-- ngx.shared.rate_limit_store
-- ngx.shared.challenge_sessions
-- ngx.shared.ip_list_store

local security_questions = {
    { question = "What is the capital of France?", answer = "paris" },
    { question = "What is 2 + 2?", answer = "4" },
    { question = "What color is the sky on a clear day?", answer = "blue" },
    { question = "How many sides does a triangle have?", answer = "3" },
    { question = "What is the largest planet in our solar system?", answer = "jupiter" }
}

local function generate_captcha()
    local num1 = math.random(1, 10)
    local num2 = math.random(1, 10)
    local operations = {"+", "-", "*"}
    local op = operations[math.random(1, #operations)]

    local question = num1.. " ".. op.. " ".. num2
    local answer
    if op == "+" then
        answer = tostring(num1 + num2)
    elseif op == "-" then
        answer = tostring(num1 - num2)
    else
        answer = tostring(num1 * num2)
    end

    return question, answer
end

local function html_escape(s)
    if not s then return "" end
    s = tostring(s)
    s = s:gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;"):gsub('"', "&quot;"):gsub("'", "&#39;")
    return s
end

local function challenge_page(challenge_id, question, redirect_to)
    ngx.status = ngx.HTTP_OK
    ngx.header.content_type = "text/html"
    ngx.say([[
<!DOCTYPE html>
<html>
<head>
    <title>Security Challenge</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background-color: #fff; padding: 40px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); text-align: center; }
        h2 { color: #007bff; margin-bottom: 10px; }
        p { margin-bottom: 20px; }
        form { display: flex; flex-direction: column; align-items: center; }
        input[type="text"] { width: 80%; padding: 10px; margin-top: 10px; margin-bottom: 20px; border: 1px solid #ccc; border-radius: 4px; }
        input[type="submit"] { background-color: #007bff; color: white; padding: 12px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 1em; }
        input[type="submit"]:hover { background-color: #0056b3; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Security Challenge</h2>
        <p>To prove you are human, please answer the following question:</p>
        <h3>]] .. html_escape(question) .. [[</h3>
        <form action="/challenge" method="POST">
            <input type="text" name="answer" placeholder="Your Answer" required>
            <input type="hidden" name="redirect_to" value="]] .. html_escape(redirect_to or "/") .. [[">
            <input type="submit" value="Submit">
        </form>
    </div>
</body>
</html>
]])
    ngx.exit(ngx.HTTP_OK)
end

-- Handle challenge submission (expects POST)
function _M.handle_challenge()
    ngx.req.read_body()

    -- Prefer session id from cookie (challenge_session), fallback to id param if present
    local session_id = ngx.var.cookie_challenge_session or ngx.var.arg_id
    if session_id and session_id ~= "" then
        -- nothing
    else
        -- fallback to IP-based key (legacy)
        session_id = "session_" .. ngx.var.remote_addr
    end

    local session_data_json = ngx.shared.challenge_sessions:get(session_id)

    if session_data_json then
        local session_data = cjson.decode(session_data_json)
        local args = ngx.req.get_post_args()
        local user_answer = args and args.answer or ""
        local redirect_to = args and args.redirect_to or "/"

        -- normalize
        user_answer = ngx.unescape_uri(tostring(user_answer))
        user_answer = user_answer:gsub("^%s*(.-)%s*$", "%1")
        redirect_to = ngx.unescape_uri(tostring(redirect_to))

        -- avoid open redirect
        if not redirect_to:match("^/") then redirect_to = "/" end

        local expected = tostring(session_data.answer or "")
        expected = expected:gsub("^%s*(.-)%s*$", "%1")

        if user_answer ~= "" and string.lower(user_answer) == string.lower(expected) then
            -- Passed: mark passed flag with a TTL and clean up session & rate counter
            local passed_key = "passed_" .. session_id
            -- give a short grace period (seconds) to avoid immediate re-challenge; adjust TTL as needed
            ngx.shared.challenge_sessions:set(passed_key, true, 300)
            ngx.shared.challenge_sessions:delete(session_id)

            -- reset rate counter for IP so user won't be immediately re-challenged
            local rate_ip_key = "rate_limit_".. ngx.var.remote_addr
            ngx.shared.rate_limit_store:delete(rate_ip_key)

            -- clear cookie by setting expired cookie (best effort)
            ngx.header["Set-Cookie"] = {"challenge_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly"}

            return ngx.redirect(redirect_to)
        end

        if user_answer and user_answer ~= "" then
            ngx.log(ngx.ERR, "WAF: Incorrect challenge answer for session " .. session_id)
        end

        -- show page again (preserve redirect_to)
        challenge_page(session_id, session_data.question, redirect_to)
    else
        ngx.log(ngx.ERR, "WAF: Challenge session not found for session_id: ".. tostring(session_id))
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end
end

function _M.apply_rules()
    local ip_key = "rate_limit_".. ngx.var.remote_addr
    local rate_limit_config

    local rate_limit_json = ngx.shared.rate_limit_store:get("config")
    if rate_limit_json then
        rate_limit_config = cjson.decode(rate_limit_json)
    else
        ngx.log(ngx.ERR, "WAF: Rate limit config not found in shared dict, using defaults.")
        rate_limit_config = { rate = "5r/m", burst = 10, challenge_enabled = true, ban_duration = 300 }
    end

    local rate = rate_limit_config.rate
    local burst = rate_limit_config.burst
    local challenge_enabled = rate_limit_config.challenge_enabled

    local ip_list = ngx.shared.ip_list_store:get("config")
    if ip_list then
        local config = cjson.decode(ip_list)
        if config.blocked_ips and config.blocked_ips[ngx.var.remote_addr] then
            ngx.log(ngx.ERR, "WAF: Denied access for IP ".. ngx.var.remote_addr.. " is in the blocked list.")
            return ngx.exit(ngx.HTTP_FORBIDDEN)
        end
    end

    -- Check cookie-based passed flag first (grace period)
    local session_cookie = ngx.var.cookie_challenge_session
    if session_cookie and session_cookie ~= "" then
        local passed = ngx.shared.challenge_sessions:get("passed_" .. session_cookie)
        if passed then
            -- user recently passed challenge, allow request
            return
        end
    end

    -- Also allow legacy IP-based passed flag
    local legacy_passed = ngx.shared.challenge_sessions:get("passed_session_" .. ngx.var.remote_addr)
    if legacy_passed then return end

    local count = ngx.shared.rate_limit_store:get(ip_key) or 0
    count = count + 1
    ngx.shared.rate_limit_store:set(ip_key, count, 60)

    if count > burst and challenge_enabled then
        -- try to find existing session id: cookie or legacy ip key
        local session_id = ngx.var.cookie_challenge_session or ("session_" .. ngx.var.remote_addr)
        local session_exists = ngx.shared.challenge_sessions:get(session_id)

        if not session_exists then
             local question, answer = generate_captcha()
             local new_session_id = "sess_".. math.random(100000, 999999)
             local session_data = {
                 id = new_session_id,
                 question = question,
                 answer = answer,
                 failed_attempts = 0
             }
             -- store session under session id
             ngx.shared.challenge_sessions:set(new_session_id, cjson.encode(session_data), 3600)

             -- set cookie so browser sends session id on challenge page
             ngx.header["Set-Cookie"] = {"challenge_session=" .. new_session_id .. "; Path=/; HttpOnly"}

             session_id = new_session_id
        end

        ngx.log(ngx.ERR, "WAF: Rate limit exceeded for ".. ngx.var.remote_addr.. ". Redirecting to challenge page. Request: ".. ngx.var.request_uri)
        ngx.redirect("/challenge?redirect_to=" .. ngx.escape_uri(ngx.var.request_uri))
    elseif count > burst and not challenge_enabled then
        ngx.log(ngx.ERR, "WAF: Rate limit exceeded for ".. ngx.var.remote_addr.. ". Returning 429. Request: ".. ngx.var.request_uri)
        return ngx.exit(ngx.HTTP_TOO_MANY_REQUESTS)
    end
end

function _M.update_rules(file_type, content)
    local cjson = require "cjson.safe"

    local ip_list_path = "/usr/local/openresty/nginx/conf/ip_list.json"
    local rate_limit_path = "/usr/local/openresty/nginx/conf/rate_limit_config.json"

    if file_type == "ip_list" then
        local f, err = io.open(ip_list_path, "w")
        if f then
            f:write(content)
            f:close()
            local ip_config = cjson.decode(content)
            if ip_config then
                 ngx.shared.ip_list_store:set("config", cjson.encode(ip_config))
            end
        else
            return "Failed to write ip_list.json: ".. tostring(err)
        end
    elseif file_type == "rate_limit" then
        local rf, rerr = io.open(rate_limit_path, "w")
        if rf then
            rf:write(content)
            rf:close()
            local rl_config = cjson.decode(content)
            if rl_config then
                ngx.shared.rate_limit_store:set("config", cjson.encode(rl_config))
            end
        else
            return "Failed to write rate_limit_config.json: ".. tostring(rerr)
        end
    else
        return "Invalid file type."
    end
    return "Rules updated successfully."
end

return _M
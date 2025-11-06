-- FlexiWAF/nginx/waf.lua
local ngx = ngx
local cjson = require "cjson.safe"
local _M = {}
-- تهيئة البذرة العشوائية
math.randomseed((os.time() + (ngx and ngx.now and math.floor(ngx.now()*1000) or 0)) * 1000 + tonumber(tostring(math.random()):sub(3,6)))

-- -------------------------------------------------------------
-- دالة مساعدة: تحويل المصفوفة إلى جدول هاش للبحث السريع (O(1))
-- -------------------------------------------------------------
local function array_to_hash_map(ip_array)
	local ip_hash = {}
	if ip_array and type(ip_array) == "table" then
		-- ipairs تتكرر عبر المفاتيح العددية (التي نتجت عن فك تشفير مصفوفة JSON)
		for _, ip_addr in ipairs(ip_array) do
			-- استخدام عنوان IP كسلسلة نصية مفتاحًا (Key) والقيمة "true"
			ip_hash[ip_addr] = true
		end
	end
	return ip_hash
end

-- -------------------------------------------------------------
-- دالة مساعدة: توليد UUID بإنتروبيا أعلى (محاكاة)
local function generate_high_entropy_id()
	local t = os.time()
	local r1 = math.floor(math.random() * 10^10)
	local r2 = math.floor(math.random() * 10^10)
	return "sess_".. string.format("%x%x%x", t, r1, r2)
end

-- منطق توليد CAPTCHA: تقليل عدد الأحرف، وإضافة انحناءات/تشويه بصري عبر CSS + SVG overlay
local function generate_visual_captcha()
	local charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789abcdefghijklmnopqrstuvwxyz" -- تجنّب حروف شبيهة
	local len = 4 -- طول السلسلة
	local chars = {}
	for i = 1, len do
		local idx = math.random(1, #charset)
		chars[i] = charset:sub(idx, idx)
	end
	-- نطلب الحرف الثاني والرابع
	local index1 = 2
	local index2 = 4
	local required_char1 = chars[index1]
	local required_char2 = chars[index2]
	local question = "Please enter the character at position 2 and the character at position 4 (e.g., if the 2nd is 'A' and 4th is 'B', enter 'AB')."
	local answer = tostring(required_char1.. required_char2)
	-- نولد HTML لكل حرف مع أنماط inline عشوائية لتشويه كل حرف بشكل مختلف
	local char_spans = {}
	for i, ch in ipairs(chars) do
		local rot = (math.random(-35, 35) + (math.random()/10))
		local skew = (math.random(-25, 25) / 10)
		local tx = math.random(-6, 6)
		local ty = math.random(-6, 6)
		local scale = 0.9 + (math.random() * 0.4)
		local letter_spacing = 3 + math.random(0,5)
		local opacity = 0.85 - (math.random() * 0.3)
		local color_choices = {"#1b1b1b", "#2a2a2a", "#0f2433", "#2b1020"}
		local color = color_choices[ (i % #color_choices) + 1 ]
		local span = '<span class="captcha-char" style="display:inline-block; transform: rotate('.. string.format("%.2f", rot).. 'deg) skewY('.. string.format("%.2f", skew).. 'deg) translate('.. tx.. 'px,'.. ty.. 'px) scale('.. string.format("%.3f", scale).. '); letter-spacing:'.. letter_spacing.. 'px; opacity:'.. string.format("%.2f", opacity).. '; color:'.. color.. ';">'.. ch.. '</span>'
		table.insert(char_spans, span)
	end
	local rendered_text = table.concat(char_spans, "")
	-- نولد منحنيات ونقاط كضوضاء
	local function random_point()
		return math.random(10, 440), math.random(10, 120)
	end
	local curves = {}
	local curve_count = math.random(2, 4)
	for i = 1, curve_count do
		local x1, y1 = random_point()
		local cx1, cy1 = random_point()
		local cx2, cy2 = random_point()
		local x2, y2 = random_point()
		local stroke_w = 1 + math.random() * 2.5
		local opacity = 0.06 + math.random() * 0.14
		local path = string.format('<path d="M %.1f %.1f C %.1f %.1f, %.1f %.1f, %.1f %.1f" stroke="rgba(200,40,40,%.3f)" stroke-width="%.2f" fill="none" stroke-linecap="round" />',
			x1, y1, cx1, cy1, cx2, cy2, x2, y2, opacity, stroke_w)
		table.insert(curves, path)
	end
	local dots = {}
	local dot_count = 8 + math.random(4, 12)
	for i = 1, dot_count do
		local x, y = random_point()
		local r = 1 + math.random() * 3
		local o = 0.05 + math.random() * 0.15
		table.insert(dots, string.format('<circle cx="%.1f" cy="%.1f" r="%.2f" fill="rgba(0,0,0,%.3f)"/>', x, y, r, o))
	end
	local svg_overlay = '<svg class="captcha-overlay" viewBox="0 0 460 140" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true" focusable="false" style="position:absolute; top:0; left:0; width:100%; height:100%; pointer-events:none;">'.. table.concat(curves).. table.concat(dots).. '</svg>'
	local rendered_html = [[
	<div class="captcha-container" style="position:relative; display:inline-block; padding:10px 14px; background:linear-gradient(135deg, rgba(250,250,250,0.9), rgba(230,230,230,0.9)); border-radius:6px; border:2px dashed rgba(200,80,80,0.6); overflow:visible;">
		<div style="position:relative; z-index:2; font-family: 'Courier New', monospace; font-size: 2.2em; letter-spacing: 8px; padding:8px 6px; display:inline-block; user-select:none;">
			]].. rendered_text.. [[
		</div>
		]].. svg_overlay.. [[
	</div>
	]]
	-- إرجاع السلسلة الأصلية (chars concat)، السؤال، الإجابة، وHTML المولد، ووقت الإنشاء
	return table.concat(chars), question, answer, rendered_html, (ngx and ngx.now and ngx.now() or os.time())
end

local function html_escape(s)
	if not s then return "" end
	s = tostring(s)
	s = s:gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;"):gsub('"', "&quot;"):gsub("'", "&#39;")
	return s
end

local function challenge_page(challenge_id, full_string, question, failed_attempts, rendered_html)
	ngx.status = ngx.HTTP_OK
	ngx.header.content_type = "text/html"
	local rotation = string.format("%.1f", math.random(-10, 10) / 2)
	local display_html = rendered_html and rendered_html or ("<div class=\"captcha-string\">".. html_escape(full_string).. "</div>")
	ngx.say([[
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Security Verification</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; color: #333; }
		.container { max-width: 600px; margin: 40px auto; padding: 30px; background: white; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
		h2 { color: #d9534f; margin-bottom: 20px; }
		p { margin: 12px 0; line-height: 1.5; }
		form { margin-top: 20px; }
		input[type="text"] { width: 72%; padding: 12px; margin-top: 10px; margin-bottom: 18px; border: 2px solid #ccc; border-radius: 6px; font-size: 1.05em; text-transform: uppercase; letter-spacing: 2px; text-align:center; }
		input[type="submit"] { background-color: #d9534f; color: white; padding: 12px 24px; border: none; border-radius: 6px; cursor: pointer; font-size: 1em; transition: background-color 0.25s, transform 0.08s; font-weight: bold; }
		input[type="submit"]:hover { background-color: #c9302c; transform: translateY(-1px); }
		.error-message { color: #c9302c; margin-bottom: 12px; font-weight: bold; }
		.captcha-container { display:inline-block; position:relative; transform: rotate(]].. rotation.. [[deg); padding: 6px; }
		.captcha-container:after {
			content: "";
			position: absolute;
			inset: -6px;
			background: radial-gradient(ellipse at 20% 10%, rgba(255,255,255,0.02), transparent 20%),
						 radial-gradient(ellipse at 80% 90%, rgba(0,0,0,0.02), transparent 30%);
			pointer-events: none;
			mix-blend-mode: multiply;
			filter: blur(6px);
			z-index:1;
		}
		.captcha-container > div { position: relative; z-index: 2; }
		.captcha-overlay { position:absolute; top:0; left:0; z-index:3; mix-blend-mode: screen; opacity:0.95; pointer-events:none; }
		.captcha-char {
			font-family: 'Courier New', monospace;
			font-weight: 700;
			text-shadow: 1px 1px 0 rgba(255,255,255,0.06), -1px -1px 1px rgba(0,0,0,0.25);
			-webkit-font-smoothing: antialiased;
			backface-visibility: hidden;
			filter: contrast(110%) saturate(105%);
			display:inline-block;
			padding: 0 1px;
		}
		.instruction {
			color: #5cb85c;
			font-weight: bold;
			margin-top: 8px;
		}
		@media (max-width: 480px) {
			.container { padding: 20px; width: 92%; }
			.captcha-container { transform: scale(0.92) rotate(]].. rotation.. [[deg); }
			input[type="text"] { width: 88%; }
		}
	</style>
</head>
<body>
	<div class="container">
		<h2>Security Challenge Required</h2>
		<p>To prove you are human and gain access, please complete the task below:</p>
		<p>]].. html_escape(question).. [[</p>
		<div style="margin: 18px auto;">
			]].. display_html.. [[
		</div>
		]].. (failed_attempts and failed_attempts > 0 and failed_attempts < 5 and '<p class="error-message">Incorrect Answer. Attempt '.. failed_attempts.. ' of 5 remaining.</p>' or '').. [[
		<form action="/challenge" method="POST">
			<input type="hidden" name="challenge_session_id" value="]].. html_escape(challenge_id).. [[">
			<input type="text" name="answer" placeholder="Enter your answer" maxlength="2" required>
			<input type="submit" value="Verify and Continue">
		</form>
	</div>
</body>
</html>
]])
	ngx.exit(ngx.HTTP_OK)
end

-- Handle challenge submission (expects POST)
function _M.handle_challenge()
	local req_method = ngx.req.get_method()

	-- ✅ التعديل (1): يتم معالجة زيادة العداد والتحقق من الإجابة فقط إذا كان الطلب POST
	if req_method ~= "POST" then
		-- إذا لم يكن POST (سيكون GET لعرض الصفحة)، نستمر في عرضها فقط
		local session_id = ngx.var.cookie_challenge_session
		if session_id and session_id:sub(1, 4) == "sess" then
			local session_data_json = ngx.shared.challenge_sessions:get(session_id)
			if session_data_json then
				local session_data = cjson.decode(session_data_json) or {}
				-- عرض الصفحة بناءً على بيانات الجلسة الحالية
				challenge_page(session_id, session_data.full_string, session_data.question, session_data.failed_attempts, session_data.rendered_html)
				return
			end
		end
		-- إذا لم تكن هناك جلسة أو كان الطلب GET لمورد ثابت (favicon)، فليقم Nginx بمعالجة الطلب كالمعتاد
		return
	end

	-- إذا كان POST (تقديم الإجابة)
	ngx.req.read_body()
	local args = ngx.req.get_post_args()
	local session_id = args and args.challenge_session_id or ngx.var.cookie_challenge_session
	if not session_id or session_id == "" or session_id:sub(1, 4) ~= "sess" then
		ngx.log(ngx.WARN, "WAF: Challenge submission without valid session ID. IP: ".. ngx.var.remote_addr.. ", User-Agent: ".. (ngx.var.http_user_agent or "N/A"))
		ngx.exit(ngx.HTTP_FORBIDDEN)
	end
	
	local session_data_json = ngx.shared.challenge_sessions:get(session_id)
	if session_data_json then
		local session_data = cjson.decode(session_data_json) or {}
		-- إذا لم يحتوي على rendered_html أو كان قديمًا، أعد توليده
		local now = ngx and ngx.now and ngx.now() or os.time()
		local need_regen = false
		if not session_data.rendered_html then
			need_regen = true
		else
			local created = tonumber(session_data.created_at) or 0
			if (now - created) > 300 then -- 5 دقائق — اعتبرها قديمة من منظور العرض
				need_regen = true
			end
		end
		
		if need_regen then
			local new_string, new_question, new_answer, new_render, created_at = generate_visual_captcha()
			session_data.full_string = new_string
			session_data.question = new_question
			session_data.answer = new_answer
			session_data.rendered_html = new_render
			session_data.created_at = created_at
			local session_ttl = ngx.shared.challenge_sessions:ttl(session_id) or 3600
			ngx.shared.challenge_sessions:set(session_id, cjson.encode(session_data), session_ttl)
		end
		
		local user_answer = args and args.answer or ""
		local redirect_to = session_data.target_uri or "/"
		user_answer = ngx.unescape_uri(tostring(user_answer))
		user_answer = user_answer:gsub("^%s*(.-)%s*$", "%1")
		local normalized_user_answer = string.upper(user_answer)
		local expected = tostring(session_data.answer or "")
		local normalized_expected = string.upper(expected)
		
		if normalized_user_answer ~= "" and normalized_user_answer == normalized_expected then
			local passed_key = "grace_".. ngx.var.remote_addr
			local GRACE_PERIOD = 900 -- 15 دقيقة سماح
			ngx.shared.rate_limit_store:set(passed_key, true, GRACE_PERIOD)	
			
			-- إعادة تعيين عداد المعدل للسماح بعدد غير محدود من الطلبات
			local rate_ip_key = "rate_limit_".. ngx.var.remote_addr
			ngx.shared.rate_limit_store:delete(rate_ip_key)
			
			-- حذف جلسة التحدي
			ngx.shared.challenge_sessions:delete(session_id)
			
			-- حذف ملف تعريف الارتباط
			ngx.header["Set-Cookie"] = "challenge_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly"

			-- ✅ التعديل: تعيين متغير التسجيل لنجاح الكابتشا
			ngx.var.waf_log_type = "CAPTCHA_SUCCESS"
			
			ngx.log(ngx.NOTICE, "WAF: Challenge Passed. Grace period activated for IP: ".. ngx.var.remote_addr.. " for 15 minutes. Redirecting to: ".. redirect_to)
			return ngx.redirect(redirect_to)
		end
		
		if user_answer and user_answer ~= "" then
			-- ✅ التعديل (1): يتم تنفيذ زيادة العداد هنا فقط لأنه داخل كتلة (user_answer and user_answer ~= "")
			session_data.failed_attempts = (session_data.failed_attempts or 0) + 1
			local MAX_ATTEMPTS = 5
			local BAN_DURATION = 300 -- 5 دقائق
			
			-- ✅ التعديل: تعيين متغير التسجيل لفشل الكابتشا
			ngx.var.waf_log_type = "CAPTCHA_FAIL"

			-- ✅ استبدال write_log بـ ngx.log للتسجيل
			ngx.log(ngx.WARN, "WAF: CAPTCHA_FAILURE - Failed attempt ".. tostring(session_data.failed_attempts).. " from IP: ".. ngx.var.remote_addr)
			
			if session_data.failed_attempts >= MAX_ATTEMPTS then
				local ban_key = "banned_ip_".. ngx.var.remote_addr
				ngx.shared.rate_limit_store:set(ban_key, true, BAN_DURATION)
				ngx.shared.challenge_sessions:delete(session_id)
				ngx.header["Set-Cookie"] = "challenge_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly"
				
				-- ✅ التعديل (3): تعيين متغير التسجيل للحظر النهائي لظهوره على الداشبورد
				ngx.var.waf_log_type = "TEMP_BAN"

				-- ✅ استبدال write_log بـ ngx.log للتسجيل
				ngx.log(ngx.CRIT, "WAF: FINAL_BAN - Max challenge attempts reached and IP banned for ".. BAN_DURATION.. " seconds: ".. ngx.var.remote_addr.. ", User-Agent: ".. (ngx.var.http_user_agent or "N/A"))
				
				return ngx.exit(ngx.HTTP_FORBIDDEN)
			else
				local new_string, new_question, new_answer, new_render, created_at = generate_visual_captcha()
				session_data.full_string = new_string
				session_data.question = new_question
				session_data.answer = new_answer
				session_data.rendered_html = new_render
				session_data.created_at = created_at
				local session_ttl = ngx.shared.challenge_sessions:ttl(session_id) or 3600
				ngx.shared.challenge_sessions:set(session_id, cjson.encode(session_data), session_ttl)
			end
		end
		
		challenge_page(session_id, session_data.full_string, session_data.question, session_data.failed_attempts, session_data.rendered_html)
	else
		ngx.log(ngx.ERR, "WAF: Challenge session expired or not found for session_id: ".. tostring(session_id).. ", IP: ".. ngx.var.remote_addr.. ", User-Agent: ".. (ngx.var.http_user_agent or "N/A"))
		ngx.exit(ngx.HTTP_FORBIDDEN)
	end
end

function _M.apply_rules()
	local ip_addr = ngx.var.remote_addr
	local user_agent = ngx.var.http_user_agent or "N/A"
	
	-- التحقق أولاً من فترة السماح (بعد حل الكابتشا بنجاح)
	local grace_key = "grace_".. ip_addr
	local in_grace_period = ngx.shared.rate_limit_store:get(grace_key)
	if in_grace_period then
		-- ✅ التعديل: تعيين متغير التسجيل لفترة السماح (يجب أن يتم تسجيله في log_grace_period)
		ngx.var.waf_log_type = "GRACE_PERIOD"
		ngx.log(ngx.INFO, "WAF: Allowing request during grace period. IP: ".. ip_addr.. ", URI: ".. ngx.var.request_uri)
		return
	end
	
	-- التحقق من الحظر المؤقت
	local ban_key = "banned_ip_".. ip_addr
	local is_banned = ngx.shared.rate_limit_store:get(ban_key)
	if is_banned then
		-- ✅ التعديل: تعيين متغير التسجيل لنظام الحظر المؤقت
		ngx.var.waf_log_type = "TEMP_BAN"
		ngx.log(ngx.WARN, "WAF: TEMP_BAN - Temporary rate-limit ban for IP: ".. ip_addr.. ", Duration: ".. ngx.shared.rate_limit_store:ttl(ban_key).. " seconds")
		return ngx.exit(ngx.HTTP_TOO_MANY_REQUESTS) -- 429: Too Many Requests
	end
	
	-- الحصول على إعدادات الريت ليميتينج
	local rate_limit_json = ngx.shared.rate_limit_store:get("config")
	local rate_limit_config
	if rate_limit_json then
		rate_limit_config = cjson.decode(rate_limit_json)
	else
		ngx.log(ngx.ERR, "WAF: Rate limit config not found in shared dict, using defaults.")
		rate_limit_config = {	
			rate = "5r/m",	
			burst = 10,	
			challenge_enabled = true,	
			ban_duration = 300	
		}
		-- حفظ الإعدادات الافتراضية في الذاكرة المشتركة
		ngx.shared.rate_limit_store:set("config", cjson.encode(rate_limit_config))
	end
	
	local burst = rate_limit_config.burst
	local challenge_enabled = rate_limit_config.challenge_enabled
	
	-- التحقق من قائمة الأيبيات المحظورة
	local ip_list_json = ngx.shared.ip_list_store:get("config")
	if ip_list_json then
		local config = cjson.decode(ip_list_json) or {}
		-- التحقق من الأيبيات المحظورة
		if config.blocked_ips and config.blocked_ips[ip_addr] then
			-- ✅ التعديل: تعيين متغير التسجيل لنظام الحظر الدائم
			ngx.var.waf_log_type = "BLOCKED_IP"
			-- ✅ التعديل (2): حذف السجل الثاني المكرر
			ngx.log(ngx.WARN, "WAF: BLOCKED_IP - IP blocked from list (Permanent): ".. ip_addr.. ", Source: ip_list.json. Request: ".. ngx.var.request_uri)
			return ngx.exit(ngx.HTTP_FORBIDDEN)
		end
		
		-- التحقق من الأيبيات المسموح بها فقط (إذا كانت القائمة غير فارغة)
		if config.allowed_ips and next(config.allowed_ips) ~= nil then
			if not config.allowed_ips[ip_addr] then
				-- ✅ التعديل: تعيين متغير التسجيل لنظام الحظر الدائم
				ngx.var.waf_log_type = "BLOCKED_IP"
				-- ✅ التعديل (2): حذف السجل الثاني المكرر
				ngx.log(ngx.WARN, "WAF: BLOCKED_IP - IP not in allowed list: ".. ip_addr.. ", Source: ip_list.json. Request: ".. ngx.var.request_uri)
				return ngx.exit(ngx.HTTP_FORBIDDEN)
			end
		end
	end
	
	-- عداد الطلبات للمستخدم
	local rate_ip_key = "rate_limit_".. ip_addr
	local count = ngx.shared.rate_limit_store:get(rate_ip_key) or 0
	
	
	if count >= burst then -- نتحقق من الحد قبل الزيادة (هذا البلوك يتفعل عند الطلب الـ 11 حيث count = 10)
		-- تم تجاوز الحد
		if challenge_enabled then
			local session_id = ngx.var.cookie_challenge_session
			local session_data_json = session_id and ngx.shared.challenge_sessions:get(session_id)
			
			-- ✅ التعديل: تعيين متغير التسجيل لتفعيل الريت ليميت
			ngx.var.waf_log_type = "RATE_LIMIT"

			if not session_data_json then
				-- ✅ استبدال write_log بـ ngx.log للتسجيل
				ngx.log(ngx.WARN, "WAF: RATE_LIMIT_TRIGGER - Rate limit exceeded - showing CAPTCHA. Count: ".. count.. ", Burst: ".. burst.. ", IP: ".. ip_addr)
				
				-- إنشاء جلسة جديدة
				local new_string, new_question, new_answer, new_render, created_at = generate_visual_captcha()
				local new_session_id = generate_high_entropy_id()
				local session_data = {
					id = new_session_id,
					full_string = new_string,
					question = new_question,
					answer = new_answer,
					rendered_html = new_render,
					created_at = created_at,
					failed_attempts = 0,
					target_uri = ngx.var.request_uri
				}
				ngx.shared.challenge_sessions:set(new_session_id, cjson.encode(session_data), 3600)
				ngx.header["Set-Cookie"] = "challenge_session=".. new_session_id.. "; Path=/; HttpOnly"
				return ngx.redirect("/challenge?challenge_session_id=".. new_session_id)
			else
				-- ✅ استبدال write_log بـ ngx.log للتسجيل
				ngx.log(ngx.WARN, "WAF: RATE_LIMIT_TRIGGER - Rate limit exceeded - redirecting to existing session. Count: ".. count.. ", Burst: ".. burst.. ", IP: ".. ip_addr)
				return ngx.redirect("/challenge?challenge_session_id=".. session_id)
			end
		else
			-- التحدي مُعطَّل - حظر فوري
			-- ✅ التعديل: تعيين متغير التسجيل لتفعيل الريت ليميت حتى لو تم الحظر
			ngx.var.waf_log_type = "RATE_LIMIT"
			ngx.log(ngx.WARN, "WAF: Rate limit exceeded (challenge disabled). Returning 429. Count: ".. count.. ", Burst: ".. burst.. ", IP: ".. ip_addr)
			return ngx.exit(ngx.HTTP_TOO_MANY_REQUESTS)
		end
	end
	
	-- إذا وصلنا إلى هنا: لم يتم تجاوز الحد، نسمح للطلب بالمرور و نزيد العداد
	count = count + 1
	-- حفظ العداد مع وقت انتهاء الصلاحية (60 ثانية)
	ngx.shared.rate_limit_store:set(rate_ip_key, count, 60)
	
	return
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
			
			-- تطبيق تحويل الهاش وحفظ في الذاكرة المشتركة
			local raw_ip_config, decode_err = cjson.decode(content)
			if decode_err then
				ngx.log(ngx.ERR, "Failed to decode IP list JSON: ".. decode_err)
				return "Failed to decode IP list JSON"
			end
			
			if raw_ip_config then
				local optimized_blocked_ips = array_to_hash_map(raw_ip_config.blocked_ips or {})
				local optimized_allowed_ips = array_to_hash_map(raw_ip_config.allowed_ips or {})
				local optimized_config = {
					allowed_ips = optimized_allowed_ips,
					blocked_ips = optimized_blocked_ips
				}
				ngx.shared.ip_list_store:set("config", cjson.encode(optimized_config))
				ngx.log(ngx.INFO, "WAF: IP list configuration updated successfully")
				return "IP list rules updated successfully."
			end
		else
			return "Failed to write ip_list.json: ".. tostring(err)
		end
	elseif file_type == "rate_limit" then
		local rf, rerr = io.open(rate_limit_path, "w")
		if rf then
			rf:write(content)
			rf:close()
			
			local rl_config, decode_err = cjson.decode(content)
			if decode_err then
				ngx.log(ngx.ERR, "Failed to decode rate limit config JSON: ".. decode_err)
				return "Failed to decode rate limit config JSON"
			end
			
			if rl_config then
				ngx.shared.rate_limit_store:set("config", cjson.encode(rl_config))
				ngx.log(ngx.INFO, "WAF: Rate limit configuration updated successfully")
				return "Rate limit rules updated successfully."
			end
		else
			return "Failed to write rate_limit_config.json: ".. tostring(rerr)
		end
	else
		return "Invalid file type."
	end
	
	return "Rules updated successfully."
end

function _M.load_configurations()
	-- تحميل إعدادات الريت ليميتينج عند التشغيل
	local rate_limit_path = "/usr/local/openresty/nginx/conf/rate_limit_config.json"
	local ip_list_path = "/usr/local/openresty/nginx/conf/ip_list.json"
	
	-- تحميل إعدادات الريت ليميتينج
	local rf = io.open(rate_limit_path, "r")
	if rf then
		local content = rf:read("*a")
		rf:close()
		local rl_config, err = cjson.decode(content)
		if not err and rl_config then
			ngx.shared.rate_limit_store:set("config", cjson.encode(rl_config))
			ngx.log(ngx.INFO, "WAF: Rate limit config loaded from file: ".. rate_limit_path)
		else
			ngx.log(ngx.WARN, "WAF: Failed to decode rate limit config: ".. tostring(err).. ". Using defaults.")
		end
	else
		ngx.log(ngx.WARN, "WAF: Rate limit config file not found at ".. rate_limit_path.. ". Using defaults.")
	end
	
	-- تحميل قائمة الأيبيات
	local f = io.open(ip_list_path, "r")
	if f then
		local content = f:read("*a")
		f:close()
		local raw_config, err = cjson.decode(content)
		if not err and raw_config then
			local optimized_blocked_ips = array_to_hash_map(raw_config.blocked_ips or {})
			local optimized_allowed_ips = array_to_hash_map(raw_config.allowed_ips or {})
			local optimized_config = {
				allowed_ips = optimized_allowed_ips,
				blocked_ips = optimized_blocked_ips
			}
			ngx.shared.ip_list_store:set("config", cjson.encode(optimized_config))
			ngx.log(ngx.INFO, "WAF: IP list config loaded from file: ".. ip_list_path)
		else
			ngx.log(ngx.WARN, "WAF: Failed to decode IP list config: ".. tostring(err))
		end
	else
		ngx.log(ngx.WARN, "WAF: IP list file not found at ".. ip_list_path)
	end
end

return _M

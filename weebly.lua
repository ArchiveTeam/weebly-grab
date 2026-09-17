local urlparse = require("socket.url")
local socket = require("socket")
local dns = require("org.conman.dns")
local https = require("ssl.https")
local cjson = require("cjson")
local utf8 = require("utf8")
local html_entities = require("htmlEntities")
local basexx = require("basexx")
local openssl_digest = require("openssl.digest")

local item_dir = os.getenv("item_dir")
local warc_file_base = os.getenv("warc_file_base")
local item_type = nil
local item_name = nil
local item_value = nil

local url_count = 0
local tries = 0
local downloaded = {}
local addedtolist = {}
local abortgrab = false
local killgrab = false
local logged_response = false
local status_code = 0
local content_type = ""

local discovered_outlinks = {}
local discovered_items = {}
local discovered_stash = {}
local bad_items = {}
local ids = {}

local retry_url = false
local context = {}
local accept_ip_cache = {}

local item_patterns = {
  ["^https?://([^/]+/uploads/.+)$"] = "media",
  ["^https?://([^/]+/files/.+)$"] = "media",
  ["^https?://([^/]+/editor/uploads/.+)$"] = "media",
  ["^https?://([^/]+/cdn%-cgi/image/.+)$"] = "media",
  ["^https?://([^/]+/favicon%.ico)$"] = "media",
  ["^https?://([^/]+/.*)$"] = "page",
}

abort_item = function(item)
  abortgrab = true
  if not item then
    item = item_name
  end
  if not bad_items[item] then
    io.stdout:write("Aborting item " .. item .. ".\n")
    io.stdout:flush()
    bad_items[item] = true
  end
end

kill_grab = function(item)
  io.stdout:write("Aborting crawling.\n")
  io.stdout:flush()
  killgrab = true
end

read_file = function(file)
  if file then
    local f = assert(io.open(file, "rb"))
    local body = f:read("*all")
    f:close()
    return body
  else
    return ""
  end
end

processed = function(url)
  if downloaded[url] or addedtolist[url] then
    return true
  end
  return false
end

discover_item = function(target, item)
  if item ~= item_name and not target[item] then
    target[item] = true
    return true
  end
  return false
end

percent_encode_url = function(newurl)
  return string.gsub(newurl, "(.)", function(c)
    local b = string.byte(c)
    if b < 32 or b > 126 then
      return string.format("%%%02X", b)
    end
    return c
  end)
end

find_item = function(url)
  local found = nil
  for pattern, type_ in pairs(item_patterns) do
    local value = string.match(url, pattern)
    if value then
      found = {
        ["value"]=value,
        ["type"]=type_
      }
      if type_ ~= "page" then
        return found
      end
    end
  end
  return found
end

set_item = function(url)
  if ids[string.lower(url)] then
    return nil
  end
  local found = find_item(url)
  if found then
    local new_item_type = found["type"]
    local new_item_value = found["value"]
    local new_item_name = new_item_type .. ":" .. new_item_value
    if new_item_name ~= item_name then
      ids = {}
      context = {
        ["page_url"]=url,
        ["digests"]={},
        ["warc_digests"]={}
      }
      item_value = new_item_value
      item_type = new_item_type
      ids[string.lower(url)] = true
      if item_type == "media" then
        ids[string.gsub(string.match(url, "^https?://[^/]+(/.+)$"), "%?[0-9]+$", "")] = true
      end
      abortgrab = false
      tries = 0
      retry_url = false
      item_name = new_item_name
      print("Archiving item " .. item_name)
    end
  end
end

accept_ip = function(url)
  local domain = string.match(url, "^https?://([^/%?&;]+)")
  if not domain or string.match(domain, "@") then
    return false
  end
  domain = string.match(domain, "^(.-):[0-9]+$") or domain
  domain = string.lower(string.match(domain, "^(.-)%.*$"))
  if accept_ip_cache[domain] ~= nil then
    return accept_ip_cache[domain]
  end
  for _, record_type in ipairs({"A", "AAAA"}) do
    local dns_result = false
    local dns_tries = 0
    while not dns_result and dns_tries < 5 do
      local id = math.random(65535)
      local packet = dns.encode({
        ["id"] = id,
        ["query"] = true,
        ["rd"] = true,
        ["question"] = {
          ["name"] = domain .. ".",
          ["type"] = record_type
        }
      })
      for _, server in ipairs({
        "1.1.1.1",
        "1.0.0.1",
        "2606:4700:4700::1111",
        "2606:4700:4700::1001"
      }) do
        local udp = socket.udp()
        udp:settimeout(1)
        local response = nil
        if udp:setpeername(server, 53) and udp:send(packet) then
          response = udp:receive()
        end
        udp:close()
        if response then
          local decoded = dns.decode(response)
          if decoded and decoded["id"] == id and not decoded["tc"] then
            if decoded["rcode"] == 0 then
              dns_result = true
              for _, record in pairs(decoded["answers"]) do
                if record["address"] then
                  for _, pattern in pairs({
                    "^199%.34%.22[89]%.",
                    "^199%.34%.23[01]%.",
                    "^74%.115%.4[89]%.",
                    "^74%.115%.5[01]%.",
                    "^185%.148%.180%.",
                    "^2620:0*11c:0*[0-9a-f]:",
                    "^2620:0*11c::"
                  }) do
                    if string.match(string.lower(record["address"]), pattern) then
                      accept_ip_cache[domain] = true
                      return true
                    end
                  end
                end
              end
              break
            elseif decoded["rcode"] == 3 then
              dns_result = true
              break
            end
          end
        end
      end
      if not dns_result then
        dns_tries = dns_tries + 1
        if dns_tries < 5 then
          os.execute("sleep " .. math.floor(math.pow(2, dns_tries - 1)))
        end
      end
    end
    if not dns_result then
      error("DNS resolver errors.")
    end
  end
  accept_ip_cache[domain] = false
  return false
end

allowed = function(url)
  local lower = string.lower(url)
  if string.match(lower, "^http://")
    and processed(string.gsub(url, "^http://", "https://")) then
    return false
  end
  if ids[lower] then
    return true
  end

  for _, pattern in pairs({
    "^https?://[^/]*twitter%.com/share/?%?",
    "^https?://[^/]*twitter%.com/intent/tweet/?%?",
    "^https?://[^/]*x%.com/share/?%?",
    "^https?://[^/]*x%.com/intent/tweet/?%?",
    "^https?://[^/]*facebook%.com/sharer%.php%?",
    "^https?://[^/]*facebook%.com/sharer/sharer%.php%?",
    "^https?://[^/]*linkedin%.com/sharearticle%?",
    "^https?://[^/]*linkedin%.com/sharing/share%-offsite/?%?",
    "^https?://[^/]*pinterest%.com/pin/create/button/?%?",
    "^https?://[^/]*t%.me/share/url/?%?"
  }) do
    if string.match(lower .. "?", pattern) then
      return false
    end
  end

  local host = string.match(lower, "^https?://([^/]+)/")
  local page_host = string.match(string.lower(context["page_url"]), "^https?://([^/]+)/")
  if not string.match(host, "%.") then
    return false
  end

  if item_type == "media"
    and (host == page_host or host == "www.weebly.com") then
    for identifier in string.gmatch(url, "https?://[^/]+(/.+)$") do
      if ids[string.gsub(identifier, "%?[0-9]+$", "")] then
        return true
      end
    end
  end

  for _, name in pairs({"video", "forum", "map"}) do
    if string.match(lower, "^https?://www%.weebly%.com/weebly/apps/generate" .. name .. "%.php%?")
      or (name == "map" and string.match(lower, "^https?://www%.weebly%.com/ajax/apps/generatemap%.php%?")) then
      for identifier in string.gmatch(url, "[%?&]elementid=([^&]+)") do
        if ids[identifier] then
          return true
        end
      end
      return false
    end
  end

  if host ~= page_host
    and not string.match(lower, "^https?://[^/]+%.weebly%.com/")
    and not string.match(lower, "^https?://[^/]+%.editmysite%.com/uploads/") then
    if string.match(lower, "^https?://[^/]+%.editmysite%.com/")
      or string.match(lower, "^https?://[^/]+%.google%-analytics%.com/")
      or string.match(lower, "^https?://[^/]+%.googletagmanager%.com/")
      or string.match(lower, "^https?://fonts%.googleapis%.com/")
      or string.match(lower, "^https?://ajax%.googleapis%.com/ajax/libs/")
      or string.match(lower, "^https?://www%.google%.com/recaptcha/") then
      return false
    end
    if not accept_ip(url) then
      discover_item(discovered_outlinks, percent_encode_url(url))
      return false
    end
  end

  if host == page_host
    and context["category"]
    and string.match(urlparse.unescape(url), "^https?://[^/]+/ajax/api/JsonRPC/Commerce/%?Commerce%[Category::generateProductList%]") then
    return true
  end

  local found = find_item(url)
  for _, pattern in pairs({
    "^https?://[^/]+/ajax/",
    "^https?://[^/]+/app/",
    "^https?://[^/]+/editor/",
    "^https?://[^/]+/weebly/",
    "^https?://[^/]+/cdn%-cgi/",
    "^https?://[^/]+/store/cart[/%?]",
    "^https?://[^/]+/store/checkout[/%?]",
    "^https?://[^/]+/store/account[/%?]"
  }) do
    if string.match(lower .. "?", pattern)
      and not string.match(lower, "^https?://[^/]+/editor/uploads/")
      and not string.match(lower, "^https?://[^/]+/cdn%-cgi/image/") then
      return false
    end
  end
  if host ~= page_host
    and (host == "www.weebly.com" or host == "editor.weebly.com" or host == "help.weebly.com")
    and not string.match(lower, "^https?://[^/]+/uploads/")
    and not string.match(lower, "^https?://[^/]+/files/")
    and not string.match(lower, "^https?://[^/]+/editor/uploads/")
    and not string.match(lower, "^https?://[^/]+/cdn%-cgi/image/") then
    return false
  end

  if found then
    if string.match(url, "^https?://www%.weebly%.com/uploads/") then
      found["value"] = string.match(context["page_url"], "^https?://([^/]+)") .. string.match(url, "^https?://[^/]+(/.+)$")
    end
    if item_type == "page" and found["type"] == "media" then
      local original, extension = string.match(found["value"] .. "?", "^([^/]+/uploads/[^%?]+)%.([a-zA-Z]+)%?")
      if original
        and ({
          ["jpg"]=true,
          ["jpeg"]=true,
          ["png"]=true,
          ["gif"]=true,
          ["webp"]=true
        })[string.lower(extension)] then
        if string.match(found["value"], "%?width=[0-9]+$") then
          allowed("https://" .. original .. "." .. extension)
        end
        if not string.match(string.lower(original), "_orig$") then
          original = string.gsub(original, "/published/", "/")
          allowed("https://" .. original .. "_orig." .. extension)
        end
      end
    end
    local new_item = found["type"] .. ":" .. found["value"]
    if new_item ~= item_name then
      local target = discovered_items
      if found["type"] == "page"
        and host == page_host
        and context["stash_pages"] then
        --target = discovered_stash
      end
      discover_item(target, percent_encode_url(new_item))
      return false
    end
    return true
  end

  return false
end

wget.callbacks.download_child_p = function(urlpos, parent, depth, start_url_parsed, iri, verdict, reason)
  return false
end

decode_codepoint = function(newurl)
  newurl = string.gsub(
    newurl, "\\[uU]([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F])",
    function(s)
      return utf8.char(tonumber(s, 16))
    end
  )
  return newurl
end

wget.callbacks.get_urls = function(file, url, is_css, iri)
  local urls = {}
  local html = nil
  local json = nil

  downloaded[url] = true

  if abortgrab then
    return {}
  end

  local function fix_case(newurl)
    if not string.match(newurl, "^https?://[^/]") then
      return newurl
    end
    if string.match(newurl, "^https?://[^/]+$") then
      newurl = newurl .. "/"
    end
    local a, b = string.match(newurl, "^(https?://[^/]+/)(.*)$")
    return string.lower(a) .. b
  end

  local function check(newurl, body_data)
    if not newurl then
      newurl = ""
    end
    newurl = html_entities.decode(decode_codepoint(newurl))
    newurl = string.gsub(newurl, "\\/", "/")
    newurl = string.match(newurl, "^%s*(.-)%s*$")
    newurl = fix_case(newurl)
    newurl = string.gsub(newurl, "^http://", "https://")
    if not string.match(newurl, "^https?://[^/]+/") or string.match(newurl, '[%s\\"]')
      or string.match(urlparse.unescape(newurl), "{{") then
      return nil
    end
    local url = string.match(newurl, "^([^#]+)")
    local url_ = url
    while string.match(url_, "&amp;") do
      url_ = string.gsub(url_, "&amp;", "&")
    end
    local key = (body_data and "POST" or "GET") .. "\0" .. url_ .. "\0" .. (body_data or "")
    if not processed(key)
      and (body_data or not processed(url_))
      and allowed(url_) then
      local url_data = {
        url=url_,
        headers={}
      }
      if body_data then
        url_data["body_data"] = body_data
        url_data["method"] = "POST"
        url_data["headers"]["Content-Type"]="application/json"
      end
      table.insert(urls, url_data)
      ids[string.lower(url_)] = true
      addedtolist[key] = true
      if not body_data then
        addedtolist[url_] = true
        addedtolist[url] = true
      end
      return true
    end
  end

  local function checknewurl(newurl)
    if not newurl then
      newurl = ""
    end
    newurl = decode_codepoint(newurl)
    if string.match(newurl, "['\"><]") then
      return nil
    end
    if string.match(newurl, "^https?:////") then
      check((string.gsub(newurl, ":////", "://")))
    elseif string.match(newurl, "^https?://") then
      check(newurl)
    elseif string.match(newurl, "^https?:\\/\\?/") then
      check((string.gsub(newurl, "\\", "")))
    elseif string.match(newurl, "^\\/\\/") then
      checknewurl(string.gsub(newurl, "\\", ""))
    elseif string.match(newurl, "^//") then
      check(urlparse.absolute(url, newurl))
    elseif string.match(newurl, "^\\/") then
      checknewurl(string.gsub(newurl, "\\", ""))
    elseif string.match(newurl, "^/") then
      check(urlparse.absolute(url, newurl))
    elseif string.match(newurl, "^%.%./") then
      if string.match(url, "^https?://[^/]+/[^/]+/") then
        check(urlparse.absolute(url, newurl))
      else
        checknewurl(string.match(newurl, "^%.%.(/.+)$"))
      end
    elseif string.match(newurl, "^%./") then
      check(urlparse.absolute(url, newurl))
    end
  end

  local function checknewshorturl(newurl)
    newurl = decode_codepoint(newurl)
    if string.match(newurl, "['\"><]") then
      return nil
    end
    if string.match(newurl, "^%?") then
      check(urlparse.absolute(url, newurl))
    elseif not (
      string.match(newurl, "^https?:\\?/\\?//?/?")
      or string.match(newurl, "^[/\\]")
      or string.match(newurl, "^%./")
      or string.match(newurl, "^[jJ]ava[sS]cript:")
      or string.match(newurl, "^[mM]ail[tT]o:")
      or string.match(newurl, "^vine:")
      or string.match(newurl, "^android%-app:")
      or string.match(newurl, "^ios%-app:")
      or string.match(newurl, "^data:")
      or string.match(newurl, "^irc:")
      or string.match(newurl, "^%${")
    ) then
      check(urlparse.absolute(url, newurl))
    end
  end

  local function check_category(page)
    local category = context["category"]
    local rpc_url = string.match(context["page_url"], "^(https?://[^/]+)") .. "/ajax/api/JsonRPC/Commerce/?Commerce%5BCategory::generateProductList%5D"
    check(rpc_url, '{"jsonrpc":"2.0","method":"Category::generateProductList","params":["' .. category["id"] .. '","' .. page .. '","' .. category["limit"] .. '"],"id":0}')
    check(rpc_url .. "&jsonrpc=2.0&method=Category%3A%3AgenerateProductList&params%5B%5D=" .. category["id"] .. "&params%5B%5D=" .. page .. "&params%5B%5D=" .. category["limit"] .. "&id=0&callback=WJsonp")
  end

  if allowed(url) and status_code < 300 then
    if string.match(url, "^https?://[^/]+/ajax/api/JsonRPC/Commerce/")
      or string.match(content_type, "^text/")
      or string.match(content_type, "xml")
      or string.match(content_type, "javascript") then
      html = read_file(file)
    end

    if item_type == "media" then
      if string.match(item_value, "^[^/]+/uploads/") then
        check((string.gsub(url, "%?[0-9]+$", "")))
        check("https://www.weebly.com" .. string.match(item_value, "^[^/]+(/.+)$"))
      end
    elseif string.match(url, "^https?://[^/]+/ajax/api/JsonRPC/Commerce/") then
      json = cjson.decode(string.match(html, "^WJsonp%((.+)%)%s*;?%s*$") or html)
      html = json["result"]["content"]
      for page in string.gmatch(json["result"]["pagelist"], 'data%-page=["\']([0-9]+)["\']') do
        check_category(page)
      end
    elseif html then
      if string.match(url, "^https?://[^/]+/robots%.txt$") then
        for line in string.gmatch(html .. "\n", "([^\r\n]+)[\r\n]+") do
          local name, newurl = string.match(line, "^%s*([a-zA-Z]+):%s*([^#%s]+)")
          if name then
            name = string.lower(name)
            if name == "sitemap" then
              check(newurl)
            elseif (name == "allow" or name == "disallow")
              and string.match(newurl, "^/")
              and not string.match(newurl, "[*$]") then
              check(urlparse.absolute(url, newurl))
            end
          end
        end
      elseif string.match(url, "^https?://www%.weebly%.com/weebly/apps/generateVideo%.php%?") then
        url = context["page_url"]
      elseif url == context["page_url"] then
        if string.match(content_type, "^text/html") then
          local country = string.match(html, "_W%.storeCountry%s*=%s*[\"']([a-zA-Z][a-zA-Z])[\"']")
          if country then
            context["stash_pages"] = not ({
              ["AD"]=true,
              ["AE"]=true,
              ["AL"]=true,
              ["AM"]=true,
              ["AW"]=true,
              ["AZ"]=true,
              ["BA"]=true,
              ["BB"]=true,
              ["BD"]=true,
              ["BH"]=true,
              ["BJ"]=true,
              ["BS"]=true,
              ["BY"]=true,
              ["CD"]=true,
              ["CG"]=true,
              ["CI"]=true,
              ["CL"]=true,
              ["CM"]=true,
              ["CO"]=true,
              ["CR"]=true,
              ["DZ"]=true,
              ["EC"]=true,
              ["EG"]=true,
              ["ET"]=true,
              ["GA"]=true,
              ["GE"]=true,
              ["GH"]=true,
              ["GN"]=true,
              ["IS"]=true,
              ["JO"]=true,
              ["KE"]=true,
              ["KH"]=true,
              ["KR"]=true,
              ["KZ"]=true,
              ["LA"]=true,
              ["MA"]=true,
              ["MD"]=true,
              ["ME"]=true,
              ["MU"]=true,
              ["MY"]=true,
              ["NC"]=true,
              ["NG"]=true,
              ["NP"]=true,
              ["OM"]=true,
              ["PE"]=true,
              ["PF"]=true,
              ["PK"]=true,
              ["PW"]=true,
              ["PY"]=true,
              ["RS"]=true,
              ["RU"]=true,
              ["SA"]=true,
              ["SG"]=true,
              ["SL"]=true,
              ["SN"]=true,
              ["SR"]=true,
              ["TH"]=true,
              ["TJ"]=true,
              ["TR"]=true,
              ["TW"]=true,
              ["TZ"]=true,
              ["UA"]=true,
              ["UG"]=true,
              ["UY"]=true,
              ["UZ"]=true,
              ["VN"]=true,
              ["ZM"]=true,
              ["ZW"]=true
            })[string.upper(country)]
          end
          check(urlparse.absolute(url, "/favicon.ico"))
        end
        if string.match(url, "^https?://[^/]+/$") then
          check(url .. "sitemap.xml")
          check(url .. "robots.txt")
        end
        local category = string.match(url, "/store/c([0-9]+)/")
        if category and string.match(html, "generateProductList") then
          local limit = nil
          for input in string.gmatch(html, "<input[^>]+>") do
            if string.match(input, 'id=["\']wsite%-com%-category%-product%-group%-pagelimit["\']') then
              limit = string.match(input, 'value=["\']([0-9]+)["\']')
            end
          end
          context["category"] = {
            ["id"]=category,
            ["limit"]=limit or "24"
          }
          check_category(0)
        end
      end
      for element in string.gmatch(html, '//www%.weebly%.com/weebly/apps/generate[a-zA-Z]+%.php%?[^"\']-elementid=([^&"\']+)') do
        ids[element] = true
      end
      for slideshow in string.gmatch(html, "wSlideshow%.render%((%b{})") do
        for images in string.gmatch(slideshow, "images:%s*(%b[])") do
          for _, image in ipairs(cjson.decode(images)) do
            local newurl = image["publishedUrl"] or image["url"]
            if not image["editorUrl"]
              and not string.match(newurl, "/weebly/images/")
              and not string.match(newurl, "x%-com%-weebly%-images") then
              newurl = "/uploads/" .. string.gsub(newurl, "^/uploads/", "")
              check(urlparse.absolute(url, newurl))
              if image["thumbnail"] ~= false then
                newurl = string.gsub(newurl, "^(.*)%.([^%.]+)$", "%1_orig.%2")
              end
            end
            check(urlparse.absolute(url, newurl))
          end
        end
      end
    end

    if html then
      for quote, quoted in pairs({
        ['"']=string.gsub(html, "&[qQ][uU][oO][tT];", '"'),
        ["'"]=string.gsub(html, "&#039;", "'")
      }) do
        for newurl in string.gmatch(quoted, "([^" .. quote .. "]+)") do
          checknewurl(newurl)
        end
        for _, attribute in pairs({"href", "src"}) do
          for newurl in string.gmatch(html, "[^%-]" .. attribute .. "=" .. quote .. "([^" .. quote .. "]+)" .. quote) do
            checknewshorturl(newurl)
          end
        end
      end
      for newurl in string.gmatch(html, "url%(([^%)]+)%)") do
        newurl = html_entities.decode(newurl)
        newurl = string.match(newurl, "^%s*(.-)%s*$")
        check(urlparse.absolute(url, string.gsub(newurl, "^['\"](.-)['\"]$", "%1")))
      end
      for _, pattern in pairs({
        "<loc%s*>(.-)</loc%s*>",
        "<[0-9a-zA-Z_%-]+:loc%s*>(.-)</[0-9a-zA-Z_%-]+:loc%s*>"
      }) do
        for newurl in string.gmatch(html, pattern) do
          check(string.match(newurl, "^%s*<!%[CDATA%[(.-)%]%]>%s*$") or newurl)
        end
      end
      for newurl in string.gmatch(html, '<link>(https?://[^<]+)</link>') do
        check(newurl)
      end
      for srcset in string.gmatch(html, 'srcset=["\']([^"\']+)') do
        for newurl in string.gmatch(srcset, "([^,%s]+)%s+[0-9.]+[wx]") do
          check(urlparse.absolute(url, newurl))
        end
      end
    end
  end

  return urls
end

wget.callbacks.dedup_response = function(url, digest)
  if context["digests"][url] then
    if digest ~= context["digests"][url] then
      error("WARC digest does not match downloaded data.")
    end
    context["digests"][url] = true
    context["warc_digests"][digest] = true
  end
end

wget.callbacks.write_to_warc = function(url, http_stat)
  local headers = http_stat["response_headers"]["headers"]
  status_code = http_stat["statcode"]
  content_type = headers["content-type"] and string.lower(headers["content-type"][1]) or ""
  set_item(url["url"])

  url_count = url_count + 1
  io.stdout:write(url_count .. "=" .. status_code .. " " .. url["url"] .. " \n")
  io.stdout:flush()

  logged_response = true
  if not item_name then
    error("No item name found.")
  end

  if http_stat["res"] < 0 then
    return false
  end

  if not (
    status_code == 200
    or status_code == 301
    or status_code == 302
    or status_code == 404
  ) then
    retry_url = true
    return false
  end

  if status_code == 200 then
    if http_stat["len"] == 0
      or (http_stat["contlen"] >= 0 and http_stat["len"] ~= http_stat["contlen"]) then
      retry_url = true
      return false
    end
    if string.match(url["url"], "^https?://[^/]+/ajax/api/JsonRPC/Commerce/") then
      local html = read_file(http_stat["local_file"])
      local json = cjson.decode(string.match(html, "^WJsonp%((.+)%)%s*;?%s*$") or html)
      if json["error"]
        or type(json["result"]) ~= "table"
        or type(json["result"]["content"]) ~= "string"
        or type(json["result"]["pagelist"]) ~= "string"
        or type(json["result"]["total"]) ~= "number" then
        retry_url = true
        return false
      end
    elseif string.match(url["url"], "^https?://www%.weebly%.com/weebly/apps/generateVideo%.php%?") then
      if not string.match(read_file(http_stat["local_file"]), "<source%s") then
        retry_url = true
        return false
      end
    end
    local expected = nil
    if headers["etag"] then
      local etag = string.gsub(headers["etag"][1], "^W/", "")
      expected = string.match(etag, "^\"([0-9a-fA-F]+)\"$") or string.match(etag, "^\"([0-9a-fA-F]+)%-gzip\"$")
    end
    local sha1 = openssl_digest.new("sha1")
    local md5 = nil
    if expected and string.len(expected) == 32 then
      md5 = openssl_digest.new("md5")
    end
    local file = assert(io.open(http_stat["local_file"], "rb"))
    while true do
      local data = file:read(16 * 1024 * 1024)
      if not data then
        break
      end
      sha1:update(data)
      if md5 then
        md5:update(data)
      end
    end
    file:close()
    if md5 and basexx.to_hex(md5:final()) ~= string.upper(expected) then
      error("File does not match etag.")
    end
    context["digests"][url["url"]] = "sha1:" .. basexx.to_base32(sha1:final())
  end

  if status_code >= 300 and status_code <= 399 then
    if not http_stat["newloc"] then
      retry_url = true
      return false
    end
    local newloc = urlparse.absolute(url["url"], http_stat["newloc"])
    if string.match(newloc, "^https?://[^/]+$") then
      newloc = newloc .. "/"
    end
    if string.match(newloc, '[%s\\"]') or not string.match(newloc, "^https?://") then
      retry_url = true
      return false
    end
  end

  if abortgrab then
    print("Not writing to WARC.")
    return false
  end
  retry_url = false
  tries = 0
  return true
end

wget.callbacks.httploop_result = function(url, err, http_stat)
  status_code = http_stat["statcode"]
  set_item(url["url"])

  if not logged_response then
    url_count = url_count + 1
    io.stdout:write(url_count .. "=" .. status_code .. " " .. url["url"] .. " \n")
    io.stdout:flush()
    retry_url = true
  end
  logged_response = false

  if killgrab then
    return wget.actions.ABORT
  end

  if not item_name then
    error("No item name found.")
  end

  if abortgrab then
    abort_item()
    return wget.actions.EXIT
  end

  local newloc = nil
  if status_code >= 300 and status_code <= 399 then
    if http_stat["newloc"] then
      newloc = urlparse.absolute(url["url"], http_stat["newloc"])
    end
  end

  if status_code == 0 or http_stat["res"] < 0 or retry_url then
    io.stdout:write("Server returned bad response. ")
    io.stdout:flush()
    tries = tries + 1
    local maxtries = 5
    if tries > maxtries then
      io.stdout:write(" Skipping.\n")
      io.stdout:flush()
      tries = 0
      abort_item()
      return wget.actions.EXIT
    end
    local sleep_time = math.random(
      math.floor(math.pow(2, tries-0.5)),
      math.floor(math.pow(2, tries))
    )
    io.stdout:write("Sleeping " .. sleep_time .. " seconds.\n")
    io.stdout:flush()
    os.execute("sleep " .. sleep_time)
    return wget.actions.CONTINUE
  else
    downloaded[url["url"]] = true
  end

  if newloc then
    if string.match(newloc, "^https?://[^/]+$") then
      newloc = newloc .. "/"
    end
    if processed(newloc) or not allowed(newloc) then
      tries = 0
      return wget.actions.EXIT
    end
    ids[string.lower(newloc)] = true
    if item_type == "page" and url["url"] == context["page_url"] then
      context["page_url"] = newloc
    end
  end

  tries = 0

  return wget.actions.NOTHING
end

wget.callbacks.finish = function(start_time, end_time, wall_time, numurls, total_downloaded_bytes, total_download_time)
  for _, checked in pairs(context["digests"]) do
    if checked ~= true and not context["warc_digests"][checked] then
      error("WARC digest does not match downloaded data.")
    end
  end
  local function submit_backfeed(items, key)
    local tries = 0
    local maxtries = 5
    while tries < maxtries do
      if killgrab then
        return false
      end
      local body, code, headers, status = https.request(
        "https://legacy-api.arpa.li/backfeed/legacy/" .. key,
        items .. "\0"
      )
      if code == 200 and body ~= nil and cjson.decode(body)["status_code"] == 200 then
        io.stdout:write(string.match(body, "^(.-)%s*$") .. "\n")
        io.stdout:flush()
        return nil
      end
      io.stdout:write("Failed to submit discovered URLs." .. tostring(code) .. tostring(body) .. "\n")
      io.stdout:flush()
      os.execute("sleep " .. math.floor(math.pow(2, tries)))
      tries = tries + 1
    end
    kill_grab()
    error()
  end

  local file = io.open(item_dir .. "/" .. warc_file_base .. "_bad-items.txt", "w")
  for url, _ in pairs(bad_items) do
    file:write(url .. "\n")
  end
  file:close()
  for key, data in pairs({
    ["weebly-485228e7414c957f"] = discovered_items,
    --["weebly-stash-37bf6477d0c34dc2?shard=stash"] = discovered_stash,
    ["urls-37a59ecb1f858125"] = discovered_outlinks
  }) do
    print("queuing for", string.match(key, "^(.+)%-"))
    local items = nil
    local count = 0
    for item, _ in pairs(data) do
      print("found item", item)
      if items == nil then
        items = item
      else
        items = items .. "\0" .. item
      end
      count = count + 1
      if count == 1000 then
        submit_backfeed(items, key)
        items = nil
        count = 0
      end
    end
    if items ~= nil then
      submit_backfeed(items, key)
    end
  end
end

wget.callbacks.before_exit = function(exit_status, exit_status_string)
  if killgrab then
    return wget.exits.IO_FAIL
  end
  if abortgrab then
    abort_item()
  end
  return exit_status
end

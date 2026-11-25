-- Persistent installation identity for WeRead's ordinary Web QR sessions.
-- Not the Native shelf-management deviceId and not the local login_session_id.
--
-- The real Web client does not invent wr_fp from entropy: the weread.qq.com
-- bundle exports generateFingerprint(), which computes
--     murmur3_32(JSON.stringify(deviceFingerprint, null, 4))
-- over a browser attribute map and then pins the unsigned 32-bit result in the
-- wr_fp cookie for a year (expires: 365, domain: weread.qq.com).
-- We reproduce that shape for this device: the same MurmurHash3 primitive and
-- the same JSON-ish serialisation, but over the attributes a KOReader install
-- actually has. The result is a fingerprint that behaves like a browser's —
-- deterministic per device and unique per device, so it survives a plugin
-- reinstall instead of minting a brand-new identity on every upgrade.
--
-- A device whose hardware cannot be told apart from another's keeps the old
-- entropy behaviour on purpose: two installations sharing one identity is a
-- worse outcome than a value that never repeats.
local D = require("miuread.digests")
local Protocol = require("miuread.protocol")

local Identity = {}
local KEY = "device_fingerprint"

function Identity.valid(value)
    return type(value) == "string" and #value >= 1 and #value <= 10
        and value:match("^%d+$") ~= nil and tonumber(value) <= 4294967295
end

--------------------------------------------------------------------------
-- Device attributes
--------------------------------------------------------------------------

local function read_file(path, limit)
    local file = io.open(path, "rb")
    if not file then return nil end
    local ok, data = pcall(file.read, file, limit or 4096)
    file:close()
    if not ok or type(data) ~= "string" or data == "" then return nil end
    return data
end

local function popen_line(command)
    if type(io.popen) ~= "function" then return nil end
    local ok, pipe = pcall(io.popen, command)
    if not ok or not pipe then return nil end
    local data = pipe:read("*l")
    pipe:close()
    if type(data) ~= "string" then return nil end
    data = data:gsub("%s+$", "")
    if data == "" then return nil end
    return data
end

-- Stable physical-device discriminator. Only genuinely device-unique values
-- qualify; a model name alone would collide across every identical reader.
local function hardware_signature()
    local cpuinfo = read_file("/proc/cpuinfo", 8192)
    if cpuinfo then
        -- Serial is one line among many, never the first.
        for line in cpuinfo:gmatch("[^\n]+") do
            local serial = line:match("^[Ss]erial%s*:%s*(%w+)")
            if serial and serial ~= "" and serial:match("^0+$") == nil then
                return "cpu:" .. serial
            end
        end
    end
    local direct = read_file("/sys/class/net/wlan0/address", 64)
        or read_file("/sys/class/net/eth0/address", 64)
    if direct then
        local mac = direct:match("([%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x])")
        if mac and mac ~= "00:00:00:00:00:00" then return "mac:" .. mac:lower() end
    end
    if type(io.popen) == "function" then
        local ok, pipe = pcall(io.popen, "cat /sys/class/net/*/address 2>/dev/null")
        if ok and pipe then
            local dump = pipe:read("*a") or ""
            pipe:close()
            for mac in dump:gmatch("([%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x])") do
                if mac ~= "00:00:00:00:00:00" then return "mac:" .. mac:lower() end
            end
        end
    end
end

local function uname()
    local line = popen_line("uname -s -m 2>/dev/null")
    if line then
        local system, machine = line:match("^(%S+)%s+(%S+)$")
        if system then return system, machine end
    end
    return nil, nil
end

-- Returns the IANA-ish zone label and the value Date.prototype.getTimezoneOffset
-- would report (minutes WEST of UTC, so UTC+8 is -480).
local function timezone()
    local stamp = os.time()
    local offset = 0
    local raw = os.date("%z", stamp)
    if raw and raw:match("^[+-]%d%d%d%d$") then
        offset = tonumber(raw:sub(2, 3)) * 60 + tonumber(raw:sub(4, 5))
        if raw:sub(1, 1) == "-" then offset = -offset end
    end
    local zone = os.date("%Z", stamp)
    if not zone or zone == "" then zone = "UTC" end
    return zone, -offset
end

--------------------------------------------------------------------------
-- Profile + canonical serialisation
--------------------------------------------------------------------------

-- Fixed order, mirroring the key order the Web bundle builds its map in.
-- Stability matters more than the exact text: a reordered table would change
-- the hash and hand the account a new device identity on the next run.
local PROFILE_KEYS = {
    "appCodeName", "appName", "appVersion", "cookieEnabled", "deviceMemory",
    "devicePixelRatio", "doNotTrack", "hardwareConcurrency", "language",
    "languages", "maxTouchPoints", "platform", "product", "productSub",
    "timezone", "timezoneOffset", "touchSupport", "userAgent", "vendor",
    "vendorSub", "hardware",
}

local function json_scalar(value)
    local kind = type(value)
    if kind == "boolean" then return value and "true" or "false" end
    if kind == "number" then
        if value % 1 == 0 then return string.format("%d", value) end
        return tostring(value)
    end
    local text = tostring(value or "")
    text = text:gsub('[%c"\\]', function(char)
        if char == '"' then return '\\"' end
        if char == "\\" then return "\\\\" end
        if char == "\n" then return "\\n" end
        if char == "\r" then return "\\r" end
        if char == "\t" then return "\\t" end
        return string.format("\\u%04x", char:byte())
    end)
    return '"' .. text .. '"'
end

-- Equivalent of JSON.stringify(profile, null, 4): fixed key order, four-space
-- indentation, one entry per line.
local function serialize(profile)
    local lines = {}
    for index, key in ipairs(PROFILE_KEYS) do
        lines[index] = '    "' .. key .. '": ' .. json_scalar(profile[key])
    end
    return "{\n" .. table.concat(lines, ",\n") .. "\n}"
end

function Identity.profile(hardware)
    local system, machine = uname()
    local zone, offset = timezone()
    local useragent = Protocol.USER_AGENT
    local app_version = useragent:gsub("^Mozilla/", "")
    return {
        appCodeName = "Mozilla",
        appName = "Netscape",
        appVersion = app_version,
        cookieEnabled = true,
        deviceMemory = 8,
        devicePixelRatio = 1,
        doNotTrack = "1",
        hardwareConcurrency = 4,
        language = "zh-CN",
        languages = "zh-CN,zh",
        maxTouchPoints = 5,
        platform = (system and machine) and (system .. " " .. machine) or "Linux unknown",
        product = "Gecko",
        productSub = "20030107",
        timezone = zone,
        timezoneOffset = offset,
        touchSupport = true,
        userAgent = useragent,
        vendor = "Google Inc.",
        vendorSub = "",
        hardware = hardware,
    }
end

-- MurmurHash3 over the serialised profile. Returns nil when the device cannot
-- be distinguished, so the caller can fall back to entropy.
function Identity.derive()
    local hardware = hardware_signature()
    if not hardware then return nil, "no stable hardware identifier" end
    local fingerprint = D.murmur3_32(serialize(Identity.profile(hardware)))
    local text = tostring(fingerprint)
    if not Identity.valid(text) then return nil, "derived fingerprint out of range" end
    return text, "device"
end

-- Last resort, unchanged from the original implementation: a value unique to
-- this installation and nothing else.
function Identity.entropy()
    local source = io.open("/dev/urandom", "rb")
    if not source then return nil end
    local ok, bytes = pcall(source.read, source, 4)
    source:close()
    if not ok or type(bytes) ~= "string" or #bytes ~= 4 then return nil end
    local a, b, c, d = bytes:byte(1, 4)
    return string.format("%.0f", ((a * 256 + b) * 256 + c) * 256 + d)
end

--------------------------------------------------------------------------
-- Persistence
--------------------------------------------------------------------------

-- Returns the stored fingerprint, generating and persisting one on first use.
-- An existing value is always kept, so upgrading never rotates a live
-- account's device identity; only fresh installations get the derived value.
function Identity.get(store)
    if not store or type(store.get) ~= "function" or type(store.set) ~= "function" then
        return nil, "device settings unavailable"
    end
    local existing = store:get(KEY, "")
    if Identity.valid(existing) then
        if type(store.read_persisted) == "function" then
            local persisted = store:read_persisted(KEY)
            if persisted ~= existing then
                return nil, "existing device identity is not safely persisted"
            end
        end
        return existing
    end

    local fingerprint, source = Identity.derive()
    if not fingerprint then
        fingerprint, source = Identity.entropy(), "entropy"
        if not fingerprint then return nil, "secure device randomness unavailable" end
    end

    local saved, err = store:set(KEY, fingerprint)
    if saved ~= true then return nil, "device identity save failed: " .. tostring(err or "unknown") end
    -- QR credentials must never be issued under an identity that only existed
    -- in memory. Store's disk validation catches interrupted writes.
    if type(store.read_persisted) == "function" then
        local persisted, read_err = store:read_persisted(KEY)
        if tostring(persisted) ~= tostring(fingerprint) then
            return nil, "device identity verification failed: " .. tostring(read_err or "not persisted")
        end
    end
    Identity.last_source = source
    return fingerprint
end

return Identity

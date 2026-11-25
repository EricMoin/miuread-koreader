-- Locks in the client-identity hardening:
--   1. the read-report body carries the same appId/deviceId/installId the
--      E-Ink client populates (ReportService.setAppId/setDeviceId/setInstallId),
--   2. appId stays inside the reading-time signature input,
--   3. wr_fp is a device-derived MurmurHash3 value, not raw entropy, while a
--      previously stored fingerprint still wins (migration safety).
-- Offline only: no KOReader credentials, no server requests.
local TOOL_DIR=tostring(arg and arg[0] or ""):gsub("\\","/"):match("^(.*)/[^/]+$") or "."
package.path=TOOL_DIR.."/../miuread.koplugin/?.lua;"..package.path

local failures=0
local function check(name,ok,detail)
    if ok then print("  ok   "..name)
    else failures=failures+1; print("  FAIL "..name..(detail~=nil and ("  -> "..tostring(detail)) or "")) end
end

------------------------------------------------------------------
-- 1. install_id mirrors Devices.generateInstallId (E-Ink 2.1.2)
------------------------------------------------------------------
local Protocol=require("miuread.protocol")
-- 32 chars: "eink" | "33" | 4691225 | 19-digit hash
local dev="eink3346912251234567890123456789"
local install_id=Protocol.install_id(dev)
check("deviceId is 32 chars",#dev==32,#dev)
check("installId is 32 chars",#install_id==32,#install_id)
check("installId keeps the eink edition prefix",install_id:sub(1,6)=="eink31",install_id:sub(1,6))
-- generateDeviceIdV2 and generateInstallId emit the same
-- DEVICE/BOARD/CPU_ABI/DISPLAY/HOST/TAGS/ID len%10 block, so the pair must
-- agree digit for digit. This is the invariant the two fields are cross-checked on.
check("installId repeats the deviceId digit block",install_id:sub(7,13)==dev:sub(7,13),
    install_id:sub(7,13).." vs "..dev:sub(7,13))
check("installId time block is 9 digits starting 1",install_id:sub(14,22):match("^1%d%d%d%d%d%d%d%d$")~=nil,install_id:sub(14,22))
check("installId random block is 10 digits starting 1",install_id:sub(23,32):match("^1%d%d%d%d%d%d%d%d%d$")~=nil,install_id:sub(23,32))
check("installId is deterministic",Protocol.install_id(dev)==install_id)
check("installId is device-specific",Protocol.install_id("eink3355511111222222222222222222")~=install_id)
-- An unrecognised device id still has to yield a well-formed install id.
local fallback=Protocol.install_id("garbage")
check("fallback keeps the eink31 prefix",fallback:sub(1,6)=="eink31",fallback:sub(1,6))
check("fallback is 32 chars",#fallback==32,#fallback)

------------------------------------------------------------------
-- 2. ReadBookInShelf body fields
------------------------------------------------------------------
local ReportTime=require("miuread.readtime_protocol")
local rows={{start_time=1700000000,duration=600,time_zone="+08:00",book_version=1,risk=0}}
local batch=ReportTime.batch({vid="1234567890",deviceId=dev},"3300000001",rows,"5ecdcfd7f","cfg-token",
    1700000000,7,{timestamp=1700000000000,random=42})
local body=batch.books[1]
check("appId equals deviceId",body.appId==dev and body.deviceId==dev,body.appId)
check("installId matches login value",body.installId==install_id,body.installId)
check("body signature is sha256 hex","#"..tostring(#body.signature)=="#64")
check("outer signature is sha256 hex","#"..tostring(#batch.signature)=="#64")
check("hours are present",type(body.hours)=="table" and #body.hours==1)

-- generatePayLoad feeds appId into the signature; if it ever drops out, a body
-- could be re-attributed to a different device without changing the signature.
local function signature_for(app_id)
    local parts={"1234567890",dev,app_id,"3300000001","0","+08:00","600","0","1700000000_+08:00_600_0"}
    return ReportTime.sign({"5ecdcfd7f","7","1700000000",table.concat(parts,"_")})
end
check("appId is covered by the signature",signature_for("")~=signature_for(dev))

------------------------------------------------------------------
-- 3. wr_fp derivation
------------------------------------------------------------------
local real_open,real_popen=io.open,io.popen
local cpuinfo="processor\t: 0\nmodel name\t: Cortex-A53\nSerial\t\t: 0a1b2c3d4e5f\n"
local function fake_file(content)
    local file={}
    function file:read(count) if count then return content:sub(1,count) end return content end
    function file:close() end
    return file
end
io.open=function(path,mode)
    if path=="/proc/cpuinfo" then return fake_file(cpuinfo) end
    if path=="/sys/class/net/wlan0/address" then return nil end
    return real_open(path,mode)
end
io.popen=function(command)
    if type(command)=="string" and command:find("uname",1,true) then
        return {read=function() return "Linux armv7l" end,close=function() end}
    end
end

local Identity=require("miuread.device_identity")
local derived=Identity.derive()
check("wr_fp derived from hardware",derived~=nil,derived)
check("wr_fp is deterministic",Identity.derive()==derived,derived)
check("wr_fp is a valid fingerprint",Identity.valid(derived),derived)
check("wr_fp is inside uint32",tonumber(derived)<=4294967295,derived)

cpuinfo=cpuinfo:gsub("0a1b2c3d4e5f","ffffffffffff")
check("wr_fp differs per device",Identity.derive()~=derived)

cpuinfo="processor\t: 0\nmodel name\t: unknown\n"
check("wr_fp refuses to guess without hardware",Identity.derive()==nil)

io.open,io.popen=real_open,real_popen

-- An installation that already stored a fingerprint must keep it: rotating a
-- live account's device identity on upgrade is worse than a legacy value.
local stored={device_fingerprint="12345"}
local store={
    get=function(_,key,default) local value=stored[key]; return value==nil and default or value end,
    set=function(_,key,value) stored[key]=value; return true end,
}
check("stored wr_fp wins over derivation",Identity.get(store)=="12345")

-- The entropy path remains reachable on hardware we cannot tell apart.
local entropy=Identity.entropy()
check("entropy fallback stays valid",Identity.valid(entropy),entropy)

print()
if failures>0 then print(failures.." check(s) failed"); os.exit(1) end
print("client identity hardening: all checks passed")

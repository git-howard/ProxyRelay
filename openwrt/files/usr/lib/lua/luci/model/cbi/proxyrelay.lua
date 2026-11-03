local m, s, o
local uci = luci.model.uci.cursor()
local port = uci:get("proxyrelay", "global", "web_port") or "8080"
local server_host = luci.http.getenv("HTTP_HOST") or "192.168.1.1"
local host_ip = server_host:match("^([^:]+)") or "192.168.1.1"
local web_url = "http://" .. host_ip .. ":" .. port .. "/"

m = Map("proxyrelay", translate("ProxyRelay 服务"), 
	translate("ProxyRelay 是一个高性能二级代理中继与智能分流网关。可在下方配置管理端口与进入密码。<br/>" ..
	"<b>Web 控制台入口：</b> <a href='" .. web_url .. "' target='_blank' style='color:#0072c6; font-weight:bold; text-decoration:underline;'>点击此处打开 ProxyRelay Web 控制台</a>"))

s = m:section(NamedSection, "global", "proxyrelay", translate("基础配置"))
s.anonymous = true

o = s:option(Flag, "enabled", translate("启用 ProxyRelay 服务"))
o.default = "1"
o.rmempty = false

o = s:option(Value, "web_port", translate("Web 控制台端口"), translate("设置 ProxyRelay 嵌入式 Web 控制台的监听端口，默认为 8080。"))
o.datatype = "port"
o.default = "8080"
o.rmempty = false

o = s:option(Value, "password", translate("Web 管理密码"), translate("设置进入 Web 控制台的管理密码。若留空则不需要密码直接进入。"))
o.password = true
o.rmempty = true

o = s:option(Value, "db_path", translate("数据库文件路径"), translate("SQLite 数据库文件存储路径。"))
o.default = "/etc/proxyrelay/proxy.db"
o.rmempty = false

function m.on_after_commit(self)
	luci.sys.call("/etc/init.d/proxyrelay restart >/dev/null 2>&1 &")
end

return m

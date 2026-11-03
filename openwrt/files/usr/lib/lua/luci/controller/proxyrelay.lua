module("luci.controller.proxyrelay", package.seeall)

function index()
	if not nixio.fs.access("/etc/config/proxyrelay") then
		return
	end

	local page
	page = entry({"admin", "services", "proxyrelay"}, cbi("proxyrelay"), _("ProxyRelay"), 60)
	page.dependent = true
	page.acl_depends = { "luci-app-proxyrelay" }
end

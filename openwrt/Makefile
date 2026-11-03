include $(TOPDIR)/rules.mk

PKG_NAME:=proxyrelay
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/proxyrelay
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=ProxyRelay - Advanced Proxy Relay and Transparent Gateway
  DEPENDS:=+libpthread +libopenssl +libstdcpp
  URL:=https://github.com/git-howard/ProxyRelay
endef

define Package/proxyrelay/description
  ProxyRelay is an enterprise-grade secondary proxy relay and transparent proxy gateway.
  It supports multi-inbound listeners (HTTP, SOCKS5, TPROXY, REDIRECT), intelligent
  rule-based routing, traffic quotas, device-level access control, and a modern WebUI.
endef

define Package/proxyrelay/conffiles
/etc/config/proxyrelay
endef

define Package/proxyrelay/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/proxyrelay $(1)/usr/bin/proxyrelay

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/proxyrelay $(1)/etc/init.d/proxyrelay

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/proxyrelay $(1)/etc/config/proxyrelay

	$(INSTALL_DIR) $(1)/usr/share/proxyrelay
	$(INSTALL_BIN) ./files/usr/share/proxyrelay/firewall.include $(1)/usr/share/proxyrelay/firewall.include
	$(INSTALL_BIN) ./files/usr/share/proxyrelay/component_manager.sh $(1)/usr/share/proxyrelay/component_manager.sh
	$(CP) -r ./ui $(1)/usr/share/proxyrelay/

	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./files/usr/share/rpcd/acl.d/luci-app-proxyrelay.json $(1)/usr/share/rpcd/acl.d/luci-app-proxyrelay.json

	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DATA) ./files/usr/lib/lua/luci/controller/proxyrelay.lua $(1)/usr/lib/lua/luci/controller/proxyrelay.lua

	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/cbi
	$(INSTALL_DATA) ./files/usr/lib/lua/luci/model/cbi/proxyrelay.lua $(1)/usr/lib/lua/luci/model/cbi/proxyrelay.lua
endef

$(eval $(call BuildPackage,proxyrelay))

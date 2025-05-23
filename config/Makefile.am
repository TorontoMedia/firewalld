sconfdir = $(sysconfdir)/firewalld
prefixlibdir = ${prefix}/lib/firewalld
dist_sconf_DATA = firewalld.conf

desktop_FILES = firewall-config.desktop.in
desktopdir = $(datadir)/applications
desktop_DATA = $(desktop_FILES:.in=)

appdata_FILES = firewall-config.appdata.xml.in
appdatadir = $(datadir)/metainfo/
appdata_DATA = $(appdata_FILES:.in=)

applet_desktop_FILES = firewall-applet.desktop.in
applet_desktopdir = $(sysconfdir)/xdg/autostart
applet_desktop_DATA = $(applet_desktop_FILES:.in=)

confdir = $(sysconfdir)/firewall
dist_conf_DATA = applet.conf

polkit1_action_FILES = org.fedoraproject.FirewallD1.server.policy.in \
                       org.fedoraproject.FirewallD1.desktop.policy.in
polkit1_actiondir = $(datadir)/polkit-1/actions
polkit1_action_DATA = $(polkit1_action_FILES:.in=)

dbus_policydir = $(datadir)/dbus-1/system.d
dist_dbus_policy_DATA = FirewallD.conf

gsettings_in_file = org.fedoraproject.FirewallConfig.gschema.xml.in
gsettings_SCHEMAS = $(gsettings_in_file:.xml.in=.xml)

xmlschemadir = $(prefixlibdir)/xmlschema
dist_xmlschema_DATA = \
	xmlschema/helper.xsd \
	xmlschema/icmptype.xsd \
	xmlschema/ipset.xsd \
	xmlschema/service.xsd \
	xmlschema/zone.xsd
dist_xmlschema_SCRIPTS = xmlschema/check.sh

BUILT_SOURCES = \
	$(desktop_DATA) \
	$(appdata_DATA) \
	$(applet_desktop_DATA) \
	$(polkit1_action_DATA) \
	$(gsettings_SCHEMAS) \
	firewalld-sysctls.conf \
	firewalld.logrotate \
	firewalld.service

@INTLTOOL_DESKTOP_RULE@
@INTLTOOL_POLICY_RULE@
@INTLTOOL_XML_RULE@
@GSETTINGS_RULES@

all: $(desktop_DATA) $(appdata_DATA) $(applet_desktop_DATA) $(polkit1_action_DATA) $(gsettings_SCHEMAS)

CLEANFILES = *~ *\# .\#* firewalld.service firewalld-sysctls.conf firewalld.logrotate

DISTCLEANFILES = \
	$(desktop_DATA) \
	$(appdata_DATA) \
	$(applet_desktop_DATA) \
	$(polkit1_action_DATA) \
	$(gsettings_SCHEMAS)

CONFIG_FILES = \
	helpers/amanda.xml \
	helpers/ftp.xml \
	helpers/h323.xml \
	helpers/irc.xml \
	helpers/netbios-ns.xml \
	helpers/pptp.xml \
	helpers/proto-gre.xml \
	helpers/Q.931.xml \
	helpers/RAS.xml \
	helpers/sane.xml \
	helpers/sip.xml \
	helpers/snmp.xml \
	helpers/tftp.xml \
	icmptypes/address-unreachable.xml \
	icmptypes/bad-header.xml \
	icmptypes/beyond-scope.xml \
	icmptypes/communication-prohibited.xml \
	icmptypes/destination-unreachable.xml \
	icmptypes/echo-reply.xml \
	icmptypes/echo-request.xml \
	icmptypes/failed-policy.xml \
	icmptypes/fragmentation-needed.xml \
	icmptypes/host-precedence-violation.xml \
	icmptypes/host-prohibited.xml \
	icmptypes/host-redirect.xml \
	icmptypes/host-unknown.xml \
	icmptypes/host-unreachable.xml \
	icmptypes/ip-header-bad.xml \
	icmptypes/mld-listener-done.xml \
	icmptypes/mld-listener-query.xml \
	icmptypes/mld-listener-report.xml \
	icmptypes/mld2-listener-report.xml \
	icmptypes/neighbour-advertisement.xml \
	icmptypes/neighbour-solicitation.xml \
	icmptypes/network-prohibited.xml \
	icmptypes/network-redirect.xml \
	icmptypes/network-unknown.xml \
	icmptypes/network-unreachable.xml \
	icmptypes/no-route.xml \
	icmptypes/packet-too-big.xml \
	icmptypes/parameter-problem.xml \
	icmptypes/port-unreachable.xml \
	icmptypes/precedence-cutoff.xml \
	icmptypes/protocol-unreachable.xml \
	icmptypes/redirect.xml \
	icmptypes/reject-route.xml \
	icmptypes/required-option-missing.xml \
	icmptypes/router-advertisement.xml \
	icmptypes/router-solicitation.xml \
	icmptypes/source-quench.xml \
	icmptypes/source-route-failed.xml \
	icmptypes/time-exceeded.xml \
	icmptypes/timestamp-reply.xml \
	icmptypes/timestamp-request.xml \
	icmptypes/tos-host-redirect.xml \
	icmptypes/tos-host-unreachable.xml \
	icmptypes/tos-network-redirect.xml \
	icmptypes/tos-network-unreachable.xml \
	icmptypes/ttl-zero-during-reassembly.xml \
	icmptypes/ttl-zero-during-transit.xml \
	icmptypes/unknown-header-type.xml \
	icmptypes/unknown-option.xml \
	ipsets/README.md \
	policies/allow-host-ipv6.xml \
	services/0-AD.xml \
	services/afp.xml \
	services/alvr.xml \
	services/amanda-client.xml \
	services/amanda-k5-client.xml \
	services/amqp.xml \
	services/amqps.xml \
	services/anno-1602.xml \
	services/anno-1800.xml \
	services/apcupsd.xml \
	services/aseqnet.xml \
	services/audit.xml \
	services/ausweisapp2.xml \
	services/bacula-client.xml \
	services/bacula.xml \
	services/bareos-director.xml \
	services/bareos-filedaemon.xml \
	services/bareos-storage.xml \
	services/bb.xml \
	services/bgp.xml \
	services/bitcoin-rpc.xml \
	services/bitcoin-testnet-rpc.xml \
	services/bitcoin-testnet.xml \
	services/bitcoin.xml \
	services/bittorrent-lsd.xml \
	services/lightning-network.xml \
	services/ceph-exporter.xml \
	services/ceph-mon.xml \
	services/ceph.xml \
	services/cfengine.xml \
	services/checkmk-agent.xml \
	services/civilization-iv.xml \
	services/civilization-v.xml \
	services/cockpit.xml \
	services/collectd.xml \
	services/condor-collector.xml \
	services/cratedb.xml \
	services/ctdb.xml \
	services/dds.xml \
	services/dds-multicast.xml \
	services/dds-unicast.xml \
	services/dhcpv6-client.xml \
	services/dhcpv6.xml \
	services/dhcp.xml \
	services/distcc.xml \
	services/dns-over-quic.xml \
	services/dns-over-tls.xml \
	services/dns.xml \
	services/docker-registry.xml \
	services/docker-swarm.xml \
	services/dropbox-lansync.xml \
	services/elasticsearch.xml \
	services/etcd-client.xml \
	services/etcd-server.xml \
	services/factorio.xml \
	services/finger.xml \
	services/foreman.xml \
	services/foreman-proxy.xml \
	services/freeipa-4.xml \
	services/freeipa-ldaps.xml \
	services/freeipa-ldap.xml \
	services/freeipa-replication.xml \
	services/freeipa-trust.xml \
	services/ftp.xml \
	services/galera.xml \
	services/ganglia-client.xml \
	services/ganglia-master.xml \
	services/git.xml \
	services/gitea.xml \
	services/gpsd.xml \
	services/grafana.xml \
	services/gre.xml \
	services/high-availability.xml \
	services/http3.xml \
	services/https.xml \
	services/http.xml \
	services/ident.xml \
	services/imaps.xml \
	services/imap.xml \
	services/iperf2.xml \
	services/iperf3.xml \
	services/ipfs.xml \
	services/ipp-client.xml \
	services/ipp.xml \
	services/ipsec.xml \
	services/ircs.xml \
	services/irc.xml \
	services/iscsi-target.xml \
	services/isns.xml \
	services/jenkins.xml \
	services/kadmin.xml \
	services/kdeconnect.xml \
	services/kerberos.xml \
	services/kibana.xml \
	services/klogin.xml \
	services/kpasswd.xml \
	services/kprop.xml \
	services/kshell.xml \
	services/kubelet.xml \
	services/kubelet-readonly.xml \
	services/kubelet-worker.xml \
	services/kube-api.xml \
	services/kube-apiserver.xml \
	services/kube-control-plane.xml \
	services/kube-control-plane-secure.xml \
	services/kube-controller-manager.xml \
	services/kube-controller-manager-secure.xml \
	services/kube-nodeport-services.xml \
	services/kube-scheduler.xml \
	services/kube-scheduler-secure.xml \
	services/kube-worker.xml \
	services/ldaps.xml \
	services/ldap.xml \
	services/libvirt-tls.xml \
	services/libvirt.xml \
	services/llmnr-client.xml \
	services/llmnr-tcp.xml \
	services/llmnr-udp.xml \
	services/llmnr.xml \
	services/managesieve.xml \
	services/matrix.xml \
	services/mdns.xml \
	services/minecraft.xml \
	services/memcache.xml \
	services/minidlna.xml \
	services/mndp.xml \
	services/mongodb.xml \
	services/mosh.xml \
	services/mountd.xml \
	services/mpd.xml \
	services/mqtt.xml \
	services/mqtt-tls.xml \
	services/mssql.xml \
	services/ms-wbt.xml \
	services/murmur.xml \
	services/mysql.xml \
	services/nbd.xml \
	services/nebula.xml \
	services/need-for-speed-most-wanted.xml \
	services/netbios-ns.xml \
	services/netdata-dashboard.xml \
	services/nfs.xml \
	services/nfs3.xml \
	services/nmea-0183.xml \
	services/nrpe.xml \
	services/ntp.xml \
	services/nut.xml \
	services/openvpn.xml \
	services/opentelemetry.xml \
	services/ovirt-imageio.xml \
	services/ovirt-storageconsole.xml \
	services/ovirt-vmconsole.xml \
	services/pmcd.xml \
	services/pmproxy.xml \
	services/pmwebapis.xml \
	services/pmwebapi.xml \
	services/plex.xml \
	services/pop3s.xml \
	services/pop3.xml \
	services/postgresql.xml \
	services/privoxy.xml \
	services/prometheus-node-exporter.xml \
	services/prometheus.xml \
	services/proxy-dhcp.xml \
	services/proxy-http.xml \
	services/ps2link.xml \
	services/ps3netsrv.xml \
	services/ptp.xml \
	services/pulseaudio.xml \
	services/puppetmaster.xml \
	services/quassel.xml \
	services/radius.xml \
	services/radsec.xml \
	services/rdp.xml \
	services/redis-sentinel.xml \
	services/redis.xml \
	services/RH-Satellite-6.xml \
	services/RH-Satellite-6-capsule.xml \
	services/rpc-bind.xml \
	services/rootd.xml \
	services/rquotad.xml \
	services/rsh.xml \
	services/rsyncd.xml \
	services/rtsp.xml \
	services/salt-master.xml \
	services/samba-client.xml \
	services/samba-dc.xml \
	services/samba.xml \
	services/sane.xml \
	services/settlers-history-collection.xml \
	services/sips.xml \
	services/sip.xml \
	services/slimevr.xml \
	services/slp.xml \
	services/smtp-submission.xml \
	services/smtps.xml \
	services/smtp.xml \
	services/snmptrap.xml \
	services/snmp.xml \
	services/snmptls-trap.xml \
	services/snmptls.xml \
	services/socks.xml \
	services/spideroak-lansync.xml \
	services/spotify-sync.xml \
	services/squid.xml \
	services/ssdp.xml \
	services/ssh.xml \
	services/statsrv.xml \
	services/steam-streaming.xml \
	services/steam-lan-transfer.xml \
	services/stellaris.xml \
	services/stronghold-crusader.xml \
	services/stun.xml \
	services/stuns.xml \
	services/submission.xml \
	services/supertuxkart.xml \
	services/svdrp.xml \
	services/svn.xml \
	services/syncthing.xml \
	services/syncthing-gui.xml \
	services/syncthing-relay.xml \
	services/synergy.xml \
	services/syscomlan.xml \
	services/syslog-ng.xml \
	services/syslog-tls.xml \
	services/syslog.xml \
	services/telnet.xml \
	services/tentacle.xml \
	services/terraria.xml \
	services/tftp.xml \
	services/tile38.xml \
	services/tinc.xml \
	services/tor-socks.xml \
	services/transmission-client.xml \
	services/turn.xml \
	services/turns.xml \
	services/upnp-client.xml \
	services/vdsm.xml \
	services/vnc-server.xml \
	services/vrrp.xml \
	services/warpinator.xml \
	services/wbem-http.xml \
	services/wbem-https.xml \
	services/wireguard.xml \
	services/ws-discovery-client.xml \
	services/ws-discovery-host.xml \
	services/ws-discovery-tcp.xml \
	services/ws-discovery-udp.xml \
	services/ws-discovery.xml \
	services/wsman.xml \
	services/wsmans.xml \
	services/xdmcp.xml \
	services/xmpp-bosh.xml \
	services/xmpp-client.xml \
	services/xmpp-local.xml \
	services/xmpp-server.xml \
	services/zabbix-agent.xml \
	services/zabbix-java-gateway.xml \
	services/zabbix-server.xml \
	services/zabbix-trapper.xml \
	services/zabbix-web-service.xml \
	services/zero-k.xml \
	services/zerotier.xml \
	zones/block.xml \
	zones/dmz.xml \
	zones/drop.xml \
	zones/external.xml \
	zones/home.xml \
	zones/internal.xml \
	zones/public.xml \
	zones/trusted.xml \
	zones/work.xml

CONFIG_FILES_TESTS = \
	tests/policies/libvirt-routed-in.xml \
	tests/policies/libvirt-routed-out.xml \
	tests/policies/libvirt-to-host.xml \
	tests/zones/FedoraServer.xml \
	tests/zones/FedoraWorkstation.xml \
	tests/zones/libvirt-routed.xml \
	tests/zones/libvirt.xml \
	tests/zones/nm-shared.xml \
	$(NULL)

EXTRA_DIST = \
	$(desktop_FILES) \
	$(appdata_FILES) \
	$(applet_desktop_FILES) \
	$(polkit1_action_FILES) \
	$(gsettings_in_file) \
	$(CONFIG_FILES) \
	$(CONFIG_FILES_TESTS) \
	$(dist_xmlschema_DATA) \
	firewalld.init \
	firewalld.logrotate.in \
	firewalld-sysctls.conf.in \
	firewalld.service.in \
	firewalld.sysconfig \
	macros.firewalld

INSTALL_TARGETS = install-config
UNINSTALL_TARGETS = uninstall-config

INSTALL_TARGETS += install-modprobe.d
UNINSTALL_TARGETS += uninstall-modprobe.d

INSTALL_TARGETS += install-logrotate.d
UNINSTALL_TARGETS += uninstall-logrotate.d

if USE_SYSTEMD
INSTALL_TARGETS += install-service
UNINSTALL_TARGETS += uninstall-service
else
INSTALL_TARGETS += install-init
UNINSTALL_TARGETS += uninstall-init
endif

if INSTALL_SYSCONFIG
INSTALL_TARGETS += install-sysconfig
UNINSTALL_TARGETS += uninstall-sysconfig
endif

if INSTALL_RPMMACROS
INSTALL_TARGETS += install-rpmmacros
UNINSTALL_TARGETS += uninstall-rpmmacros
endif

edit = sed \
	-e 's|@bindir[@]|$(bindir)|g' \
	-e 's|@sbindir[@]|$(sbindir)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	-e 's|@localstatedir[@]|$(localstatedir)|g' \
	-e 's|@MODPROBE[@]|$(MODPROBE)|g' \
	-e 's|@SYSCTL[@]|$(SYSCTL)|g'

firewalld.service: firewalld.service.in
	$(edit) $< >$@

firewalld-sysctls.conf: firewalld-sysctls.conf.in
	$(edit) $< >$@

firewalld.logrotate: firewalld.logrotate.in
	$(edit) $< >$@

install-sysconfig:
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/sysconfig
	$(INSTALL_DATA) $(srcdir)/firewalld.sysconfig $(DESTDIR)$(sysconfdir)/sysconfig/firewalld

uninstall-sysconfig:
	rm -f $(DESTDIR)$(sysconfdir)/sysconfig/firewalld
	rmdir $(DESTDIR)$(sysconfdir)/sysconfig || :

install-rpmmacros:
	$(MKDIR_P) $(DESTDIR)$(prefix)/lib/rpm/macros.d
	$(INSTALL_DATA) $(srcdir)/macros.firewalld $(DESTDIR)$(prefix)/lib/rpm/macros.d

uninstall-rpmmacros:
	rm -f $(DESTDIR)$(prefix)/lib/rpm/macros.d/macros.firewalld
	rmdir $(DESTDIR)$(prefix)/lib/rpm/macros.d || :

install-init: install-sysconfig
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/rc.d/init.d
	$(INSTALL_SCRIPT) $(srcdir)/firewalld.init $(DESTDIR)$(sysconfdir)/rc.d/init.d/firewalld

uninstall-init: uninstall-sysconfig
	rm -f $(DESTDIR)$(sysconfdir)/rc.d/init.d/firewalld
	rmdir $(DESTDIR)$(sysconfdir)/rc.d/init.d || :

install-service: install-sysconfig
	$(MKDIR_P) $(DESTDIR)$(SYSTEMD_UNITDIR)
	$(INSTALL_DATA) firewalld.service $(DESTDIR)$(SYSTEMD_UNITDIR)/firewalld.service

uninstall-service: uninstall-sysconfig
	rm -f $(DESTDIR)$(SYSTEMD_UNITDIR)/firewalld.service
	rmdir $(DESTDIR)$(SYSTEMD_UNITDIR) || :

install-modprobe.d:
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/modprobe.d
	$(INSTALL_DATA) firewalld-sysctls.conf $(DESTDIR)$(sysconfdir)/modprobe.d/firewalld-sysctls.conf

uninstall-modprobe.d:
	rm -f $(DESTDIR)$(sysconfdir)/modprobe.d/firewalld-sysctls.conf
	rmdir $(DESTDIR)$(sysconfdir)/modprobe.d || :

install-logrotate.d:
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/logrotate.d
	$(INSTALL_DATA) firewalld.logrotate $(DESTDIR)$(sysconfdir)/logrotate.d/firewalld

uninstall-logrotate.d:
	rm -f $(DESTDIR)$(sysconfdir)/logrotate.d/firewalld
	rmdir $(DESTDIR)$(sysconfdir)/logrotate.d || :

install-config:
	$(MKDIR_P) $(DESTDIR)$(sconfdir)
	$(MKDIR_P) $(DESTDIR)$(sconfdir)/icmptypes
	$(MKDIR_P) $(DESTDIR)$(sconfdir)/ipsets
	$(MKDIR_P) $(DESTDIR)$(sconfdir)/policies
	$(MKDIR_P) $(DESTDIR)$(sconfdir)/services
	$(MKDIR_P) $(DESTDIR)$(sconfdir)/zones
	$(MKDIR_P) $(DESTDIR)$(sconfdir)/helpers
	$(MKDIR_P) $(DESTDIR)$(prefixlibdir)
	cp -r $(srcdir)/icmptypes $(DESTDIR)$(prefixlibdir)
	cp -r $(srcdir)/ipsets $(DESTDIR)$(prefixlibdir)
	cp -r $(srcdir)/policies $(DESTDIR)$(prefixlibdir)
	cp -r $(srcdir)/services $(DESTDIR)$(prefixlibdir)
	cp -r $(srcdir)/zones $(DESTDIR)$(prefixlibdir)
	cp -r $(srcdir)/helpers $(DESTDIR)$(prefixlibdir)

uninstall-config:
	rmdir $(DESTDIR)$(sconfdir)/icmptypes
	rmdir $(DESTDIR)$(sconfdir)/ipsets
	rmdir $(DESTDIR)$(sconfdir)/policies
	rmdir $(DESTDIR)$(sconfdir)/services
	rmdir $(DESTDIR)$(sconfdir)/zones
	rm -f $(DESTDIR)$(prefixlibdir)/icmptypes/*
	rmdir $(DESTDIR)$(prefixlibdir)/icmptypes
	rm -f $(DESTDIR)$(prefixlibdir)/ipsets/*
	rmdir $(DESTDIR)$(prefixlibdir)/ipsets
	rm -f $(DESTDIR)$(prefixlibdir)/policies/*
	rmdir $(DESTDIR)$(prefixlibdir)/policies
	rm -f $(DESTDIR)$(prefixlibdir)/services/*
	rmdir $(DESTDIR)$(prefixlibdir)/services
	rm -f $(DESTDIR)$(prefixlibdir)/zones/*
	rmdir $(DESTDIR)$(prefixlibdir)/zones
	rm -f $(DESTDIR)$(prefixlibdir)/helpers/*
	rmdir $(DESTDIR)$(prefixlibdir)/helpers

install-data-local: $(INSTALL_TARGETS)

uninstall-local: $(UNINSTALL_TARGETS)

install-data-hook:
	cd $(DESTDIR)$(polkit1_actiondir) && \
		mv org.fedoraproject.FirewallD1.server.policy org.fedoraproject.FirewallD1.server.policy.choice && \
		mv org.fedoraproject.FirewallD1.desktop.policy org.fedoraproject.FirewallD1.desktop.policy.choice && \
		rm -f org.fedoraproject.FirewallD1.policy && \
		$(LN_S) org.fedoraproject.FirewallD1.server.policy.choice org.fedoraproject.FirewallD1.policy

check-local-xmlschema:
	./xmlschema/check.sh
	./xmlschema/check.sh -d ./tests/

# make sure CONFIG_FILES are also in POTFILES
check-local: check-local-xmlschema
	@for file in $(filter-out helpers/% %/README.md,$(CONFIG_FILES)); do \
		if ! grep "$${file}" ${top_srcdir}/po/POTFILES.in > /dev/null; then \
			echo "$${file} should be in ${abs_top_srcdir}/po/POTFILES.in"; \
			exit 1; \
		fi; \
	done

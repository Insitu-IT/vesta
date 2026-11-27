%global debug_package %{nil}
%global __os_install_post %{nil}
%global _build_id_links none

Name:           vesta-agent
Version:        6.2.0
Release:        1%{?dist}
Summary:        Vesta KVM Backup Agent (prebuilt binary)

License:        LicenseRef-Vesta-MMIT-1.1
URL:            https://github.com/Insitu-IT/vesta
Source0:        %{name}-files-%{version}.tar.gz
BuildArch:      x86_64

Provides:       vnbui-agent = %{version}-%{release}
Obsoletes:      vnbui-agent <= %{version}-%{release}
Conflicts:      vnbui-agent > %{version}-%{release}
Conflicts:      vesta-agent-files
Requires:       libvirt-daemon >= 11.10.0
Requires:       libvirt-daemon-driver-qemu >= 11.10.0
Requires:       python3-libvirt >= 11.10.0
Requires:       qemu-img >= 10.1.0
Requires:       acl
Requires:       polkit
Requires:       systemd
Requires:       python3
Requires:       util-linux
Requires(pre): shadow-utils
Requires(pre): systemd
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
Requires(posttrans): systemd

%description
The Vesta Agent connects KVM/libvirt hosts to Vesta Backup for native libvirt
push backup and restore operations. Includes the offline raw-disk restore
command and optional native staging and recovery tools.

%prep
%setup -q -n %{name}-files-%{version}

%build
# The payload binaries are built before rpmbuild runs.

%install
install -Dpm 755 vesta-agent %{buildroot}/opt/vesta-agent/vesta-agent
install -Dpm 755 vesta-restore %{buildroot}%{_bindir}/vesta-restore
ln -s /opt/vesta-agent/vesta-agent %{buildroot}%{_bindir}/vesta-agent
install -Dpm 644 VERSION %{buildroot}/opt/vesta-agent/VERSION
install -Dpm 644 vesta-agent.service %{buildroot}/usr/lib/systemd/system/vesta-agent.service
install -Dpm 644 vesta-native-staging.service %{buildroot}/usr/lib/systemd/system/vesta-native-staging.service
install -Dpm 644 agent.env.template %{buildroot}/etc/vesta/agent.env.example
install -Dpm 644 file-backups.json.example %{buildroot}/etc/vesta/file-backups.json.example
install -Dpm 644 native-staging.env.example %{buildroot}/etc/vesta/native-staging.env.example
install -d %{buildroot}%{_libexecdir}/vesta-native-staging
install -pm 644 native-staging/*.py %{buildroot}%{_libexecdir}/vesta-native-staging/
install -d -m 750 %{buildroot}/var/lib/vesta/backups %{buildroot}/var/lib/vesta/restores %{buildroot}/var/log/vesta
install -d -m 700 %{buildroot}/var/lib/vesta/certs
install -d %{buildroot}/etc/logrotate.d %{buildroot}/etc/polkit-1/rules.d %{buildroot}/usr/lib/firewalld/services

cat > %{buildroot}/etc/logrotate.d/vesta-agent <<'LOGROTATE'
/var/log/vesta/agent.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 vesta-agent vesta-agent
}
LOGROTATE

# Authenticate the service to the local QEMU socket.
cat > %{buildroot}/etc/polkit-1/rules.d/50-vesta-libvirt.rules <<'POLKIT'
polkit.addRule(function(action, subject) {
    if (action.id == "org.libvirt.unix.manage" &&
        subject.user == "vesta-agent") {
        return polkit.Result.YES;
    }
});
POLKIT

cat > %{buildroot}/usr/lib/firewalld/services/vesta-agent.xml <<'FIREWALL'
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>Vesta Agent</short>
  <description>Vesta KVM Backup Agent API and metrics</description>
  <port protocol="tcp" port="8090"/>
  <port protocol="tcp" port="9090"/>
</service>
FIREWALL

%pre
# Fresh hosts use the Vesta Agent account. Migrated services retain the
# original UID/GID and ACLs through a systemd drop-in.
getent group vesta-agent >/dev/null || groupadd -r vesta-agent || exit 1
getent passwd vesta-agent >/dev/null ||
    useradd -r -g vesta-agent -d /opt/vesta-agent -s /sbin/nologin -c 'Vesta Agent' vesta-agent || exit 1
for group in libvirt qemu; do
    if getent group "$group" >/dev/null; then
        usermod -aG "$group" vesta-agent || exit 1
    fi
done

restart_marker=/run/vesta-agent-rpm-restart
if [ "$1" -gt 1 ] && systemctl is-active --quiet vesta-agent.service 2>/dev/null; then
    touch "$restart_marker"
fi

# RPM runs the outgoing vnbui-agent scriptlets as a final erase. Those scriptlets
# stop the services and delete the default agent key. Save the launch state
# and key before the erase, after stopping the old agent's key writer.
if rpm -q --quiet vnbui-agent; then
    migration=/var/lib/vesta-agent-rpm-migration
    install -d -m 700 "$migration" || exit 1
    for service in vnbui-agent vnbui-native-staging; do
        if systemctl is-active --quiet "$service.service" 2>/dev/null; then
            touch "$migration/$service.active" || exit 1
        fi
        if systemctl is-enabled --quiet "$service.service" 2>/dev/null; then
            touch "$migration/$service.enabled" || exit 1
        fi
    done
    if [ -f "$migration/vnbui-agent.active" ] &&
        ! systemctl stop vnbui-agent.service; then
        exit 1
    fi
    if { [ -f /var/lib/vnbui/agent.key ] || [ -L /var/lib/vnbui/agent.key ]; } &&
        ! cp -aT -- /var/lib/vnbui/agent.key "$migration/agent.key"; then
        if [ -f "$migration/vnbui-agent.active" ]; then
            systemctl start vnbui-agent.service || :
        fi
        exit 1
    fi
fi
exit 0

%post
chown vesta-agent:vesta-agent /var/lib/vesta /var/lib/vesta/backups /var/lib/vesta/restores /var/lib/vesta/certs /var/log/vesta
if getent passwd qemu >/dev/null; then
    setfacl -m u:qemu:--x /var/lib/vesta /var/lib/vesta/backups
fi
systemctl daemon-reload >/dev/null 2>&1 || :

if [ "$1" -eq 1 ] && [ ! -d /var/lib/vesta-agent-rpm-migration ]; then
    cat <<'INSTALL'

Vesta Agent installed.
Configure /etc/vesta/agent.env using /etc/vesta/agent.env.example.
Set the Vesta HTTPS endpoint, scoped registration inputs and site TLS files.
Start and enable the agent with: systemctl enable --now vesta-agent
View diagnostics with: journalctl -u vesta-agent
Documentation: https://github.com/Insitu-IT/vesta

INSTALL
fi
exit 0

%preun
if [ "$1" -eq 0 ]; then
    systemctl disable --now vesta-agent.service vesta-native-staging.service >/dev/null 2>&1 || :
fi
exit 0

%postun
systemctl daemon-reload >/dev/null 2>&1 || :
if [ "$1" -eq 0 ]; then
    # Remove only the new default credential. Preserve storage, certificates,
    # and recovery state, including paths retained from a legacy install.
    rm -f /var/lib/vesta/agent.key
    logger -t vesta-agent "Package removed. Backups and recovery state preserved."
fi
exit 0

%posttrans
migration=/var/lib/vesta-agent-rpm-migration
restart_marker=/run/vesta-agent-rpm-restart
if [ -d "$migration" ]; then
    # Keep absolute state paths unchanged: existing journals and operations
    # can refer to them. An existing Vesta environment takes precedence.
    if { [ -f "$migration/agent.key" ] || [ -L "$migration/agent.key" ]; } &&
        [ ! -e /var/lib/vnbui/agent.key ] && [ ! -L /var/lib/vnbui/agent.key ]; then
        cp -aT -- "$migration/agent.key" /var/lib/vnbui/agent.key || exit 1
    fi
    install -d /etc/systemd/system/vesta-agent.service.d || exit 1
    cat > /etc/systemd/system/vesta-agent.service.d/10-legacy-account.conf <<'LEGACY_ACCOUNT'
[Service]
User=vnbui
Group=vnbui
LEGACY_ACCOUNT
    if getent passwd vnbui >/dev/null; then
        sed 's/"vesta-agent"/"vnbui"/' /etc/polkit-1/rules.d/50-vesta-libvirt.rules \
            > /etc/polkit-1/rules.d/50-vesta-libvirt-legacy.rules || exit 1
    fi
    if [ ! -e /etc/firewalld/services/vnbui-agent.xml ]; then
        install -D -m 644 /usr/lib/firewalld/services/vesta-agent.xml \
            /etc/firewalld/services/vnbui-agent.xml || exit 1
    fi
    if [ ! -e /etc/logrotate.d/vnbui-agent ]; then
        sed -e 's|/var/log/vesta/|/var/log/vnbui/|' -e 's/create 0640 vesta-agent vesta-agent/create 0640 vnbui vnbui/' \
            /etc/logrotate.d/vesta-agent > /etc/logrotate.d/vnbui-agent || exit 1
    fi
    if [ ! -e /etc/vesta/agent-legacy.env ]; then
        (umask 077; cat > /etc/vesta/agent-legacy.env <<'LEGACY'
KEY_FILE_PATH=/var/lib/vnbui/agent.key
BACKUP_STORAGE_PATH=/var/lib/vnbui/backups
NATIVE_RESTORE_ROOT=/var/lib/vnbui/restores
LEGACY
        ) || exit 1
    fi
    if [ -f /etc/vnbui/agent.env ] && [ ! -e /etc/vesta/agent.env ]; then
        install -m 600 /etc/vnbui/agent.env /etc/vesta/agent.env || exit 1
    fi
    if [ -f /etc/vnbui/native-staging.env ] && [ ! -e /etc/vesta/native-staging.env ]; then
        install -m 600 /etc/vnbui/native-staging.env /etc/vesta/native-staging.env || exit 1
        (umask 077; cat > /etc/vesta/native-staging-legacy.env <<'LEGACY_STAGING'
NATIVE_STAGING_MOUNT=/var/lib/vnbui-native-staging
NATIVE_STAGING_SOCKET=/run/vnbui-native-staging/broker.sock
LEGACY_STAGING
        ) || exit 1
        install -d /etc/systemd/system/vesta-native-staging.service.d || exit 1
        cat > /etc/systemd/system/vesta-native-staging.service.d/10-legacy-paths.conf <<'LEGACY_UNIT'
[Unit]
RequiresMountsFor=/var/lib/vnbui-native-staging

[Service]
Group=vnbui
RuntimeDirectory=vnbui-native-staging
ReadWritePaths=-/var/lib/vnbui-native-staging/attempts /run/vnbui-native-staging
LEGACY_UNIT
        test -s /etc/systemd/system/vesta-native-staging.service.d/10-legacy-paths.conf || exit 1
    fi
    for service in agent native-staging; do
        old_unit=vnbui-$service.service
        new_unit=vesta-$service.service
        if [ -d "/etc/systemd/system/$old_unit.d" ]; then
            install -d "/etc/systemd/system/$new_unit.d" || exit 1
            cp -an "/etc/systemd/system/$old_unit.d/." "/etc/systemd/system/$new_unit.d/" || exit 1
        fi
        systemctl disable "$old_unit" >/dev/null 2>&1 || :
        if [ -f "$migration/vnbui-$service.enabled" ]; then
            systemctl enable "$new_unit" || exit 1
        fi
    done
    systemctl daemon-reload >/dev/null 2>&1 || :
    # Start the optional broker first, and only when it was already running.
    if [ -f "$migration/vnbui-native-staging.active" ]; then
        systemctl start vesta-native-staging.service || exit 1
    fi
    if [ -f "$migration/vnbui-agent.active" ]; then
        systemctl start vesta-agent.service || exit 1
    fi
    rm -f "$migration/agent.key" "$migration/vnbui-agent.active" "$migration/vnbui-agent.enabled" \
        "$migration/vnbui-native-staging.active" "$migration/vnbui-native-staging.enabled"
    rmdir "$migration"
fi
if [ -f "$restart_marker" ]; then
    if ! systemctl restart vesta-agent.service; then
        logger -t vesta-agent "Agent restart after RPM upgrade failed"
        exit 1
    fi
    rm -f "$restart_marker"
fi
exit 0

%files
%license LICENSE
%license NOTICE
%license third-party-notices
%doc supply-contract.json
%doc README.md INSTALL_UNINSTALL_BEHAVIOR.md
%dir /opt/vesta-agent
/opt/vesta-agent/vesta-agent
/opt/vesta-agent/VERSION
%{_bindir}/vesta-agent
%{_bindir}/vesta-restore
%dir /etc/vesta
%config(noreplace) /etc/vesta/agent.env.example
%config(noreplace) /etc/vesta/file-backups.json.example
%config(noreplace) /etc/vesta/native-staging.env.example
/usr/lib/systemd/system/vesta-agent.service
/usr/lib/systemd/system/vesta-native-staging.service
%dir %{_libexecdir}/vesta-native-staging
%{_libexecdir}/vesta-native-staging/*.py
%config(noreplace) /etc/logrotate.d/vesta-agent
/etc/polkit-1/rules.d/50-vesta-libvirt.rules
/usr/lib/firewalld/services/vesta-agent.xml
%dir %attr(0750,vesta-agent,vesta-agent) /var/lib/vesta
%dir %attr(0750,vesta-agent,vesta-agent) /var/lib/vesta/backups
%dir %attr(0750,vesta-agent,vesta-agent) /var/lib/vesta/restores
%dir %attr(0700,vesta-agent,vesta-agent) /var/lib/vesta/certs
%dir %attr(0750,vesta-agent,vesta-agent) /var/log/vesta

%changelog
* Fri Nov 27 2026 Vesta Backup maintainers - 6.2.0-1
- Managed optional encrypted file backups and independent file recovery

* Fri Nov 27 2026 Vesta Backup maintainers - 6.1.1-1
- Align the agent package with the console readability patch.

* Wed Nov 25 2026 Vesta Backup maintainers - 6.1.0-1
- Initial Community release of the native libvirt agent and standalone disk recovery tool.
- Report backup readiness from the observed disks, checkpoints and available storage.

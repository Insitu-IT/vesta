%global debug_package %{nil}
%global _build_id_links none

Name:           vesta-agent-files
Version:        %{vesta_version}
Release:        1%{?dist}
Summary:        Vesta managed Linux file backup agent

License:        LicenseRef-Vesta-MMIT-1.1
URL:            https://github.com/Insitu-IT/vesta
Source0:        %{name}-%{version}.tar.gz

Conflicts:      vesta-agent
Conflicts:      vnbui-agent
Requires:       systemd
Requires(pre):  shadow-utils
Requires(pre):  systemd
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
Requires(posttrans): systemd

%description
The Vesta Agent backs up locally declared Linux directory sets to versioned
S3-compatible storage. Includes the standalone vesta-restore command.

%prep
%setup -q

%build
# The payload binaries are built before rpmbuild runs.

%install
install -Dpm 755 vesta-agent %{buildroot}/opt/vesta-agent/vesta-agent
install -Dpm 755 vesta-restore %{buildroot}%{_bindir}/vesta-restore
ln -s /opt/vesta-agent/vesta-agent %{buildroot}%{_bindir}/vesta-agent
install -Dpm 644 VERSION %{buildroot}/opt/vesta-agent/VERSION
install -Dpm 644 vesta-agent-files.service %{buildroot}/usr/lib/systemd/system/vesta-agent.service
install -Dpm 644 file-backups.env.example %{buildroot}/etc/vesta/agent.env.example
install -Dpm 644 file-backups.json.example %{buildroot}/etc/vesta/file-backups.json.example
install -d -m 750 %{buildroot}/var/lib/vesta
install -d -m 700 %{buildroot}/var/lib/vesta/certs %{buildroot}/var/lib/vesta/file-backups

%pre
getent group vesta-agent >/dev/null || groupadd -r vesta-agent || exit 1
getent passwd vesta-agent >/dev/null ||
    useradd -r -g vesta-agent -d /opt/vesta-agent -s /sbin/nologin -c 'Vesta Agent' vesta-agent || exit 1
if [ "$1" -gt 1 ] && systemctl is-active --quiet vesta-agent.service 2>/dev/null; then
    touch /run/vesta-agent-files-rpm-restart
fi
exit 0

%post
systemctl daemon-reload >/dev/null 2>&1 || :
if [ "$1" -eq 1 ]; then
    cat <<'INSTALL'
Vesta Linux file backup agent installed.
Configure /etc/vesta/agent.env and /etc/vesta/file-backups.json from the examples.
Start and enable the agent with systemctl enable --now vesta-agent.
INSTALL
fi
exit 0

%preun
if [ "$1" -eq 0 ]; then
    systemctl disable --now vesta-agent.service >/dev/null 2>&1 || :
fi
exit 0

%postun
systemctl daemon-reload >/dev/null 2>&1 || :
exit 0

%posttrans
if [ -f /run/vesta-agent-files-rpm-restart ]; then
    systemctl restart vesta-agent.service || exit 1
    rm -f /run/vesta-agent-files-rpm-restart
fi
exit 0

%files
%license LICENSE
%license NOTICE
%license third-party-notices
%doc supply-contract.json README.md
%dir /opt/vesta-agent
/opt/vesta-agent/vesta-agent
/opt/vesta-agent/VERSION
%{_bindir}/vesta-agent
%{_bindir}/vesta-restore
%dir /etc/vesta
%config(noreplace) /etc/vesta/agent.env.example
%config(noreplace) /etc/vesta/file-backups.json.example
/usr/lib/systemd/system/vesta-agent.service
%dir %attr(0750,vesta-agent,vesta-agent) /var/lib/vesta
%dir %attr(0700,vesta-agent,vesta-agent) /var/lib/vesta/certs
%dir %attr(0700,vesta-agent,vesta-agent) /var/lib/vesta/file-backups

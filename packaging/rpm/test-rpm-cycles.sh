#!/usr/bin/env bash
# Run on a disposable EL9 host with the supported libvirt repositories.
set -euo pipefail

if [[ ${EUID} != 0 || $# -lt 1 || $# -gt 2 ]]; then
    echo "Usage as root on a disposable EL9 host: $0 VESTA_RPM [LEGACY_RPM]" >&2
    exit 2
fi
vesta_rpm=$(realpath -e -- "$1")
test "$(rpm -qp --qf '%{NAME}' "$vesta_rpm")" = vesta-agent
for package in vesta-agent vnbui-agent; do
    if rpm -q --quiet "$package"; then
        echo "An agent package is already installed: $package" >&2
        exit 2
    fi
done
for path in /etc/vesta /etc/vnbui /var/lib/vesta /var/lib/vnbui; do
    if [[ -e $path ]]; then
        echo "Existing agent state found at $path" >&2
        exit 2
    fi
done

state_dir=/var/lib/vesta
service_user=vesta-agent
if [[ $# == 2 ]]; then
    legacy_rpm=$(realpath -e -- "$2")
    test "$(rpm -qp --qf '%{NAME}' "$legacy_rpm")" = vnbui-agent
    dnf install -y "$legacy_rpm"
    state_dir=/var/lib/vnbui
    service_user=vnbui
    legacy_uid=$(id -u "$service_user")
    printf 'ORCHESTRATOR_URL=https://example.org\n' > /etc/vnbui/agent.env
    chmod 600 /etc/vnbui/agent.env
    printf 'test enrollment state\n' > "$state_dir/agent.key"
    chmod 600 "$state_dir/agent.key"
    chown "$service_user:$service_user" "$state_dir/agent.key"
    printf 'test backup state\n' > "$state_dir/backups/recovery-test"
fi

dnf install -y "$vesta_rpm"
rpm -q --quiet vesta-agent
! rpm -q --quiet vnbui-agent
restore_help=$(vesta-restore -h 2>&1)
[[ $restore_help == 'Usage: vesta-restore '* ]]
test "$(vesta-agent --version)" = "$(rpm -q --qf '%{VERSION}' vesta-agent)"
agent_help=$(vesta-agent --help 2>&1)
[[ $agent_help == 'Usage of vesta-agent:'* ]]
test -f /usr/lib/systemd/system/vesta-agent.service
test -f /usr/lib/systemd/system/vesta-native-staging.service
test "$(stat -c '%U' "$state_dir/backups")" = "$service_user"
test "$(stat -c '%a' /var/lib/vesta/certs)" = 700

if [[ $# == 2 ]]; then
    test "$(id -u "$service_user")" = "$legacy_uid"
    test "$(stat -c '%a:%u' "$state_dir/agent.key")" = "600:$legacy_uid"
    test "$(cat "$state_dir/agent.key")" = 'test enrollment state'
    test "$(cat "$state_dir/backups/recovery-test")" = 'test backup state'
    test "$(stat -c '%a:%u' /etc/vesta/agent.env)" = 600:0
    cmp /etc/vnbui/agent.env /etc/vesta/agent.env
    test ! -e /usr/lib/systemd/system/vnbui-agent.service
    test ! -d /var/lib/vesta-agent-rpm-migration
else
    printf 'test backup state\n' > "$state_dir/backups/recovery-test"
    test ! -d /var/lib/vnbui
fi

dnf remove -y vesta-agent
! rpm -q --quiet vesta-agent
test ! -e /usr/lib/systemd/system/vesta-agent.service
test "$(cat "$state_dir/backups/recovery-test")" = 'test backup state'
echo 'Vesta Agent RPM lifecycle checks passed.'

#!/usr/bin/env bash
# Install a verified local Vesta Agent RPM on a supported EL9 host.
set -euo pipefail

if [[ $# != 1 || ! -f $1 || $1 != *.rpm ]]; then
    echo "Usage: $0 /path/to/vesta-agent-VERSION.x86_64.rpm" >&2
    exit 2
fi
rpm_file=$(realpath -- "$1")
if [[ $(rpm -qp --qf '%{NAME}' "$rpm_file") != vesta-agent ]]; then
    echo 'The supplied RPM is not the Vesta Agent package.' >&2
    exit 2
fi
exec dnf install "$rpm_file"

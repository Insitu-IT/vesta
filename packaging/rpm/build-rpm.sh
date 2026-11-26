#!/usr/bin/env bash
# Build the Vesta Agent and its native restore command for EL9.
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
spec="$repo_root/packaging/rpm/vesta-agent.spec"
version=$(awk '/^Version:/ { print $2 }' "$spec")

for tool in go rpmbuild; do
    if ! command -v "$tool" >/dev/null; then
        echo "Missing build tool: $tool" >&2
        exit 1
    fi
done

build_dir=$(mktemp -d)
trap 'rm -rf -- "$build_dir"' EXIT
package_dir="$build_dir/vesta-agent-$version"
mkdir -p "$package_dir/native-staging" "$build_dir"/{BUILD,RPMS,SOURCES,SPECS,SRPMS,tools}

cd "$repo_root/agent"
echo "Building Vesta Agent $version for $(uname -m)"
GOBIN="$build_dir/tools" go install github.com/google/go-licenses/v2@v2.0.1
CGO_ENABLED=1 go build -trimpath -buildvcs=false -tags libvirt -ldflags="-s -w -X main.version=$version" \
    -o "$package_dir/vesta-agent" ./cmd/vnbui-agent
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" \
    -o "$package_dir/vesta-restore" ./cmd/vnbui-restore
GO_LICENSES_BIN="$build_dir/tools/go-licenses" \
    sh scripts/collect-third-party-notices.sh "$package_dir/third-party-notices" libvirt "$(go env GOROOT)/LICENSE"

cp VERSION vesta-agent.service vesta-native-staging.service agent.env.template native-staging.env.example "$package_dir/"
cp internal/backup/libvirt_push.py internal/backup/native_write_fence.py \
    internal/backup/native_staging_broker.py internal/backup/native_fence_operator.py \
    internal/backup/native_staging_accounting.py "$package_dir/native-staging/"

cd "$repo_root"
cp packaging/rpm/README.customer.md "$package_dir/README.md"
cp packaging/rpm/INSTALL_UNINSTALL_BEHAVIOR.md "$package_dir/"
cp LICENSE NOTICE packaging/okd/supply-contract.json "$package_dir/"
tar -C "$build_dir" -czf "$build_dir/SOURCES/vesta-agent-$version.tar.gz" "vesta-agent-$version"

rpmbuild --define "_topdir $build_dir" -bb "$spec"
mapfile -t rpm_files < <(find "$build_dir/RPMS" -type f -name "vesta-agent-$version-*.rpm")
if [[ ${#rpm_files[@]} != 1 ]]; then
    echo "Expected exactly one built Vesta Agent RPM" >&2
    exit 1
fi
rpm_file=${rpm_files[0]}
output="$repo_root/packaging/rpm/output"
mkdir -p "$output"
cp "$rpm_file" "$output/"
bash "$repo_root/ci/record-native-supply.sh" "$rpm_file" \
    "$repo_root/packaging/okd/supply-contract.json" "$output/supply-evidence"
printf 'RPM package: %s/%s\n' "$output" "$(basename "$rpm_file")"

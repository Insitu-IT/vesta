#!/bin/sh
# Build-time only: collect upstream legal documents, never runtime source/tools.
set -eu
destination=${1:?usage: collect-third-party-notices.sh DESTINATION PROFILE GO_LICENSE_FILE}
profile=${2:?build profile required}
go_license=${3:?matching Go toolchain license file required}
test -s "$go_license"
go_version=$(go env GOVERSION)
test -n "$go_version"
original_flags=${GOFLAGS:-}
case "$profile" in
    default) export CGO_ENABLED=0 ;;
    kubevirt) export CGO_ENABLED=0; export GOFLAGS="$original_flags -tags=kubevirt" ;;
    libvirt) export CGO_ENABLED=1; export GOFLAGS="$original_flags -tags=libvirt" ;;
    *) echo 'Unknown notice collection profile' >&2; exit 1 ;;
esac
test ! -e "$destination"
collector=${GO_LICENSES_BIN:-go-licenses}
# Reciprocal/restricted/unknown terms need review; do not silently copy source
# or replace upstream terms with the product's first-party notice.
collect_target() {
    "$collector" check --ignore=vnbui/agent --disallowed_types=forbidden,restricted,reciprocal,unknown "$1"
    "$collector" save --ignore=vnbui/agent --save_path="$2" "$1"
}
collect_target ./cmd/vnbui-agent "$destination/agent"
# Restore ships in each profile as a separate untagged, CGO-disabled binary.
export CGO_ENABLED=0
export GOFLAGS="$original_flags"
collect_target ./cmd/vnbui-restore "$destination/restore"
mkdir -p "$destination/go"
cp "$go_license" "$destination/go/LICENSE"
if [ -f "$(dirname "$go_license")/PATENTS" ]; then
    cp "$(dirname "$go_license")/PATENTS" "$destination/go/PATENTS"
fi
printf 'Third-party legal notices for Vesta %s binaries.\nGo standard library: %s.\nDependency notices retain their upstream terms.\n' "$profile" "$go_version" > "$destination/NOTICE.txt"
test -s "$destination/go/LICENSE"
find "$destination" -type f -print | while IFS= read -r document; do
    legal_name=$(basename "$document" | tr '[:lower:]' '[:upper:]')
    case "$legal_name" in
        LICENSE*|LICENCE*|COPYING*|NOTICE*|COPYRIGHT*|PATENTS*|AUTHORS*) ;;
        *) echo 'Unexpected non-notice document in legal bundle' >&2; exit 1 ;;
    esac
    case "$legal_name" in
        *.GO|*.C|*.H|*.S|*.PY|*.JS|*.JSON) echo 'Source or tooling is not a legal notice payload' >&2; exit 1 ;;
    esac
done

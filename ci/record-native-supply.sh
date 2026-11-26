#!/usr/bin/env bash
# Read the exact candidate RPM; do not install it or execute its binaries.
set -euo pipefail
rpm_file=$1
policy_file=$2
evidence_dir=$3
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
command -v rpm2cpio >/dev/null
command -v cpio >/dev/null
mkdir -p "$evidence_dir"
test "$(rpm -qp --qf '%{FILEDIGESTALGO}' "$rpm_file")" = 8
rpm -qp --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' "$rpm_file" > "$evidence_dir/nevra.txt"
rpm -qpl "$rpm_file" > "$evidence_dir/contents.txt"
rpm -qpR "$rpm_file" > "$evidence_dir/requires.txt"
rpm -qp --dump "$rpm_file" > "$evidence_dir/files.txt"
sha256sum "$rpm_file" > "$evidence_dir/rpm.sha256"
sha256sum "$policy_file" > "$evidence_dir/policy.sha256"
expected_policy=$(awk '$1 ~ /\/supply-contract.json$/ { print $4 }' "$evidence_dir/files.txt")
actual_policy=$(sha256sum "$policy_file" | cut -d ' ' -f 1)
test -n "$expected_policy"
test "$actual_policy" = "$expected_policy"
# Prove these are the actual packaged bytes by matching RPM's SHA-256 file table.
for component in agent restore; do
    if [ "$component" = agent ]; then
        payload=/opt/vesta-agent/vesta-agent
    else
        payload=/usr/bin/vesta-restore
    fi
    binary=$temporary/$component
    # --to-stdout emits only the named member; no archive paths are unpacked.
    # Inspect packaged bytes after RPM brp-strip, not the loose Go build output.
    rpm2cpio "$rpm_file" | cpio -i --to-stdout --quiet ".$payload" > "$binary"
    expected=$(awk -v p="$payload" '$1 == p { print $4 }' "$evidence_dir/files.txt")
    actual=$(sha256sum "$binary" | cut -d ' ' -f 1)
    test -n "$expected"
    test "$actual" = "$expected"
    go version -m "$binary" > "$evidence_dir/$component.go-build.txt"
    readelf -d "$binary" > "$evidence_dir/$component.elf-dynamic.txt"
done
cat > "$evidence_dir/qualification.txt" <<'EOF'
Exact RPM payload/dependency/Go-build/ELF evidence only. This receipt does not
qualify host compatibility or certify complete notices/source fulfilment.
Review the matching source/patch/build inventories and applicable obligations.
EOF
(cd "$evidence_dir" && sha256sum nevra.txt contents.txt requires.txt files.txt rpm.sha256 policy.sha256 agent.go-build.txt restore.go-build.txt agent.elf-dynamic.txt restore.elf-dynamic.txt qualification.txt > SHA256SUMS)

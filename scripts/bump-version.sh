#!/bin/bash
# Bump version for Vesta components
# Usage: ./scripts/bump-version.sh <component> <new-version>
#   component: backend|frontend|agent|sync
#   version: X.Y.Z (semver format)
#
# Version convention:
#   PATCH bumps are independent per component (agent 5.0.16, backend 5.0.4 — normal)
#   MINOR/MAJOR: bump changed component, validate compatibility, then sync others
#   On a branch with .release-version, use sync for coordinated patches as well.

set -e

COMPONENT=$1
NEW_VERSION=$2

if [ -z "$COMPONENT" ] || [ -z "$NEW_VERSION" ]; then
    echo "Usage: $0 <component> <version>"
    echo "  component: backend|frontend|agent|sync"
    echo "  version: X.Y.Z (e.g., 2.5.0)"
    echo ""
    echo "Examples:"
    echo "  $0 backend 5.0.5                       # Patch bump backend only"
    echo "  $0 frontend 5.0.3                      # Patch bump frontend only"
    echo "  $0 agent 5.0.17                        # Patch bump agent only"
    echo "  $0 sync 5.1.0                          # Align all to same major.minor"
    echo "  CHANGELOG_MSG='Fix X' $0 agent 5.0.17  # Non-interactive (CI/scripts)"
    echo ""
    echo "NOTE: Use sync for coordinated releases on branches with .release-version."
    echo "      Other branches may bump individual components."
    echo "      Agent bumps auto-add RPM changelog entries."
    exit 1
fi

# Validate version format
if ! [[ $NEW_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version must be in format X.Y.Z (e.g., 2.4.0)"
    exit 1
fi

cd "$(dirname "$0")/.."

bump_backend() {
    echo "Bumping backend to $NEW_VERSION..."
    sed -i "s/__version__ = \".*\"/__version__ = \"$NEW_VERSION\"/" backend/version.py

    # Update build date
    BUILD_DATE=$(date +%Y-%m-%d)
    sed -i "s/__build_date__ = \".*\"/__build_date__ = \"$BUILD_DATE\"/" backend/version.py

    echo "  ✅ backend/version.py updated"
}

bump_frontend() {
    echo "Bumping frontend to $NEW_VERSION..."

    # Update package.json
    if command -v jq &> /dev/null; then
        jq ".version = \"$NEW_VERSION\"" frontend/package.json > frontend/package.json.tmp
        mv frontend/package.json.tmp frontend/package.json
        # npm's generated lock has two project versions. Change only those
        # fields, without resolution, registry access, or dependency rewrites.
        jq -e --arg version "$NEW_VERSION" '
            if (.packages[""] | type) != "object" then
                error("package-lock.json has no root package")
            else .version = $version | .packages[""].version = $version end
        ' frontend/package-lock.json > frontend/package-lock.json.tmp
        mv frontend/package-lock.json.tmp frontend/package-lock.json
        echo "  ✅ frontend/package.json and package-lock.json updated"
    else
        echo "  ⚠️  jq not installed, manual update needed:"
        echo "     Edit frontend/package.json and set version to $NEW_VERSION"
    fi
}

bump_agent() {
    echo "Bumping agent to $NEW_VERSION..."

    # Update VERSION file (Go agent)
    echo "$NEW_VERSION" > agent/VERSION
    echo "  ✅ agent/VERSION updated"

    # Update RPM spec version
    sed -i "s/^Version:        .*/Version:        $NEW_VERSION/" packaging/rpm/vesta-agent.spec
    sed -i "s/^Version:        .*/Version:        $NEW_VERSION/" packaging/rpm/vesta-agent-prebuilt.spec
    echo "  ✅ RPM spec Version updated"

    # Add RPM changelog entry
    CHANGELOG_DATE=$(date '+%a %b %d %Y')
    CHANGELOG_ENTRY="* ${CHANGELOG_DATE} Vesta Backup maintainers - ${NEW_VERSION}-1"

    # Prompt for changelog summary (or use default)
    if [ -n "$CHANGELOG_MSG" ]; then
        SUMMARY="$CHANGELOG_MSG"
    elif [ -t 0 ]; then
        echo ""
        echo "  Enter RPM changelog summary (one line, e.g., 'Fix backup progress tracking'):"
        read -r -p "  > " SUMMARY
    fi
    SUMMARY="${SUMMARY:-Version bump to ${NEW_VERSION}}"

    for spec in packaging/rpm/vesta-agent.spec packaging/rpm/vesta-agent-prebuilt.spec; do
        sed -i "/%changelog/a\\${CHANGELOG_ENTRY}\n- ${SUMMARY}\n" "$spec"
    done
    echo "  ✅ RPM changelog entries added"

    # Regenerate contracts
    if command -v go &> /dev/null; then
        (cd agent && make gen-contracts 2>/dev/null) && echo "  ✅ contracts/contracts.py regenerated" || echo "  ⚠️  gen-contracts failed, run manually: cd agent && make gen-contracts"
    fi
}

case $COMPONENT in
    backend)
        bump_backend
        ;;
    frontend)
        bump_frontend
        ;;
    agent)
        bump_agent
        ;;
    sync)
        echo "=== Syncing ALL components to $NEW_VERSION (major.minor alignment) ==="
        echo ""
        bump_backend
        bump_frontend
        bump_agent
        if [ -f .release-version ]; then
            printf '%s\n' "$NEW_VERSION" > .release-version
            echo "  ✅ .release-version updated"
        fi
        echo ""
        echo "✅ All components synced to $NEW_VERSION"
        ;;
    *)
        echo "Error: Unknown component '$COMPONENT'"
        echo "Must be: backend|frontend|agent|sync"
        exit 1
        ;;
esac

# Regenerate version lock (CI verifies this matches version files)
update_version_lock() {
    local be_ver fe_ver ag_ver lock_input lock_hash
    be_ver=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' backend/version.py)
    fe_ver=$(jq -r .version frontend/package.json 2>/dev/null || echo "unknown")
    ag_ver=$(cat agent/VERSION | tr -d '[:space:]')
    lock_input="backend=${be_ver} frontend=${fe_ver} agent=${ag_ver}"
    lock_hash=$(echo -n "$lock_input" | sha256sum | cut -d' ' -f1)
    cat > .versions.lock <<VLOCK
# Auto-generated by scripts/bump-version.sh — do not edit
# CI recomputes this hash from version files. Manual edits will fail.
${lock_input}
sha256=${lock_hash}
VLOCK
    echo "  ✅ .versions.lock updated"
}

update_version_lock

echo ""
echo "=== Version bump complete ==="
echo ""
echo "Changed files:"
git status --short | grep -E "(version\.py|package(-lock)?\.json|VERSION|\.spec|contracts\.py|versions\.lock)"
echo ""
echo "Review changes:"
echo "  git diff"
echo ""
echo "Commit:"
echo "  git add -A"
echo "  git commit -m 'Bump $COMPONENT version to $NEW_VERSION'"
echo ""

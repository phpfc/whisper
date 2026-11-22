#!/bin/bash
# Tags the version in Cargo.toml and pushes the tag. The Release workflow
# (.github/workflows/release.yml) then builds the binaries for macOS, Linux
# and Windows, attaches them to the GitHub release and updates the Homebrew tap.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
TAG="v$VERSION"

if [ "$(git rev-parse --abbrev-ref HEAD)" != "main" ]; then
    echo "Error: run this from main." >&2
    exit 1
fi
if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "Error: the working tree has uncommitted changes." >&2
    exit 1
fi
git fetch --quiet origin main
if [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]; then
    echo "Error: local main differs from origin/main; pull or push first." >&2
    exit 1
fi
if git rev-parse --quiet --verify "refs/tags/$TAG" >/dev/null; then
    echo "Error: tag $TAG already exists." >&2
    exit 1
fi

echo "Tagging whisper $VERSION as $TAG..."
git tag -a "$TAG" -m "whisper $VERSION"
git push origin "$TAG"
echo "Pushed $TAG. Follow the build at https://github.com/phpfc/whisper/actions"

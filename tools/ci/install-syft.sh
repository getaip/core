#!/bin/sh
set -eu

# Keep container SBOM generation reproducible on both GitHub-hosted runners and
# the self-hosted Gitea runner image. The release archive is immutable and its
# digest is verified before the binary is exposed to later workflow steps.
SYFT_VERSION=1.44.0
SYFT_ARCHIVE=syft_${SYFT_VERSION}_linux_amd64.tar.gz
SYFT_ARCHIVE_SHA256=0e91737aee2b5baf1d255b959630194a302335d848ff97bb07921eb6205b5f5a
SYFT_URL=https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/${SYFT_ARCHIVE}

case "$(uname -s):$(uname -m)" in
    Linux:x86_64 | Linux:amd64) ;;
    *)
        echo "pinned Syft installer supports only Linux x86_64 CI runners" >&2
        exit 1
        ;;
esac

if [ -w /usr/local/bin ]; then
    install_dir=/usr/local/bin
else
    install_dir=${HOME}/.local/bin
fi
mkdir -p "$install_dir"

archive=$(mktemp)
curl --fail --silent --show-error --location \
    --retry 3 --retry-all-errors \
    "$SYFT_URL" \
    --output "$archive"
printf '%s  %s\n' "$SYFT_ARCHIVE_SHA256" "$archive" | sha256sum --check --status
tar -xzf "$archive" -C "$install_dir" syft
chmod 0755 "$install_dir/syft"

if [ -n "${GITHUB_PATH:-}" ]; then
    printf '%s\n' "$install_dir" >> "$GITHUB_PATH"
fi

SYFT_CHECK_FOR_APP_UPDATE=false "$install_dir/syft" version

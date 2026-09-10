#!/bin/sh
# Register native_host.py with Chrome/Chromium for the given extension id.
#   ./install_native_host.sh <extension-id>
# Find the id on chrome://extensions after "Load unpacked" on ../extension.
set -eu

ext_id=${1:?usage: $0 <extension-id>}
host=$(cd "$(dirname "$0")" && pwd)/native_host.py
chmod +x "$host"

for dir in "$HOME/.config/google-chrome" "$HOME/.config/google-chrome-unstable" \
           "$HOME/.config/chromium" "$HOME/.config/BraveSoftware/Brave-Browser"; do
    [ -d "$dir" ] || continue
    mkdir -p "$dir/NativeMessagingHosts"
    cat > "$dir/NativeMessagingHosts/dev.focussched.host.json" <<EOF
{
  "name": "dev.focussched.host",
  "description": "focus-sched tab group bridge",
  "path": "$host",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://$ext_id/"]
}
EOF
    echo "installed for $dir"
done

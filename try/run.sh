#!/usr/bin/env bash
# Runs the application on a local Core, grants the Plugin what its Manifest declares, and opens the panel
# attached to the channel `panel`. Closing the panel stops everything.
#
# Usage: run.sh [--read-only]
#   --read-only   grants the questions, the streams and the occurrences, and no command: the panel shows
#                 everything, and every button is refused by the Core
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
manifest="$here/../plugin/com.yoke.network.yaml"

# The Plugin as the application carries it, built from ../plugin whenever it changed.
built="$here/../plugin/target/release/network"
cargo build --release --quiet --manifest-path "$here/../plugin/Cargo.toml"
if ! cmp -s "$built" "$here/components/plugins/network"; then
  cp "$built" "$here/components/plugins/network"
  cp "$manifest" "$here/manifests/"
fi
yoke-compose set units.network.digest "sha256:$(sha256sum "$here/components/plugins/network" | cut -d' ' -f1)" --dir "$here" > /dev/null
cargo build --release --quiet --manifest-path "$here/ui/Cargo.toml"

log="$(mktemp)"
yoke app run --from "$here" > "$log" 2>&1 &
run=$!
trap 'kill -INT "$run" 2>/dev/null; wait "$run" 2>/dev/null; rm -f "$log"' EXIT
until grep -q 'is observable' "$log"; do
  kill -0 "$run" 2>/dev/null || { cat "$log" >&2; exit 1; }
  sleep 0.3
done
instance="$(sed -n '1s/ runs .*//p' "$log")"
export YOKE_INSTANCE="$instance"

# A run's instance starts with nothing granted; a grant reaches the unit at its next admission.
for capability in $(sed -n 's/^  - name: //p' "$manifest"); do
  [[ "${1:-}" == --read-only && "$capability" == command.* ]] && continue
  yoke plugin grant com.yoke.network "$capability" > /dev/null
done
yoke unit restart network > /dev/null
echo "run.sh: $instance runs; the panel attaches to its channel panel"
"$here/ui/target/release/network-ui" --instance "$instance" --channel panel

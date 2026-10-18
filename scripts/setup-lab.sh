#!/usr/bin/env bash
# Clone the pinned OWASP Juice Shop release used by the isolated investigation
# lab (services/lab/), install its dependencies, and verify the checkout's
# commit matches what provisioner.py pins — refusing to proceed on a mismatch
# rather than silently running a different revision than the one documented
# in docs/INVESTIGATION.md.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

VERSION="v20.2.0"
PINNED_COMMIT="5658473cf8814459bf89000ce373b20ed0b4eb37"
DEST="$REDBEARS_ASSETS/lab/juice-shop-src"

if command -v sandbox-exec >/dev/null 2>&1; then
  echo "== sandbox-exec present (macOS Seatbelt) — lab isolation can run"
else
  echo "WARNING: sandbox-exec not found. The lab's isolation self-test will fail and"
  echo "         services/lab/provisioner.py will refuse to start any instance (LAB_ENABLED"
  echo "         is forced off at runtime, not bypassed) — see docs/INVESTIGATION.md §3."
fi

if [ ! -d "$DEST/.git" ]; then
  echo "== Cloning juice-shop/juice-shop @ $VERSION"
  git clone --depth 1 --branch "$VERSION" https://github.com/juice-shop/juice-shop.git "$DEST"
fi

HEAD="$(git -C "$DEST" rev-parse HEAD)"
if [ "$HEAD" != "$PINNED_COMMIT" ]; then
  echo "ERROR: $DEST HEAD is $HEAD, expected the pinned $PINNED_COMMIT ($VERSION)." >&2
  echo "       Remove $DEST and re-run this script, or update LAB_JUICE_SHOP_COMMIT deliberately." >&2
  exit 1
fi
if [ -n "$(git -C "$DEST" status --porcelain)" ]; then
  echo "ERROR: $DEST has local modifications — the lab refuses to provision from a dirty checkout." >&2
  exit 1
fi

echo "== Installing Juice Shop (this runs its own npm install + Angular build; a few minutes)"
(cd "$DEST" && npm install --no-audit --no-fund)

echo "Done. Lab checkout: $DEST @ $HEAD ($VERSION)"
echo "Run the isolation self-test any time with:"
echo "  cd $ROOT/oyster/backend && OYSTER_DATA_DIR=/tmp/rb/data OYSTER_LOGS_DIR=/tmp/rb/logs \\"
echo "    $VENV/bin/python -c 'from services.lab import selftest; import json; print(json.dumps(selftest.run(force=True), indent=1))'"

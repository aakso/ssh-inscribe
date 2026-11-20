#!/bin/sh
# govulncheck gate.
#
# govulncheck cannot silence findings (go.dev/issue/61211), so this wrapper
# accepts two known errors in the Go vulnerability database. GO-2026-6872
# (rate limiter bypass) and GO-2026-6875 (proxy forwards X-Real-IP) were fixed
# upstream in echo/v4 v4.16.3, which this module uses, but the database entry
# for the v4 module has no fixed version and therefore marks every v4 release
# as affected (golang/vulndb#6919, #6998). The exception applies only to
# reachable findings, only to these two IDs, and only while the module is on
# v4.16.3 or later; any other finding still fails the check. Remove this
# wrapper and run govulncheck directly once the database is corrected.
set -eu

binary=${1:?usage: vuln.sh <govulncheck-binary>}

report=$(mktemp)
trap 'rm -f "$report"' EXIT

status=0
"$binary" ./... >"$report" 2>&1 || status=$?
cat "$report"

if [ "$status" -eq 0 ]; then
	exit 0
fi
# 3 means reachable vulnerabilities were found; anything else is a scan error.
if [ "$status" -ne 3 ]; then
	exit "$status"
fi

# Only IDs in the "Symbol Results" section are reachable from our code.
ids=$(awk '
	/^=== Symbol Results ===$/ { symbol = 1; next }
	/^=== /                    { symbol = 0 }
	symbol && /^Vulnerability #[0-9]+: / {
		sub(/^Vulnerability #[0-9]+: /, "")
		print
	}
' "$report" | sort -u)

# An unparseable report must fail rather than pass silently.
if [ -z "$ids" ]; then
	exit 3
fi

# at_least HAVE WANT compares vX.Y.Z versions; a pre-release is older than
# the corresponding release.
at_least() {
	awk -v have="${1#v}" -v want="${2#v}" '
	function release(s) {
		sub(/[-+].*$/, "", s)
		return s
	}
	BEGIN {
		if (split(release(have), h, ".") < 3 || split(release(want), w, ".") < 3)
			exit 1
		for (i = 1; i <= 3; i++) {
			if (h[i] + 0 > w[i] + 0)
				exit 0
			if (h[i] + 0 < w[i] + 0)
				exit 1
		}
		exit(have ~ /-/ ? 1 : 0)
	}'
}

echo_version=$(go list -m -f '{{.Version}}' github.com/labstack/echo/v4)
if ! at_least "$echo_version" v4.16.3; then
	echo "govulncheck: echo/v4 $echo_version predates the v4.16.3 fix; not ignoring GO-2026-6872/GO-2026-6875" >&2
	exit 3
fi

unexpected=$(printf '%s\n' "$ids" | grep -v -x -F -e GO-2026-6872 -e GO-2026-6875 || true)
if [ -n "$unexpected" ]; then
	exit 3
fi

echo "govulncheck: ignoring GO-2026-6872 and GO-2026-6875: fixed in echo/v4 ${echo_version}," >&2
echo "but the database has no fixed v4 version (golang/vulndb#6919, #6998)" >&2

#!/bin/sh
# Enforces Invariant I1 by running Tier 0/1 tests inside a sealed network
# namespace. See ci/README.md and ci/tier01-tests.txt.
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
INVENTORY="$ROOT_DIR/ci/tier01-tests.txt"
cd "$ROOT_DIR"

echo "== no-brokr: verifying Invariant I1 (Tier 0/1 with no Brokr reachable) =="

if [ ! -f "$INVENTORY" ]; then
	echo "no-brokr: $INVENTORY does not exist; Invariant I1 has nothing to verify" >&2
	exit 1
fi

TMP_PAIRS=$(mktemp)
SEALED_SCRIPT=$(mktemp)
trap 'rm -f "$TMP_PAIRS" "$SEALED_SCRIPT"' EXIT

# --- Load the inventory, failing loudly the moment it has stopped
# counting: an empty file, a missing reason, or a test target that no
# longer exists must never be allowed to report success (DoD #2).
entry_count=0
while IFS='|' read -r raw_crate raw_target raw_reason; do
	crate=$(printf '%s' "${raw_crate:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
	case "$crate" in
		'' | '#'*) continue ;;
	esac
	target=$(printf '%s' "${raw_target:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
	reason=$(printf '%s' "${raw_reason:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

	if [ -z "$target" ]; then
		echo "no-brokr: $INVENTORY: entry '$crate' has no test target" >&2
		exit 1
	fi
	if [ -z "$reason" ]; then
		echo "no-brokr: $INVENTORY: entry '$crate|$target' has an empty reason" >&2
		exit 1
	fi

	test_file="crates/$crate/tests/$target.rs"
	if [ ! -f "$test_file" ]; then
		echo "no-brokr: $INVENTORY: $test_file does not exist" >&2
		exit 1
	fi

	entry_count=$((entry_count + 1))
	printf '%s|%s\n' "$crate" "$target" >> "$TMP_PAIRS"
done < "$INVENTORY"

if [ "$entry_count" -eq 0 ]; then
	echo "no-brokr: $INVENTORY names no test; Invariant I1 has nothing to verify" >&2
	exit 1
fi

echo "no-brokr: $entry_count Tier 0/1 test target(s) named in the inventory"

# --- Choose a sealing mechanism. Unprivileged user+net namespaces are
# tried first; the sudo fallback re-enters as the invoking user so files
# under target/ are not left root-owned (DoD #3).
ORIG_USER=$(id -un)
SAVED_PATH="$PATH"
HOST_NETNS=$(readlink /proc/self/ns/net) || true
if [ -z "$HOST_NETNS" ]; then
	echo "no-brokr: could not read this host's network namespace id from /proc/self/ns/net" >&2
	exit 1
fi

SEAL_METHOD=""
if unshare --user --net --map-root-user true 2> /dev/null; then
	SEAL_METHOD=userns
elif sudo -n true 2> /dev/null && sudo -n unshare --net true 2> /dev/null; then
	SEAL_METHOD=sudo
fi

if [ -z "$SEAL_METHOD" ]; then
	echo "no-brokr: no sealing mechanism available -- need either an unprivileged 'unshare --user --net --map-root-user' or passwordless 'sudo unshare --net'; refusing to run Tier 0/1 tests unsealed" >&2
	exit 1
fi

echo "no-brokr: sealing network egress to loopback via '$SEAL_METHOD'"

# --- The script that runs inside the namespace. mode=direct is already
# unprivileged (map-root-user); mode=drop is root under sudo, brings lo
# up, then re-execs itself as the invoking user (mode=body) -- lo can
# only come up once, from inside the same namespace the tests run in.
cat > "$SEALED_SCRIPT" << 'INNEREOF'
#!/bin/sh
set -eu

mode="$1"
host_netns="$2"
root_dir="$3"
pairs_file="$4"
orig_user="$5"
saved_path="$6"

if [ "$mode" = "drop" ]; then
	ip link set lo up
	exec runuser -u "$orig_user" -- env PATH="$saved_path" "$0" body "$host_netns" "$root_dir" "$pairs_file" "$orig_user" "$saved_path"
fi

if [ "$mode" = "direct" ]; then
	ip link set lo up
fi

# DoD #4: the seal must be checked from inside, never assumed. A missing
# id on either side must fail loudly rather than compare equal to "".
ns_netns=$(readlink /proc/self/ns/net) || true
if [ -z "$ns_netns" ] || [ -z "$host_netns" ]; then
	echo "no-brokr: could not read a network namespace id (host='$host_netns' ns='$ns_netns'); cannot confirm the seal" >&2
	exit 1
fi
if [ "$ns_netns" = "$host_netns" ]; then
	echo "no-brokr: still in the host's network namespace ($ns_netns); the seal was not applied" >&2
	exit 1
fi

# A namespace with only lo and no default route makes this fail on
# architecture, not on a firewall rule that could later be relaxed. Exit
# 6/7/28 are curl's "ran, could not reach" outcomes; anything else --
# including 127 for a missing curl, or 0 for a reply -- means the probe
# itself cannot be trusted to say the seal held, so it fails the job.
curl_status=0
curl --silent --max-time 2 --connect-timeout 2 -o /dev/null http://1.1.1.1/ || curl_status=$?
case "$curl_status" in
	0)
		echo "no-brokr: egress to a non-loopback address succeeded; the seal was not applied" >&2
		exit 1
		;;
	6 | 7 | 28) ;;
	*)
		echo "no-brokr: the egress probe exited $curl_status rather than a clean 'unreachable'; cannot confirm the seal" >&2
		exit 1
		;;
esac

cd "$root_dir"
set --
while IFS='|' read -r crate target; do
	[ -n "$crate" ] || continue
	echo "no-brokr: including crates/$crate/tests/$target.rs in the sealed run"
	set -- "$@" -p "$crate" --test "$target"
done < "$pairs_file"

# Matches the build step's package/test selection exactly -- a
# different selection changes cargo's on-disk fingerprint and forces a
# recompile even with every dependency already on disk. --offline turns
# a registry access, which the seal would otherwise just leave to time
# out against a namespace with no route, into an immediate failure.
cargo test --locked --offline "$@"
INNEREOF
chmod +x "$SEALED_SCRIPT"

if [ "$SEAL_METHOD" = "userns" ]; then
	unshare --user --net --map-root-user -- "$SEALED_SCRIPT" direct "$HOST_NETNS" "$ROOT_DIR" "$TMP_PAIRS" "$ORIG_USER" "$SAVED_PATH"
else
	sudo -n unshare --net -- "$SEALED_SCRIPT" drop "$HOST_NETNS" "$ROOT_DIR" "$TMP_PAIRS" "$ORIG_USER" "$SAVED_PATH"
fi

echo "== no-brokr: Invariant I1 verified successfully =="

#!/bin/sh
# Mechanizes invariant I4, rule B1, and Change Drills D5 and D9: tradr-core
# depends on nothing, only tradr-proto names prost, only tauri-plugin-tradr
# names tauri, and no implementation crate depends internally on anything
# but tradr-core and tradr-proto (tauri-plugin-tradr, the composition root,
# is exempt from that last rule).
set -u

CHECK_NAME=layer-deps
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
ALLOWLIST="$ROOT_DIR/ci/allowlist.txt"
cd "$ROOT_DIR" || exit 1

status=0

# --- Validate the allowlist file itself: an empty reason fails every check ---
if [ -f "$ALLOWLIST" ]; then
	while IFS='|' read -r a_check a_path a_reason; do
		trimmed_check=$(printf '%s' "$a_check" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
		case "$trimmed_check" in
			'' | '#'*) continue ;;
		esac
		trimmed_reason=$(printf '%s' "$a_reason" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
		if [ -z "$trimmed_reason" ]; then
			echo "ci/allowlist.txt: entry for '$trimmed_check' has an empty reason" >&2
			status=1
		fi
	done < "$ALLOWLIST"
fi

is_allowed() {
	# $1 = file path relative to repo root
	file="$1"
	[ -f "$ALLOWLIST" ] || return 1
	while IFS='|' read -r a_check a_path a_reason; do
		a_check=$(printf '%s' "$a_check" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
		case "$a_check" in
			'' | '#'*) continue ;;
		esac
		a_path=$(printf '%s' "$a_path" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
		if [ "$a_check" = "$CHECK_NAME" ] && [ "$a_path" = "$file" ]; then
			return 0
		fi
	done < "$ALLOWLIST"
	return 1
}

TMP_HITS=$(mktemp) || exit 1
trap 'rm -f "$TMP_HITS"' EXIT

manifests=$(find crates -maxdepth 2 -name 'Cargo.toml' \
	-not -path '*/target/*' \
	-not -path '*/.git/*' 2> /dev/null)

core_manifest="crates/tradr-core/Cargo.toml"

# --- Check 1: tradr-core declares no dependency at all ---
if [ -f "$core_manifest" ]; then
	awk '
	/^\[/ {
		in_deps = ($0 ~ /[Dd]ependencies/)
		next
	}
	in_deps {
		t = $0
		sub(/^[ \t]*/, "", t)
		if (t != "" && substr(t, 1, 1) != "#") print FNR
	}
	' "$core_manifest" | while IFS= read -r ln; do
		[ -n "$ln" ] || continue
		echo "$core_manifest:$ln: tradr-core must depend on nothing (invariant I4, rule B1)" >> "$TMP_HITS"
	done
fi

# --- Checks 2-4: per-crate scan over every other manifest ---
printf '%s\n' "$manifests" | while IFS= read -r m; do
	[ -n "$m" ] || continue
	[ "$m" != "$core_manifest" ] || continue

	# Check 2: prost confinement (Change Drill D5)
	if [ "$m" != "crates/tradr-proto/Cargo.toml" ]; then
		awk '/^[ \t]*"?prost(-[A-Za-z0-9_]+)?"?[ \t]*=/ { print FNR }' "$m" \
			| while IFS= read -r ln; do
				[ -n "$ln" ] || continue
				echo "$m:$ln: only tradr-proto may name prost (Change Drill D5)" >> "$TMP_HITS"
			done
	fi

	# Check 3: tauri confinement (Change Drill D9)
	if [ "$m" != "crates/tauri-plugin-tradr/Cargo.toml" ]; then
		awk '/^[ \t]*"?tauri(-[A-Za-z0-9_]+)?"?[ \t]*=/ { print FNR }' "$m" \
			| while IFS= read -r ln; do
				[ -n "$ln" ] || continue
				echo "$m:$ln: only tauri-plugin-tradr may name tauri (Change Drill D9)" >> "$TMP_HITS"
			done
	fi

	# Check 4: an implementation crate may depend internally only on
	# tradr-core and tradr-proto; tauri-plugin-tradr, the composition
	# root, is exempt and may wire up every implementation.
	if [ "$m" != "crates/tauri-plugin-tradr/Cargo.toml" ]; then
		awk '
		/[Pp]ath[ \t]*=/ {
			line = $0
			eq = index(line, "=")
			key = substr(line, 1, eq - 1)
			gsub(/^[ \t]*/, "", key)
			gsub(/[ \t]*$/, "", key)
			gsub(/"/, "", key)
			if (key != "tradr-core" && key != "tradr-proto") {
				print FNR ":" key
			}
		}
		' "$m" | while IFS=: read -r ln key; do
			[ -n "$ln" ] || continue
			echo "$m:$ln: an implementation crate may depend internally only on tradr-core and tradr-proto (found $key)" >> "$TMP_HITS"
		done
	fi
done

unsuppressed=""
if [ -s "$TMP_HITS" ]; then
	while IFS= read -r hit; do
		[ -n "$hit" ] || continue
		hit_file=${hit%%:*}
		if ! is_allowed "$hit_file"; then
			unsuppressed="$unsuppressed
$hit"
		fi
	done < "$TMP_HITS"
fi

if [ -n "$unsuppressed" ]; then
	printf '%s\n' "$unsuppressed" | sed '/^$/d'
	status=1
fi

exit $status

#!/bin/sh
# Mechanizes STATE.md's own contract (CLAUDE.md section 2-1's arrival step 5,
# and the "last_commit was fabricated for most of M0" audit): last_commit
# must name a real commit, work_items_landed must match the Work Item table,
# every DCR-N mentioned must reach a commit message, every repository path
# the file references must resolve, and the declared branch must match the
# branch actually checked out. Never writes STATE.md.
set -u

CHECK_NAME=state-sync
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
ALLOWLIST="$ROOT_DIR/ci/allowlist.txt"
STATE_FILE="$ROOT_DIR/STATE.md"
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

# $1 = the specific reference being suppressed -- a path token, not the
# file it appears in, since every reference in STATE.md lives in STATE.md.
is_allowed() {
	ref="$1"
	[ -f "$ALLOWLIST" ] || return 1
	while IFS='|' read -r a_check a_path a_reason; do
		a_check=$(printf '%s' "$a_check" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
		case "$a_check" in
			'' | '#'*) continue ;;
		esac
		a_path=$(printf '%s' "$a_path" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
		if [ "$a_check" = "$CHECK_NAME" ] && [ "$a_path" = "$ref" ]; then
			return 0
		fi
	done < "$ALLOWLIST"
	return 1
}

if [ ! -f "$STATE_FILE" ]; then
	echo "STATE.md: not found"
	exit 1
fi

# --- Check 1: last_commit names a commit that exists in this repository ---
last_commit_line=$(grep -m1 '^last_commit:' "$STATE_FILE")
if [ -z "$last_commit_line" ]; then
	echo "STATE.md: last_commit field is missing from the yaml block"
	status=1
else
	hash=$(printf '%s' "$last_commit_line" | sed -e 's/^last_commit:[[:space:]]*//' -e 's/[[:space:]]*$//')
	if [ -z "$hash" ] || ! git cat-file -e "${hash}^{commit}" 2> /dev/null; then
		echo "STATE.md: last_commit '$hash' does not name a commit in this repository"
		status=1
	fi
fi

# --- Check 2: work_items_landed matches the count of Work Item rows marked done ---
# WI-M0-010 and WI-M0-011 landed in a single commit and hold two rows, so
# rows are what is counted here, never commits.
declared_count=$(grep -m1 '^work_items_landed:' "$STATE_FILE" | sed -e 's/^work_items_landed:[[:space:]]*//' -e 's/[[:space:]]*$//')
actual_count=$(awk '/^\| WI-M0-/ && /\*\*done\*\*/ { n++ } END { print n + 0 }' "$STATE_FILE")
if [ -z "$declared_count" ]; then
	echo "STATE.md: work_items_landed field is missing from the yaml block"
	status=1
elif [ "$declared_count" != "$actual_count" ]; then
	echo "STATE.md: work_items_landed says $declared_count, but $actual_count Work Item rows are marked **done**"
	status=1
fi

# --- Check 3: every DCR-N mentioned in STATE.md appears in a commit message ---
dcrs=$(grep -oE 'DCR-[0-9]+' "$STATE_FILE" | sort -u)

dcr_hits=$(printf '%s\n' "$dcrs" | while IFS= read -r dcr; do
	[ -n "$dcr" ] || continue
	if ! git log --oneline --grep="$dcr" -F | grep -q .; then
		echo "STATE.md: $dcr is mentioned but appears in no commit message"
	fi
done)

if [ -n "$dcr_hits" ]; then
	printf '%s\n' "$dcr_hits"
	status=1
fi

# --- Check 4: every repository path STATE.md references resolves ---
# A path shows up two ways: a markdown link, "](docs/05-security.md)", and
# inline code, "`crates/tradr-core/src/lib.rs`". A reference counts only if
# its leading path component names a real top-level repository entry, which
# is what keeps a shell command like "grep -ril tauri crates/" or an
# unrelated identifier like "KeyStore" from being read as a path at all.
top_level_entries=$(ls -A "$ROOT_DIR")

is_top_level() {
	printf '%s\n' "$top_level_entries" | grep -Fxq "$1"
}

link_paths=$(grep -oE '\]\([^)]+\)' "$STATE_FILE" \
	| sed -e 's/^\](//' -e 's/)$//' -e 's/#.*$//' \
	| grep -vE '^https?://' \
	| sort -u)

link_hits=$(printf '%s\n' "$link_paths" | while IFS= read -r p; do
	[ -n "$p" ] || continue
	[ -e "$ROOT_DIR/$p" ] && continue
	is_allowed "$p" && continue
	echo "STATE.md: linked path '$p' does not exist"
done)

# Inline code spans, skipping fenced ```yaml blocks -- those hold config,
# not paths, and their ``` delimiters would otherwise mispair as code spans.
inline_spans=$(awk '
/^```/ { infence = !infence; next }
infence { next }
{
	n = split($0, parts, "`")
	for (i = 2; i <= n; i += 2) print parts[i]
}
' "$STATE_FILE" | sort -u)

path_candidates=$(printf '%s\n' "$inline_spans" | grep -E '^[A-Za-z0-9_.][A-Za-z0-9_./-]*$')

inline_hits=$(printf '%s\n' "$path_candidates" | while IFS= read -r tok; do
	[ -n "$tok" ] || continue
	first=${tok%%/*}
	is_top_level "$first" || continue
	[ -e "$ROOT_DIR/$tok" ] && continue
	is_allowed "$tok" && continue
	echo "STATE.md: referenced path '$tok' does not exist"
done)

path_hits=$(printf '%s\n%s\n' "$link_hits" "$inline_hits" | sed '/^$/d')

if [ -n "$path_hits" ]; then
	printf '%s\n' "$path_hits"
	status=1
fi

# --- Check 5: the current branch matches STATE.md's branch field ---
# A detached HEAD is a bisect or an old-commit checkout, not a commit landing
# on the wrong branch, so it is skipped rather than failed. A directory that
# is not a git repository at all is likewise skipped; git's own stderr is
# discarded so its absence does not leak into this script's output.
declared_branch=$(grep -m1 '^branch:' "$STATE_FILE" | sed -e 's/^branch:[[:space:]]*//' -e 's/[[:space:]]*$//')
if [ -z "$declared_branch" ]; then
	echo "STATE.md: branch field is missing from the yaml block"
	status=1
elif current_branch=$(git rev-parse --abbrev-ref HEAD 2> /dev/null); then
	if [ "$current_branch" != "HEAD" ] && [ "$current_branch" != "$declared_branch" ]; then
		echo "STATE.md: branch says '$declared_branch', but the current branch is '$current_branch'"
		status=1
	fi
fi

exit $status

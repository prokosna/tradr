#!/bin/sh
# Mechanizes STATE.md's own contract (CLAUDE.md section 2-1's arrival step 5,
# and the "last_commit was fabricated for most of M0" audit): last_commit
# must name a real commit, work_items_landed must match the Work Item table,
# every DCR-N already committed into STATE.md or RECORD.md appears in a
# commit message (one the working tree is only now adding is exempt -- it has
# no commit yet by construction), every DCR number is defined at most once,
# every repository path referenced resolves, a non-main declared branch
# matches the branch actually checked out, and the declared branch must never
# be "main" itself. Never writes STATE.md or RECORD.md.
set -u

CHECK_NAME=state-sync
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
ALLOWLIST="$ROOT_DIR/ci/allowlist.txt"
STATE_FILE="$ROOT_DIR/STATE.md"
RECORD_FILE="$ROOT_DIR/RECORD.md"
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
# Section state decides because a Review record row also begins with
# | WI-M... | and its cause cell is prose that may quote any marker.
# Splitting on | is unsound because cause cells may contain delimiters.
# Rows are counted rather than commits because multiple items may land
# in one commit, with wildcards matching every milestone.
declared_count=$(grep -m1 '^work_items_landed:' "$STATE_FILE" | sed -e 's/^work_items_landed:[[:space:]]*//' -e 's/[[:space:]]*$//')
actual_count=$({
	cat "$STATE_FILE"
	[ -f "$RECORD_FILE" ] && cat "$RECORD_FILE"
} | awk '
/^#+[ \t]+/ {
	heading = $0
	sub(/^#+[ \t]+/, "", heading)
	sub(/[ \t]+$/, "", heading)
}
heading == "Work Items" && /^\| WI-M[0-9]+-/ && /\*\*done\*\*/ {
	n++
}
END {
	print n + 0
}
')
if [ -z "$declared_count" ]; then
	echo "STATE.md: work_items_landed field is missing from the yaml block"
	status=1
elif [ "$declared_count" != "$actual_count" ]; then
	echo "STATE.md: work_items_landed says $declared_count, but $actual_count Work Item rows are marked **done**"
	status=1
fi

# --- Check 3: every DCR-N already committed appears in a commit message ---
# A DCR the working tree is only now adding is exempt -- CLAUDE.md section 7
# commits a DCR's row docs-first, so at the moment this gate runs on that
# commit the DCR is in the tree and in no commit yet, by construction.
# Committed against no working tree, its HEAD version, tells the two apart.
dcrs=$({
	grep -oE 'DCR-[0-9]+' "$STATE_FILE"
	[ -f "$RECORD_FILE" ] && grep -oE 'DCR-[0-9]+' "$RECORD_FILE"
} 2> /dev/null | sort -u)

if git cat-file -e HEAD 2> /dev/null; then
	committed_state=$(git show HEAD:STATE.md 2> /dev/null || true)
	committed_record=$(git show HEAD:RECORD.md 2> /dev/null || true)
	committed_dcrs=$(printf '%s\n%s\n' "$committed_state" "$committed_record" | grep -oE 'DCR-[0-9]+' | sort -u)

	dcr_hits=$(printf '%s\n' "$dcrs" | while IFS= read -r dcr; do
		[ -n "$dcr" ] || continue
		printf '%s\n' "$committed_dcrs" | grep -Fxq "$dcr" || continue
		if ! git log --oneline --grep="$dcr" -F | grep -q .; then
			if grep -qF "$dcr" "$STATE_FILE"; then
				echo "STATE.md: $dcr is mentioned but appears in no commit message"
			fi
			if [ -f "$RECORD_FILE" ] && grep -qF "$dcr" "$RECORD_FILE"; then
				echo "RECORD.md: $dcr is mentioned but appears in no commit message"
			fi
		fi
	done)

	if [ -n "$dcr_hits" ]; then
		printf '%s\n' "$dcr_hits"
		status=1
	fi
fi

# --- Check 4: every repository path referenced resolves ---
# A path shows up two ways: a markdown link, "](docs/05-security.md)", and
# inline code, "`crates/tradr-core/src/lib.rs`". A reference counts only if
# its leading path component names a real top-level repository entry, which
# is what keeps a shell command like "grep -ril tauri crates/" or an
# unrelated identifier like "KeyStore" from being read as a path at all.
top_level_entries=$(ls -A "$ROOT_DIR")

is_top_level() {
	printf '%s\n' "$top_level_entries" | grep -Fxq "$1"
}

check_file_paths() {
	target="$1"
	rel_label="$2"

	link_paths=$(grep -oE '\]\([^)]+\)' "$target" \
		| sed -e 's/^\](//' -e 's/)$//' -e 's/#.*$//' \
		| grep -vE '^https?://' \
		| sort -u)

	printf '%s\n' "$link_paths" | while IFS= read -r p; do
		[ -n "$p" ] || continue
		[ -e "$ROOT_DIR/$p" ] && continue
		is_allowed "$p" && continue
		echo "$rel_label: linked path '$p' does not exist"
	done

	inline_spans=$(awk '
	/^```/ { infence = !infence; next }
	infence { next }
	{
		n = split($0, parts, "`")
		for (i = 2; i <= n; i += 2) print parts[i]
	}
	' "$target" | sort -u)

	path_candidates=$(printf '%s\n' "$inline_spans" | grep -E '^[A-Za-z0-9_.][A-Za-z0-9_./-]*$')

	printf '%s\n' "$path_candidates" | while IFS= read -r tok; do
		[ -n "$tok" ] || continue
		first=${tok%%/*}
		is_top_level "$first" || continue
		[ -e "$ROOT_DIR/$tok" ] && continue
		is_allowed "$tok" && continue
		echo "$rel_label: referenced path '$tok' does not exist"
	done
}

path_hits=$({
	check_file_paths "$STATE_FILE" "STATE.md"
	[ -f "$RECORD_FILE" ] && check_file_paths "$RECORD_FILE" "RECORD.md"
} | sed '/^$/d')

if [ -n "$path_hits" ]; then
	printf '%s\n' "$path_hits"
	status=1
fi

# --- Check 5a: a non-main current branch matches STATE.md's branch field ---
# A detached HEAD is a bisect or an old-commit checkout, not a commit landing
# on the wrong branch, so it is skipped rather than failed. Arriving on main
# is a merge landing, not a commit on the wrong branch, so main is skipped
# too. A directory that is not a git repository at all is likewise skipped;
# git's own stderr is discarded so its absence does not leak into this output.
declared_branch=$(grep -m1 '^branch:' "$STATE_FILE" | sed -e 's/^branch:[[:space:]]*//' -e 's/[[:space:]]*$//')
if [ -z "$declared_branch" ]; then
	echo "STATE.md: branch field is missing from the yaml block"
	status=1
elif current_branch=$(git rev-parse --abbrev-ref HEAD 2> /dev/null); then
	if [ "$current_branch" != "HEAD" ] && [ "$current_branch" != "main" ] && [ "$current_branch" != "$declared_branch" ]; then
		echo "STATE.md: branch says '$declared_branch', but the current branch is '$current_branch'"
		status=1
	fi
fi

# --- Check 5b: the declared branch is never "main" itself ---
# STATE.md naming main as the work branch is the state in which the next
# Work Item commit lands directly on main, which section 5 forbids.
if [ "$declared_branch" = "main" ]; then
	echo "STATE.md: branch field is 'main' -- a Work Item must not be declared as building on main"
	status=1
fi

# --- Check 6: last_updated is not older than the newest commit ---
# ISO dates sort correctly as plain strings, so no date arithmetic is
# needed. This check runs one commit behind at pre-commit time: HEAD is
# the previous commit when the hook fires, so a same-day commit compares
# yesterday's last_updated to yesterday and passes -- CI catches it on
# the next push, where HEAD is the commit itself.
last_updated=$(grep -m1 '^last_updated:' "$STATE_FILE" | sed -e 's/^last_updated:[[:space:]]*//' -e 's/[[:space:]]*$//')
if [ -z "$last_updated" ]; then
	echo "STATE.md: last_updated field is missing from the yaml block"
	status=1
elif ! printf '%s' "$last_updated" | grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'; then
	echo "STATE.md: last_updated '$last_updated' is not a YYYY-MM-DD date"
	status=1
elif newest_commit_date=$(git log -1 --format=%cd --date=short 2> /dev/null) && [ -n "$newest_commit_date" ]; then
	if [ "$last_updated" != "$newest_commit_date" ]; then
		older=$(printf '%s\n%s\n' "$last_updated" "$newest_commit_date" | sort | sed -n '1p')
		if [ "$older" = "$last_updated" ]; then
			echo "STATE.md: last_updated is '$last_updated' but the newest commit is dated '$newest_commit_date' -- STATE.md was not updated to reflect it"
			status=1
		fi
	fi
fi

# --- Check 7: STATE.md is at most 98304 bytes (96 KiB) ---
# STATE.md reached 313 KB unmeasured; rules without instruments get broken.
# Move closed sections to RECORD.md to pass; never shorten prose. RECORD.md
# is append-only by design and intentionally has no ceiling.
STATE_MAX_BYTES=98304
state_size=$(wc -c < "$STATE_FILE" | tr -d '[:space:]')
if [ "$state_size" -gt "$STATE_MAX_BYTES" ]; then
	echo "STATE.md: size is $state_size bytes, exceeding the $STATE_MAX_BYTES byte limit -- move a closed section to RECORD.md, never shorten one"
	status=1
fi

# --- Check 8: a DCR number is defined exactly once across both files ---
# A duplicated DCR number makes Check 3's commit-message guarantee
# meaningless because a single commit message satisfies both rows, and
# allows conflicting design decisions to share an identifier silently.
dcr_duplicate_hits=$({
	awk '/^\| DCR-[0-9]+ \|/ { split($0, a, "|"); d=a[2]; gsub(/[[:space:]]/, "", d); print "STATE", d }' "$STATE_FILE"
	[ -f "$RECORD_FILE" ] && awk '/^\| DCR-[0-9]+ \|/ { split($0, a, "|"); d=a[2]; gsub(/[[:space:]]/, "", d); print "RECORD", d }' "$RECORD_FILE"
} | awk '
$1 == "STATE" {
	state_count[$2]++
	all_dcrs[$2] = 1
}
$1 == "RECORD" {
	record_count[$2]++
	all_dcrs[$2] = 1
}
END {
	for (d in all_dcrs) {
		s = state_count[d] + 0
		r = record_count[d] + 0
		if (s + r > 1) {
			if (s > 0 && r > 0) {
				print d ": defined in both STATE.md and RECORD.md"
			} else if (s > 1) {
				print "STATE.md: " d " is defined " s " times"
			} else if (r > 1) {
				print "RECORD.md: " d " is defined " r " times"
			}
		}
	}
}
' | sort)

if [ -n "$dcr_duplicate_hits" ]; then
	printf '%s\n' "$dcr_duplicate_hits"
	status=1
fi

exit $status

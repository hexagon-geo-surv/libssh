#!/bin/sh
set -eu

# header-standalone-check:
# Compile headers under include/libssh in isolation to detect hidden
# include-order dependencies.
# - Regressions (not allowlisted) fail the job.
# - Existing allowlisted failures are reported but do not fail the job.
# - Allowlisted headers that now pass are reported so the allowlist can shrink.

# Honor CC if set, otherwise pick an available compiler.
if [ -n "${CC:-}" ]; then
  : "${CC:?}"
elif command -v clang >/dev/null 2>&1; then
  CC=clang
else
  CC=cc
fi

# Ensure CC is a single command (avoid injection / args in CC).
case "$CC" in
  *[!A-Za-z0-9_./+-]*)
    echo "header-standalone: CC must be a single compiler command (no spaces/args): '$CC'"
    exit 1
    ;;
esac

if [ "$#" -gt 1 ]; then
  echo "Usage: $0 [build-dir]"
  exit 1
fi

BUILD_DIR=${1:-obj}

ALLOWLIST=".gitlab-ci/header-standalone-allowlist.txt"
TMP_DIR="$(mktemp -d)"
ALLOW_TMP="$TMP_DIR/allowlist.txt"
FAIL_NEW_TMP="$TMP_DIR/fail-new-details.txt"
FAIL_NEW_LIST_TMP="$TMP_DIR/fail-new-list.txt"
FAIL_OLD_TMP="$TMP_DIR/fail-old-details.txt"
FAIL_OLD_LIST_TMP="$TMP_DIR/fail-old-list.txt"
ALLOW_PASS_TMP="$TMP_DIR/allow-pass-list.txt"
HDRS_TMP="$TMP_DIR/headers.txt"
trap 'rm -rf "$TMP_DIR"' EXIT

section_start() {
  name=$1
  title=$2

  printf '\033[0Ksection_start:%s:%s[collapsed=true]\r\033[0K%s\n' \
    "$(date +%s)" "$name" "$title"
}

section_end() {
  name=$1

  printf '\033[0Ksection_end:%s:%s\r\033[0K\n' "$(date +%s)" "$name"
}

print_section() {
  file=$1
  name=$2
  title=$3

  [ -s "$file" ] || return 0

  echo
  section_start "$name" "$title"
  cat "$file"
  section_end "$name"
}

print_list_section() {
  file=$1
  name=$2
  title=$3
  prefix=$4

  [ -s "$file" ] || return 0

  sed "s/^/$prefix/" "$file" > "${file}.section"
  print_section "${file}.section" "$name" "$title"
  rm -f "${file}.section"
}

# Normalize allowlist (comments/blank lines removed, sorted unique).
if [ -f "$ALLOWLIST" ]; then
  sed '/^[[:space:]]*#/d;/^[[:space:]]*$/d' "$ALLOWLIST" | sort -u > "$ALLOW_TMP"
else
  : > "$ALLOW_TMP"
  echo "header-standalone: allowlist missing; any failure will fail the job."
fi

# Require configured build dir so generated headers exist.
if [ ! -f "$BUILD_DIR/config.h" ] || [ ! -f "$BUILD_DIR/include/libssh/libssh_version.h" ]; then
  echo "header-standalone: expected generated headers missing in '$BUILD_DIR'."
  echo "Run: mkdir -p $BUILD_DIR && cd $BUILD_DIR && cmake ... && cd .."
  exit 1
fi

# Discover public headers automatically under include/libssh.
find include/libssh -type f -name '*.h' | sort > "$HDRS_TMP"

# Keep include args as separate words (avoids SC2086).
set -- -I. -Iinclude "-I$BUILD_DIR" "-I$BUILD_DIR/include"

total=0
ok=0
fail_old=0
fail_new=0
allow_pass=0

while IFS= read -r h; do
  [ -n "$h" ] || continue
  total=$((total + 1))

  out=$(printf '#include "%s"\n' "$h" | "$CC" -x c -Werror "$@" -c -o /dev/null - 2>&1 || true)

  if [ -z "$out" ]; then
    ok=$((ok + 1))
    if grep -Fxq "$h" "$ALLOW_TMP"; then
      allow_pass=$((allow_pass + 1))
      echo "$h" >> "$ALLOW_PASS_TMP"
    fi
    continue
  fi

  if grep -Fxq "$h" "$ALLOW_TMP"; then
    fail_old=$((fail_old + 1))
    echo "$h" >> "$FAIL_OLD_LIST_TMP"
    {
      echo "---- FAIL (allowlisted) $h"
      echo "$out" | sed -n '1,12p'
      echo
    } >> "$FAIL_OLD_TMP"
  else
    fail_new=$((fail_new + 1))
    echo "$h" >> "$FAIL_NEW_LIST_TMP"
    {
      echo "---- FAIL (regression) $h"
      echo "$out" | sed -n '1,12p'
      echo
    } >> "$FAIL_NEW_TMP"
  fi
done < "$HDRS_TMP"

echo "Header standalone check summary:"
echo "  scope:            include/libssh"
echo "  allowlist:        $ALLOWLIST"
echo "  total:            $total"
echo "  passing:          $ok"
echo "  known failures:   $fail_old (already allowlisted)"
echo "  regressions:      $fail_new (not in allowlist)"
echo "  allowlist stale:  $allow_pass (allowlisted but now passing)"
echo "  result:           $( [ "$fail_new" -eq 0 ] && echo PASS || echo FAIL )"
echo

echo "Interpretation:"
echo "  PASS means there are no new standalone-compilation regressions in include/libssh."
echo "  Known failures stay visible so the allowlist can be reduced over time."
echo

if [ "$fail_old" -ne 0 ]; then
  sort -u "$FAIL_OLD_LIST_TMP" -o "$FAIL_OLD_LIST_TMP"
fi

print_list_section \
  "$FAIL_OLD_LIST_TMP" \
  "header_standalone_known_failure_headers" \
  "Known failures: allowlisted headers that still do not compile standalone" \
  "  - "

print_section \
  "$FAIL_OLD_TMP" \
  "header_standalone_known_failure_details" \
  "Known failures: compiler excerpts"

if [ "$allow_pass" -ne 0 ]; then
  sort -u "$ALLOW_PASS_TMP" -o "$ALLOW_PASS_TMP"
fi

print_list_section \
  "$ALLOW_PASS_TMP" \
  "header_standalone_allowlist_cleanup" \
  "Allowlist cleanup: headers that now compile standalone" \
  "  - "

if [ "$fail_new" -ne 0 ]; then
  sort -u "$FAIL_NEW_LIST_TMP" -o "$FAIL_NEW_LIST_TMP"
  echo "Header standalone regressions detected:"
  echo
  print_list_section \
    "$FAIL_NEW_LIST_TMP" \
    "header_standalone_regression_headers" \
    "Regressions: headers newly failing standalone compilation" \
    "  - "
  print_section \
    "$FAIL_NEW_TMP" \
    "header_standalone_regression_details" \
    "Regressions: compiler excerpts"
  exit 1
fi

echo "Header standalone check: OK (no regressions beyond the allowlist)."

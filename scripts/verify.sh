#!/usr/bin/env bash
# Verify gate for Shawns QA Assist.
#
# This repo ships hooks and scripts that other sessions execute. The failure
# that actually costs something is a syntax error reaching main, because the
# hook then dies inside somebody's session. Parsing every tracked script
# catches that and runs in about a second.
#
# It deliberately does not lint style or run behaviour tests: there is no test
# suite here, and a gate that failed on pre-existing style would block every PR
# on faults it did not introduce.
#
# Portable to bash 3.2 (macOS): no mapfile, no readarray.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

status=0

while IFS= read -r f; do
    [ -f "$f" ] || continue
    if ! bash -n "$f" 2>/dev/null; then
        echo "shell syntax error: $f" >&2
        bash -n "$f" 2>&1 | head -3 >&2
        status=1
    fi
done < <(git ls-files '*.sh')

while IFS= read -r f; do
    [ -f "$f" ] || continue
    if ! python3 -m py_compile "$f" 2>/dev/null; then
        echo "python syntax error: $f" >&2
        python3 -m py_compile "$f" 2>&1 | tail -3 >&2
        status=1
    fi
done < <(git ls-files '*.py')

find . -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null

if [ "$status" -eq 0 ]; then
    echo "verify: all tracked shell and python files parse"
fi
exit "$status"

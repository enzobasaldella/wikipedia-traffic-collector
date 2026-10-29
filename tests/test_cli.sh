#!/bin/sh
set -eu

python3 -m py_compile wikipedia_traffic_collector.py
python3 wikipedia_traffic_collector.py --help >/dev/null
python3 tests/test_logic.py

if python3 wikipedia_traffic_collector.py --read-min 5 --read-max 2 >/dev/null 2>&1; then
    printf '%s\n' "Invalid reading range was accepted." >&2
    exit 1
fi

if python3 wikipedia_traffic_collector.py --click-prob 2 >/dev/null 2>&1; then
    printf '%s\n' "Invalid probability was accepted." >&2
    exit 1
fi

printf '%s\n' "Wikipedia collector CLI tests passed."

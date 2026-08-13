#!/bin/sh
# Run the unit test suite with coverage.
#
# The project's Python has no pip and no pytest, so the toolchain lives in a
# project-local virtualenv (.venv/) that was bootstrapped without touching the system
# interpreter. Delete .venv/ and re-run setup to start over; nothing outside this
# directory is affected.
#
# Any argument is forwarded to pytest, so the usual selectors work:
#   ./run_tests.sh                          # everything, with a coverage summary
#   ./run_tests.sh -x                       # stop at the first failure
#   ./run_tests.sh tests/test_proc.py       # one file
#   ./run_tests.sh -k dedupe                # one topic
set -e

cd "$(dirname "$0")"

if [ ! -x .venv/bin/pytest ]; then
    echo "No .venv/bin/pytest found. Create the environment first:" >&2
    echo "  python3 -m venv --without-pip .venv" >&2
    echo "  curl -sS -o /tmp/get-pip.py https://bootstrap.pypa.io/get-pip.py" >&2
    echo "  .venv/bin/python /tmp/get-pip.py" >&2
    echo "  .venv/bin/pip install pytest pytest-cov" >&2
    exit 1
fi

exec .venv/bin/pytest "$@"

#!/usr/bin/env python3
"""Entry point: `python3 cli.py <subcommand> ...`.

Everything lives in the fuzz_lab package; this file only exists so the tool can be
run straight from a checkout without installing it or setting PYTHONPATH. Running
a script puts its directory at the front of sys.path, which is what makes the
import below resolve.
"""

from fuzz_lab.cli import main

if __name__ == "__main__":
    main()

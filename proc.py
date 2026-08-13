import os
import shlex
import subprocess

__all__ = ["run"]


def run(args, **kwargs):
    """subprocess.run(), echoing the command line to the console before running it.

    Always forces DEBUGINFOD_URLS="", overriding whatever env is passed in or
    inherited. Ubuntu sets it globally to a remote debuginfod server; when that
    server is unreachable (as on this machine), tools like llvm-symbolizer
    (spawned by ASan to print stack traces) hang for their full timeout
    (~90s) before falling back to the debug info already embedded in our -g
    builds, which is all this project ever needs.

    A caller-supplied env is copied before that override is applied, so passing a dict
    here never modifies it in place: callers can reuse or inspect their own env after
    the call and see exactly what they built.
    """
    print(f"$ {shlex.join(args)}")
    # Compared against None rather than tested for truthiness: env={} means "run with an
    # empty environment", which is not the same request as env=None ("inherit ours").
    env = kwargs.pop("env", None)
    env = dict(os.environ if env is None else env)
    env["DEBUGINFOD_URLS"] = ""
    return subprocess.run(args, env=env, **kwargs)

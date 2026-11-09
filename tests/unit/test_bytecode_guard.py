"""The package guard: a root process stops writing bytecode once brandsentinel is imported."""

import os
import subprocess
import sys

PROBE = """
import os, sys
os.geteuid = lambda: {euid}
sys.dont_write_bytecode = {before}
import brandsentinel
print(sys.dont_write_bytecode)
"""


def _probe(euid: int, before: bool) -> str:
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHONDONTWRITE")}
    done = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, "-c", PROBE.format(euid=euid, before=before)],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
        check=True,
    )
    return done.stdout.strip()


def test_effective_uid_zero_turns_bytecode_writes_off():
    assert _probe(0, False) == "True"


def test_a_non_root_process_keeps_its_setting():
    assert _probe(1000, False) == "False"
    assert _probe(1000, True) == "True"


def test_the_guard_runs_before_any_other_package_code():
    import ast
    from pathlib import Path

    import brandsentinel

    body = ast.parse(Path(brandsentinel.__file__).read_text()).body
    kinds = [type(node) for node in body[:4]]
    assert kinds == [ast.Expr, ast.Import, ast.Import, ast.If]
    assert [alias.name for node in body[1:3] for alias in node.names] == ["os", "sys"]

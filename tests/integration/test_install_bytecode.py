"""Bytecode-write prevention on a realistic installed layout (B2).

A real copy of the running interpreter, a real uv virtual environment and real
uv-generated launchers, under a temporary prefix. "Root" is `unshare -r`: effective UID 0
with write access over these test-owned files and no privilege on the host. That does not
prove behaviour on a root-owned tree, which stays a promotion check.
"""

import contextlib
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest

pytestmark = pytest.mark.installed_layout

REPO = Path(__file__).parents[2]
SCRIPTS = REPO / "scripts" / "service-account"
VERIFIER = SCRIPTS / "check_bytecode.py"
HARDEN = SCRIPTS / "harden-bytecode.sh"
VER = f"python{sys.version_info[0]}.{sys.version_info[1]}"
TAG = sys.implementation.cache_tag
UV = shutil.which("uv")
CLEAN_ENV = ["env", "-i", "PATH=/usr/bin:/bin", "HOME=/nonexistent"]


def _run(*argv, cwd=None, env=None, timeout=300) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - fixed argv
        [str(a) for a in argv],
        capture_output=True,
        text=True,
        cwd=cwd,
        env=env,
        timeout=timeout,
        check=False,
    )


def _wheel(directory: Path, name: str, modules: dict[str, str], script: str) -> Path:
    info = f"{name}-1.0.dist-info"
    path = directory / f"{name}-1.0-py3-none-any.whl"
    files = {
        **modules,
        f"{info}/METADATA": f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n",
        f"{info}/WHEEL": (
            "Wheel-Version: 1.0\nGenerator: t\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        f"{info}/entry_points.txt": f"[console_scripts]\n{script}\n",
    }
    files[f"{info}/RECORD"] = "".join(f"{k},,\n" for k in files) + f"{info}/RECORD,,\n"
    with zipfile.ZipFile(path, "w") as archive:
        for member, body in files.items():
            archive.writestr(member, body)
    return path


class Replica:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.bin = root / "venv" / "bin"
        self.python = self.bin / "python"
        self.site = root / "venv" / "lib" / VER / "site-packages"
        self.package = self.site / "brandsentinel"
        self.cli = self.bin / "brandsentinel"
        self.third = self.bin / "thirdtool"
        self.stdlib = next((root / "python").glob(f"*/lib/{VER}"))

    def state(self) -> dict[str, tuple[int, int, int]]:
        out = {}
        for path in self.root.rglob("*"):
            info = path.lstat()
            out[str(path.relative_to(self.root))] = (info.st_size, info.st_mtime_ns, info.st_mode)
        return out

    def as_root(self, *argv, cwd: Path) -> subprocess.CompletedProcess:
        return _run(*CLEAN_ENV, "unshare", "-r", *argv, cwd=cwd)

    def verify(self) -> subprocess.CompletedProcess:
        return _run(*CLEAN_ENV, self.python, "-I", "-B", "-S", VERIFIER, self.root)

    def harden(self) -> subprocess.CompletedProcess:
        return _run(*CLEAN_ENV, HARDEN, self.root)

    def clear_bytecode(self) -> None:
        for tree in (self.root / "venv", self.root / "python"):
            for cache in list(tree.rglob("__pycache__")):
                shutil.rmtree(cache)

    def pyc(self, source: Path) -> Path:
        return source.parent / "__pycache__" / f"{source.stem}.{TAG}.pyc"

    def source_count(self) -> int:
        return sum(1 for t in (self.site, self.stdlib) for p in t.rglob("*.py") if p.is_file())


def _build(root: Path, wheels: list[Path], cache: Path) -> Replica:
    source = Path(sys.base_prefix).resolve()
    (root / "python").mkdir(parents=True)
    home = root / "python" / source.name
    shutil.copytree(
        source, home, symlinks=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
    )
    env = {"PATH": "/usr/bin:/bin", "HOME": str(cache), "UV_CACHE_DIR": str(cache)}
    env |= {"UV_LINK_MODE": "copy", "UV_OFFLINE": "1"}
    made = _run(UV, "venv", "-q", "--python", home / "bin" / VER, root / "venv", env=env)
    assert made.returncode == 0, made.stderr
    installed = _run(
        UV, "pip", "install", "-q", "--python", root / "venv" / "bin" / "python", "--no-deps",
        *wheels, env=env,
    )  # fmt: skip
    assert installed.returncode == 0, installed.stderr
    return Replica(root)


def _unavailable(reason: str) -> None:
    """Skip, unless the run must prove this: a promotion gate cannot accept a skip."""
    if os.environ.get("REQUIRE_INSTALLED_LAYOUT"):
        pytest.fail(reason)
    pytest.skip(reason)


@pytest.fixture(scope="module")
def wheels(tmp_path_factory) -> list[Path]:
    if UV is None:
        _unavailable("uv is not installed: real launchers cannot be generated")
    if _run("unshare", "-r", "true").returncode != 0:
        _unavailable("unprivileged user namespaces are unavailable: cannot simulate root")
    directory = tmp_path_factory.mktemp("wheels")
    guard = (REPO / "src" / "brandsentinel" / "__init__.py").read_text()
    app = (
        "import colorsys, html, json\n"
        "from brandsentinel import marker\n"
        "def app():\n    print(marker.VALUE)\n"
    )
    return [
        _wheel(
            directory,
            "brandsentinel",
            {
                "brandsentinel/__init__.py": guard,
                "brandsentinel/cli.py": app,
                "brandsentinel/marker.py": 'VALUE = "original"\nprint(end="")\n',
            },
            "brandsentinel = brandsentinel.cli:app",
        ),
        _wheel(
            directory,
            "thirdapp",
            {"thirdapp/__init__.py": "import csv\ndef main():\n    print('third')\n"},
            "thirdtool = thirdapp:main",
        ),
    ]


@pytest.fixture(scope="module")
def unhardened(tmp_path_factory, wheels) -> Replica:
    return _build(tmp_path_factory.mktemp("plain") / "prefix", wheels, tmp_path_factory.mktemp("c"))


@pytest.fixture(scope="module")
def hardened(tmp_path_factory, wheels) -> Replica:
    replica = _build(
        tmp_path_factory.mktemp("hard") / "prefix", wheels, tmp_path_factory.mktemp("c")
    )
    done = replica.harden()
    assert done.returncode == 0, done.stdout + done.stderr
    return replica


@contextlib.contextmanager
def restoring(*paths: Path) -> Iterator[None]:
    saved = {p: p.read_bytes() for p in paths}
    try:
        yield
    finally:
        for path, body in saved.items():
            path.write_bytes(body)


def _unchanged(replica: Replica, tmp_path: Path, *argv) -> subprocess.CompletedProcess:
    before = replica.state()
    done = replica.as_root(*argv, cwd=tmp_path)
    assert replica.state() == before, done.stdout + done.stderr
    return done


# --- the control: the harness sees writes, and the verifier fails the old layout


def test_control_an_unhardened_replica_is_written_by_root_and_fails_verification(
    unhardened, tmp_path
):
    unhardened.clear_bytecode()
    failed = unhardened.verify()
    assert failed.returncode == 1, failed.stdout + failed.stderr
    assert "launcher_unhardened" in failed.stdout
    assert "missing" in failed.stdout

    before = unhardened.state()
    done = unhardened.as_root(unhardened.cli, cwd=tmp_path)
    assert done.returncode == 0, done.stderr
    written = [k for k in unhardened.state().keys() - before.keys() if k.endswith(".pyc")]
    assert written, "the harness must detect writes on an unhardened tree"
    assert any("_virtualenv" in k for k in written), "site startup runs before any guard"
    unhardened.clear_bytecode()


# --- the protected path


def test_a_hardened_replica_verifies_with_an_independent_count(hardened):
    done = hardened.verify()
    assert done.returncode == 0, done.stdout + done.stderr
    assert f"sources={hardened.source_count()} " in done.stdout
    assert "launchers=2 " in done.stdout


def test_real_uv_launchers_are_hardened_and_still_run(hardened, tmp_path):
    for launcher, expected in ((hardened.cli, "original"), (hardened.third, "third")):
        assert launcher.read_text().splitlines()[0] == f"#!{hardened.python} -B"
        assert _unchanged(hardened, tmp_path, launcher).stdout.strip() == expected


def test_root_writes_nothing_from_an_arbitrary_directory(hardened, tmp_path):
    (tmp_path / "json.py").write_text("raise SystemExit('cwd was imported')\n")
    done = _unchanged(hardened, tmp_path, hardened.cli)
    assert done.returncode == 0, done.stderr


def test_changed_mtimes_do_not_make_the_bytecode_stale(hardened, tmp_path):
    for path in [*hardened.site.rglob("*.py"), *hardened.stdlib.rglob("*.py")]:
        if path.is_file() and not path.is_symlink():
            os.utime(path, (1_700_000_000, 1_700_000_000))
    assert _unchanged(hardened, tmp_path, hardened.cli).returncode == 0
    assert hardened.verify().returncode == 0


# --- stale, missing and corrupt bytecode


def test_an_edited_source_runs_without_a_rewrite_and_is_reported(hardened, tmp_path):
    source = hardened.package / "marker.py"
    with restoring(source):
        source.write_text('VALUE = "edited"\n')
        assert _unchanged(hardened, tmp_path, hardened.cli).stdout.strip() == "edited"
        report = hardened.verify()
    assert report.returncode == 1
    assert "hash_mismatch" in report.stdout
    assert "marker" in report.stdout


def test_a_pyc_truncated_in_its_header_falls_back_to_source(hardened, tmp_path):
    pyc = hardened.pyc(hardened.package / "marker.py")
    with restoring(pyc):
        pyc.write_bytes(pyc.read_bytes()[:7])
        assert _unchanged(hardened, tmp_path, hardened.cli).stdout.strip() == "original"
        report = hardened.verify()
    assert report.returncode == 1
    assert "bad_header" in report.stdout


def test_a_pyc_truncated_in_its_body_fails_the_import_and_is_reported(hardened, tmp_path):
    pyc = hardened.pyc(hardened.package / "marker.py")
    with restoring(pyc):
        pyc.write_bytes(pyc.read_bytes()[:40])
        done = _unchanged(hardened, tmp_path, hardened.cli)
        report = hardened.verify()
    assert done.returncode != 0
    assert "EOFError" in done.stderr
    assert report.returncode == 1
    assert "bad_body" in report.stdout


def test_a_deleted_pyc_is_not_regenerated_through_a_launcher(hardened, tmp_path):
    pyc = hardened.pyc(hardened.package / "marker.py")
    with restoring(pyc):
        pyc.unlink()
        assert _unchanged(hardened, tmp_path, hardened.cli).stdout.strip() == "original"
        report = hardened.verify()
    assert report.returncode == 1
    assert "missing" in report.stdout


def test_a_submodule_run_with_a_missing_pyc_is_covered_by_the_guard(hardened, tmp_path):
    pyc = hardened.pyc(hardened.package / "cli.py")
    with restoring(pyc):
        pyc.unlink()
        assert (
            _unchanged(hardened, tmp_path, hardened.python, "-m", "brandsentinel.cli").returncode
            == 0
        )


# --- the recorded residuals


def test_bare_interpreter_on_an_intact_tree_writes_nothing(hardened, tmp_path):
    assert (
        _unchanged(hardened, tmp_path, hardened.python, "-c", "import json, asyncio").returncode
        == 0
    )


def test_residual_bare_interpreter_regenerates_a_deleted_pyc(hardened, tmp_path):
    source = hardened.stdlib / "colorsys.py"
    pyc = hardened.pyc(source)
    with restoring(pyc):
        pyc.unlink()
        done = hardened.as_root(hardened.python, "-c", "import colorsys", cwd=tmp_path)
        assert done.returncode == 0, done.stderr
        assert pyc.exists(), "documented residual: this path has only precompilation"


# --- interruption and failure


def test_a_killed_compile_is_caught_by_the_verifier(unhardened):
    unhardened.clear_bytecode()
    process = subprocess.Popen(  # noqa: S603 - fixed argv
        [
            str(unhardened.python), "-I", "-B", "-m", "compileall", "-q", "-f",
            "--invalidation-mode", "checked-hash", str(unhardened.stdlib),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )  # fmt: skip
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and process.poll() is None:
        if sum(1 for _ in unhardened.stdlib.rglob("*.pyc")) >= 20:
            break
        time.sleep(0.02)
    assert process.poll() is None, "the compile finished before it could be interrupted"
    process.send_signal(signal.SIGKILL)
    process.wait(timeout=30)
    report = unhardened.verify()
    assert report.returncode == 1
    assert "missing" in report.stdout
    assert not (unhardened.root / "INSTALL").exists()
    unhardened.clear_bytecode()


def test_a_source_that_does_not_compile_fails_hardening(hardened):
    bad = hardened.package / "broken.py"
    bad.write_text("def broken(:\n")
    try:
        assert hardened.harden().returncode != 0
    finally:
        bad.unlink()
    assert hardened.verify().returncode == 0


def test_hardening_is_idempotent(hardened):
    before = hardened.cli.read_bytes()
    assert hardened.harden().returncode == 0
    assert hardened.cli.read_bytes() == before
    assert hardened.verify().returncode == 0


def test_hardening_refuses_root(hardened, tmp_path):
    done = hardened.as_root(HARDEN, hardened.root, cwd=tmp_path)
    assert done.returncode != 0
    assert "not root" in done.stderr


def test_hardening_refuses_a_prefix_with_no_venv(tmp_path):
    assert _run(*CLEAN_ENV, HARDEN, tmp_path).returncode != 0


def test_a_read_only_tree_runs_as_non_root_without_writing(unhardened, tmp_path):
    unhardened.clear_bytecode()
    package = unhardened.package
    for path in [package, *package.rglob("*")]:
        path.chmod(path.stat().st_mode & 0o555)
    try:
        done = _run(*CLEAN_ENV, unhardened.cli, cwd=tmp_path)
        assert done.returncode == 0, done.stderr
        assert not list(package.rglob("*.pyc"))
    finally:
        for path in [package, *package.rglob("*")]:
            path.chmod(path.stat().st_mode | 0o200)
        unhardened.clear_bytecode()


def test_a_real_uv_trampoline_is_left_alone_and_fails_verification(tmp_path, wheels):
    # uv writes a #!/bin/sh trampoline when the interpreter path has a space.
    replica = _build(tmp_path / "with space" / "prefix", wheels, tmp_path / "cache")
    before = replica.cli.read_bytes()
    assert before.startswith(b"#!/bin/sh\n'''exec'")
    done = replica.harden()
    assert done.returncode == 0, done.stdout + done.stderr
    assert replica.cli.read_bytes() == before
    report = replica.verify()
    assert report.returncode == 1
    assert "launcher_unknown" in report.stdout


# --- wheel metadata


def test_package_metadata_survives_a_launcher_edit(hardened, tmp_path):
    record = hardened.site / "thirdapp-1.0.dist-info" / "RECORD"
    assert "bin/thirdtool" in record.read_text()
    done = _unchanged(
        hardened,
        tmp_path,
        hardened.python,
        "-c",
        "from importlib.metadata import version, entry_points as e;"
        "print(version('thirdapp'), [x.name for x in e(group='console_scripts')"
        " if x.name == 'thirdtool'])",
    )
    assert done.stdout.strip() == "1.0 ['thirdtool']", done.stderr


# --- wiring: these execute the real script blocks, with their dependencies stubbed


def _block(script: str, start: str, end: str | None) -> str:
    text = (SCRIPTS / script).read_text()
    begin = text.index(start)
    return text[begin : text.index(end, begin)] if end else text[begin:]


def _stub(path: Path, status: int = 0) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/bin/sh\nexit {status}\n")
    path.chmod(0o755)


def _install_tail(tmp_path: Path, verifier: int, harden: int = 0, smoke: int = 0):
    prefix = tmp_path / "prefix"
    stage = tmp_path / "stage"
    tools = prefix / "src" / "scripts" / "service-account"
    (stage / "dist").mkdir(parents=True)
    (stage / "dist" / "x.whl").write_text("wheel")
    _stub(tools / "harden-bytecode.sh", harden)
    (prefix / "src" / "uv.lock").write_text("lock")
    _stub(prefix / "venv" / "bin" / "brandsentinel", smoke)
    (prefix / "venv" / "bin" / "python").write_text(
        f'#!/bin/sh\ncase "$*" in *check_bytecode.py*) exit {verifier};; esac\necho 3.12.14\n'
    )
    (prefix / "venv" / "bin" / "python").chmod(0o755)
    body = _block("install.sh", 'echo "install: launchers and bytecode', "echo\ncat")
    harness = (
        "set -eu\n"
        f"PREFIX={prefix}\nSTAGE={stage}\nCOMMIT=abc\nDOCKERD_ROOTLESS_SHA256=def\n"
        'die() { echo "install: $*" >&2; exit 1; }\n'
    )
    return prefix, _run("sh", "-c", harness + body)


def test_a_verified_install_publishes_its_record_by_rename(tmp_path):
    prefix, done = _install_tail(tmp_path, verifier=0)
    assert done.returncode == 0, done.stderr
    assert "commit: abc" in (prefix / "INSTALL").read_text()
    assert not (prefix / ".INSTALL.tmp").exists()


@pytest.mark.parametrize(
    "failure",
    [{"verifier": 1}, {"verifier": 2}, {"verifier": 0, "harden": 1}, {"verifier": 0, "smoke": 1}],
    ids=["violations", "incomplete", "harden-failed", "smoke-failed"],
)
def test_a_failed_step_leaves_no_install_record(tmp_path, failure):
    prefix, done = _install_tail(tmp_path, **failure)
    assert done.returncode != 0
    assert not (prefix / "INSTALL").exists()
    assert not (prefix / ".INSTALL.tmp").exists()


def _validate_block(tmp_path: Path, verifier: int, record: bool):
    prefix = tmp_path / "prefix"
    out = tmp_path / "out"
    out.mkdir()
    python = prefix / "venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.write_text(f"#!/bin/sh\necho 'VIOLATION missing some/path.py'\nexit {verifier}\n")
    python.chmod(0o755)
    if record:
        (prefix / "INSTALL").write_text("commit: abc\n")
    helpers = _block("validate.sh", "pass() {", "not() {")
    body = _block("validate.sh", 'echo "== 0. installation', 'echo "== 1. account"')
    script = f'set -u\nPREFIX={prefix}\nOUT={out}\nFAILED=0\n{helpers}{body}echo "FAILED=$FAILED"\n'
    return out, _run("sh", "-c", script)


def test_validation_passes_a_complete_verified_install(tmp_path):
    _, done = _validate_block(tmp_path, verifier=0, record=True)
    assert "FAILED=0" in done.stdout, done.stdout + done.stderr


@pytest.mark.parametrize("status", [1, 2])
def test_validation_fails_on_a_verifier_failure_and_keeps_its_report(tmp_path, status):
    out, done = _validate_block(tmp_path, verifier=status, record=True)
    assert "FAILED=1" in done.stdout
    assert f"exit {status}" in done.stdout
    assert "some/path.py" in done.stdout
    assert "some/path.py" in (out / "bytecode.txt").read_text()


def test_validation_fails_without_an_install_record(tmp_path):
    _, done = _validate_block(tmp_path, verifier=0, record=False)
    assert "FAILED=1" in done.stdout


def test_the_verifier_runs_before_any_docker_step():
    text = (SCRIPTS / "validate.sh").read_text()
    assert text.index("bytecode.txt") < text.index("docker --host")
    assert not re.search(r'>\s*"\$PREFIX/INSTALL"', (SCRIPTS / "install.sh").read_text())

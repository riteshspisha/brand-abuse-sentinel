"""Only the pinned uv's built-in download list chooses the installation's Python (B7 U16, X21).

Left to the caller, `uv python install` (uv 0.12.20) takes its download list, each
archive's URL and checksum, from `UV_PYTHON_DOWNLOADS_JSON_URL`, `UV_CONFIG_FILE`, a
`uv.toml` (working directory, ancestor, user, system), `[tool.uv]` in an ancestor
`pyproject.toml` or `--config-file`, and checks the archive only against that list's own
checksum: integrity, not provenance. Offline, the archive need only sit in the Python
cache under the name the list implies.

Three kinds of test, kept apart:

- **Real uv, offline** (the uv on PATH, which must be the pinned uv 0.12.20; no network,
  no real CPython archive). The cache holds synthetic bytes under the genuine archive's
  cache name. Through install.sh's own Python step, every redirection must end in uv's
  hash-mismatch error naming the archive pin below, which only the built-in list yields,
  and leave no synthetic interpreter. Plain-uv controls run the original command and show
  each vector installing the synthetic interpreter.
- **Stub uv** (mocked: a shell script recording what it receives and laying out an
  installation). install-python.sh is copied with its uv pin replaced by the stub's hash.
  These test the pin, the same-path rule, the environment and the result check.
- **Static** checks of the scripts.

The positive install of the real archive is release evidence (U3, AU3-A), not a unit test.
"""

import hashlib
import io
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import tarfile
import tempfile
import threading
from pathlib import Path

import pytest

REPO = Path(__file__).parents[2]
INSTALL_SCRIPT = REPO / "scripts" / "service-account" / "install.sh"
PYTHON_SCRIPT = REPO / "scripts" / "service-account" / "install-python.sh"
WRAPPER = REPO / "scripts" / "uv-clean.sh"
PLAN = REPO / "docs" / "plans" / "2026-11-10-002-chore-b7-production-promotion-plan.md"

REQUEST = "cpython-3.12.14-linux-x86_64-gnu"
# The archive content pin ("Pinned inputs"): uv 0.12.20's built-in checksum for REQUEST.
ARCHIVE_SHA256 = "269b2c99e4db15b242bf01832f4fea1e8f1a664f273cff519393f296e9820b41"
ARCHIVE_NAME = "cpython-3.12.14-20260924-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"
GENUINE_URL = (
    "https://github.com/astral-sh/python-build-standalone/releases/download/20260924/"
    "cpython-3.12.14%2B20260924-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"
)
MARKER = b"SYNTHETIC-INTERPRETER"
FORBIDDEN = ("--python-downloads-json-url", "--mirror", "--pypy-mirror", "--config-file")
REDIRECTING = ("UV_PYTHON_DOWNLOADS_JSON_URL", "UV_CONFIG_FILE", "UV_PYTHON_INSTALL_MIRROR",
               "UV_PYPY_INSTALL_MIRROR", "UV_PYTHON_DOWNLOADS", "UV_PYTHON_INSTALL_DIR",
               "XDG_CONFIG_HOME", "XDG_CONFIG_DIRS", "PYTHONPATH", "KEEP_ME")  # fmt: skip


# Every child runs in its own session and is bounded: on timeout the whole process group is
# killed (a blocked grandchild would otherwise hold the output pipes open) and the test
# fails with a TIMEOUT message, so a hang is reported as a hang, never as a pass.
TIMEOUT = 120


def _run(argv, *, env, cwd) -> subprocess.CompletedProcess:
    with subprocess.Popen(  # noqa: S603 - fixed argv
        argv, env=env, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, start_new_session=True,
    ) as proc:  # fmt: skip
        try:
            out, err = proc.communicate(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate(timeout=10)
            pytest.fail(f"TIMEOUT after {TIMEOUT}s: {argv}", pytrace=False)
    return subprocess.CompletedProcess(argv, proc.returncode, out, err)


def _contains_marker(root: Path) -> bool:
    return any(
        MARKER in p.read_bytes() for p in root.rglob("*") if p.is_file() and not p.is_symlink()
    )


# -- real uv, offline ---------------------------------------------------------------------


def _uv() -> str:
    uv = shutil.which("uv")
    assert uv, "uv must be on PATH (the pinned uv 0.12.20)"
    return uv


def _synthetic_archive() -> bytes:
    """An install_only-shaped archive whose interpreter is a shell script."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data, mode in (
            ("python/bin/python3.12", b"#!/bin/sh\necho " + MARKER + b"\n", 0o755),
            ("python/lib/python3.12/README", MARKER, 0o644),
        ):
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), mode
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.fixture
def world(tmp_path):
    """The synthetic archive in a file URL and in the cache, under every name a list could
    point at, and the same bytes under the genuine archive's cache name."""
    data = _synthetic_archive()
    sha = hashlib.sha256(data).hexdigest()
    served = tmp_path / "served" / "synthetic.tar.gz"
    served.parent.mkdir()
    served.write_bytes(data)
    cache = tmp_path / "pycache"
    cache.mkdir()
    (cache / f"{sha[:9]}-synthetic.tar.gz").write_bytes(data)
    (cache / f"{sha[:9]}-{ARCHIVE_NAME}").write_bytes(data)
    (cache / f"{ARCHIVE_SHA256[:9]}-{ARCHIVE_NAME}").write_bytes(data)
    for patch, url in ((14, served.as_uri()), (99, served.as_uri()), (14, GENUINE_URL)):
        key = f"cpython-3.12.{patch}-linux-x86_64-gnu"
        entry = {"name": "cpython", "arch": {"family": "x86_64", "variant": None},
                 "os": "linux", "libc": "gnu", "major": 3, "minor": 12, "patch": patch,
                 "prerelease": "", "url": url, "sha256": sha, "variant": None,
                 "build": "20260924"}  # fmt: skip
        name = "genuine-url" if url == GENUINE_URL else f"p{patch}"
        (tmp_path / f"{name}.json").write_text(json.dumps({key: entry}))
    return tmp_path, cache


def _toml(directory: Path, name: str, list_path: Path, table: str = "") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    text = f'python-downloads-json-url = "{list_path}"\n'
    if table:
        text = '[project]\nname = "x"\nversion = "0"\n' + table + "\n" + text
    (directory / name).write_text(text)
    return directory


def _vector(name: str, root: Path) -> tuple[dict[str, str], Path]:
    """The environment additions and the working directory for one redirection."""
    lst = root / "p14.json"
    cwd = root / "cwd"
    cwd.mkdir(exist_ok=True)
    if name == "env-list":
        return {"UV_PYTHON_DOWNLOADS_JSON_URL": str(lst)}, cwd
    if name == "env-list-genuine-url":
        return {"UV_PYTHON_DOWNLOADS_JSON_URL": str(root / "genuine-url.json")}, cwd
    if name == "env-list-newer-release":
        return {"UV_PYTHON_DOWNLOADS_JSON_URL": str(root / "p99.json")}, cwd
    if name == "uv-config-file":
        return {"UV_CONFIG_FILE": str(_toml(root / "cf", "uv.toml", lst) / "uv.toml")}, cwd
    if name == "working-directory-uv-toml":
        return {}, _toml(root / "wd", "uv.toml", lst)
    if name == "ancestor-uv-toml":
        sub = _toml(root / "anc", "uv.toml", lst) / "sub"
        sub.mkdir()
        return {}, sub
    if name == "ancestor-pyproject":
        sub = _toml(root / "pp", "pyproject.toml", lst, "[tool.uv]") / "sub"
        sub.mkdir()
        return {}, sub
    if name == "user-uv-toml":
        return {"XDG_CONFIG_HOME": str(_toml(root / "xdg" / "uv", "uv.toml", lst).parent)}, cwd
    if name == "home-uv-toml":  # HOME reaches uv; only --no-config keeps this file out
        _toml(root / "home" / ".config" / "uv", "uv.toml", lst)
        return {}, cwd
    if name == "system-uv-toml":
        return {"XDG_CONFIG_DIRS": str(_toml(root / "sys" / "uv", "uv.toml", lst).parent)}, cwd
    raise AssertionError(name)


VECTORS = ["env-list", "env-list-genuine-url", "env-list-newer-release", "uv-config-file",
           "working-directory-uv-toml", "ancestor-uv-toml", "ancestor-pyproject",
           "user-uv-toml", "home-uv-toml", "system-uv-toml"]  # fmt: skip


def _env(root: Path, cache: Path, extra: dict[str, str]) -> dict[str, str]:
    return {"PATH": f"{Path(_uv()).parent}:/usr/bin:/bin", "HOME": str(root / "home"),
            "UV_OFFLINE": "1", "UV_PYTHON_CACHE_DIR": str(cache), **extra}  # fmt: skip


def _python_step_block() -> str:
    """install.sh's Python step, as committed: from its `echo` to the next blank line."""
    lines = INSTALL_SCRIPT.read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith('echo "install: python'))
    end = lines.index("", start)
    return "\n".join(lines[start:end]) + "\n"


def _install_sh_python_step(
    root: Path, env: dict, cwd: Path, src: Path = REPO
) -> tuple[Path, subprocess.CompletedProcess]:
    """install.sh's Python step, run as install.sh runs it; prints UV_RECORD on success."""
    prefix = root / "prefix"
    prefix.mkdir()
    (prefix / "src").symlink_to(src)  # install.sh runs the scripts of its own source tree
    harness = f'set -eu\nPREFIX={prefix}\ndie() {{ echo "install: $*" >&2; exit 1; }}\n'
    tail = 'echo "RECORD=$UV_RECORD"\n'
    return prefix, _run(["/bin/sh", "-c", harness + _python_step_block() + tail], env=env, cwd=cwd)


@pytest.mark.parametrize("vector", VECTORS)
def test_a_redirecting_list_installs_the_synthetic_interpreter_plainly(vector, world):
    """Control: the original command (`uv python install ... 3.12`) follows the list."""
    root, cache = world
    extra, cwd = _vector(vector, root)
    target = root / "plain"
    _run([_uv(), "python", "install", "--install-dir", str(target), "--no-bin", "3.12"],
         env=_env(root, cache, extra), cwd=cwd)  # fmt: skip
    assert _contains_marker(target), "the vector did not redirect the plain install"


@pytest.mark.parametrize("vector", VECTORS)
def test_install_sh_installs_only_from_the_built_in_list(vector, world):
    root, cache = world
    extra, cwd = _vector(vector, root)
    prefix, result = _install_sh_python_step(root, _env(root, cache, extra), cwd)
    assert result.returncode != 0
    assert not ((prefix / "python").exists() and _contains_marker(prefix / "python"))
    # Only the built-in list names this checksum for the request.
    assert "Hash mismatch" in result.stderr, result.stderr
    assert ARCHIVE_SHA256 in result.stderr, result.stderr


def test_install_sh_rejects_substituted_bytes_under_the_genuine_name(world):
    root, cache = world
    prefix, result = _install_sh_python_step(root, _env(root, cache, {}), root)
    assert result.returncode != 0
    assert "Hash mismatch" in result.stderr and ARCHIVE_SHA256 in result.stderr
    assert not ((prefix / "python").exists() and _contains_marker(prefix / "python"))


# -- uv-clean.sh's Python-install form (stub uv) ------------------------------------------


def _stub(path: Path, rec: Path, mode: str = "good", tag: str = "") -> Path:
    """A stub uv that records its own path, argv and environment, then lays out an
    installation according to `mode`."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"""#!/bin/sh
# {tag}
printf '%s\\n' "$0" > "{rec}.path"
printf '%s\\n' "$@" > "{rec}.argv"
env > "{rec}.env"
dir=
while [ $# -gt 0 ]; do case "$1" in --install-dir) dir=$2; shift ;; esac; shift; done
mk() {{
    mkdir -p "$dir/$1/bin"
    printf '#!/bin/sh\\necho %s\\n' "$2" > "$dir/$1/bin/python3.12"
    chmod +x "$dir/$1/bin/python3.12"
}}
case "{mode}" in
good) mk {REQUEST} 3.12.14; ln -s "$dir/{REQUEST}" "$dir/cpython-3.12-linux-x86_64-gnu"
      mkdir "$dir/.temp"; : > "$dir/.lock" ;;
wrong-version) mk {REQUEST} 3.12.13 ;;
two) mk {REQUEST} 3.12.14; mk cpython-3.12.13-linux-x86_64-gnu 3.12.13 ;;
none) mkdir -p "$dir" ;;
foreign-link) mk {REQUEST} 3.12.14; mkdir -p "$dir.other"
      ln -s "$dir.other" "$dir/cpython-3.12-linux-x86_64-gnu" ;;
extra) mk {REQUEST} 3.12.14; mkdir "$dir/pypy-3.12.14-linux-x86_64-gnu" ;;
linked-python) mk {REQUEST} 3.12.14; mv "$dir/{REQUEST}/bin/python3.12" "$dir.real"
      ln -s "$dir.real" "$dir/{REQUEST}/bin/python3.12" ;;
envdump) mk {REQUEST} 3.12.14; ln -s "$dir/{REQUEST}" "$dir/cpython-3.12-linux-x86_64-gnu"
      py="$dir/{REQUEST}/bin/python3.12"
      printf '#!/bin/sh\\nenv > "%s"\\necho 3.12.14\\n' "{rec}.pyenv" > "$py" ;;
fail) exit 3 ;;
record) ;;
esac
""")
    path.chmod(0o755)
    return path


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _scripts(root: Path, pin: str) -> Path:
    """A copy of the two scripts, install-python.sh pinned to `pin` (the stub's hash)."""
    tree = root / "repo" / "scripts"
    (tree / "service-account").mkdir(parents=True)
    shutil.copy(WRAPPER, tree / "uv-clean.sh")
    text = PYTHON_SCRIPT.read_text()
    assert re.search(r"^UV_SHA256=[0-9a-f]{64}", text, re.M)
    (tree / "service-account" / "install-python.sh").write_text(
        re.sub(r"^UV_SHA256=[0-9a-f]{64}", f"UV_SHA256={pin}", text, flags=re.M)
    )
    return tree / "service-account" / "install-python.sh"


@pytest.fixture
def mocked(tmp_path):
    """(script, stub, record, environment) for a stub uv first on PATH."""
    rec = tmp_path / "rec"
    stub = _stub(tmp_path / "bin" / "uv", rec)
    script = _scripts(tmp_path, _sha(stub))
    env = {"PATH": f"{stub.parent}:/usr/bin:/bin", "HOME": str(tmp_path / "home"),
           "UV_OFFLINE": "1", "UV_PYTHON_CACHE_DIR": str(tmp_path / "pycache"),
           "UV_LINK_MODE": "copy", **{name: "x" for name in REDIRECTING}}  # fmt: skip
    return script, stub, rec, env


def _python_step(script: Path, prefix: Path, env: dict, cwd: Path | None = None):
    return _run(["/bin/sh", str(script), str(prefix)], env=env, cwd=cwd or prefix.parent)


def _passed(rec: Path) -> dict[str, str]:
    lines = Path(f"{rec}.env").read_text().splitlines()
    return dict(line.split("=", 1) for line in lines if "=" in line)


def test_the_python_step_runs_the_checked_uv_with_the_exact_request(mocked, tmp_path):
    script, stub, rec, env = mocked
    prefix = tmp_path / "prefix"
    result = _python_step(script, prefix, env)
    assert result.returncode == 0, result.stderr
    assert result.stdout == f"{stub} {_sha(stub)}\n"
    assert Path(f"{rec}.path").read_text() == f"{stub}\n"
    assert Path(f"{rec}.argv").read_text().splitlines() == [
        "python", "install", "--no-config", "--install-dir", f"{prefix}/python", "--no-bin",
        REQUEST,
    ]  # fmt: skip
    passed = _passed(rec)
    assert {k: passed.get(k) for k in ("UV_OFFLINE", "UV_PYTHON_CACHE_DIR", "UV_LINK_MODE")} == {
        "UV_OFFLINE": "1", "UV_PYTHON_CACHE_DIR": str(tmp_path / "pycache"), "UV_LINK_MODE": "copy"
    }  # fmt: skip
    assert not set(passed) & set(REDIRECTING)


def test_the_uv_that_runs_is_the_resolved_file_that_was_checked(mocked, tmp_path):
    """uv on PATH is a symlink: the file hashed and the file executed are its target."""
    script, stub, rec, env = mocked
    link = tmp_path / "linkbin" / "uv"
    link.parent.mkdir()
    link.symlink_to(stub)
    env = {**env, "PATH": f"{link.parent}:/usr/bin:/bin"}
    result = _python_step(script, tmp_path / "prefix", env)
    assert result.returncode == 0, result.stderr
    assert Path(f"{rec}.path").read_text() == f"{stub}\n"
    assert result.stdout.split()[0] == str(stub)


def test_a_uv_with_another_hash_is_refused_before_it_runs(mocked, tmp_path):
    script, stub, rec, env = mocked
    other_rec = tmp_path / "other"
    other = _stub(tmp_path / "early" / "uv", other_rec, tag="not the pinned file")
    env = {**env, "PATH": f"{other.parent}:{stub.parent}:/usr/bin:/bin"}
    result = _python_step(script, tmp_path / "prefix", env)
    assert result.returncode != 0 and "not the pinned" in result.stderr
    assert not Path(f"{other_rec}.path").exists() and not Path(f"{rec}.path").exists()
    assert not (tmp_path / "prefix" / "python").exists()


@pytest.mark.parametrize("function", ["sha256sum", "readlink", "printf", "command"])
def test_an_exported_shell_function_cannot_pass_a_wrong_uv(function, mocked, tmp_path):
    """/bin/sh may be bash, which imports exported functions from the environment."""
    script, stub, _rec, env = mocked
    other_rec = tmp_path / "other"
    other = _stub(tmp_path / "early" / "uv", other_rec, tag="not the pinned file")
    body = {"sha256sum": f"echo {_sha(stub)}  x", "readlink": f"echo {stub}",
            "command": f"echo {other}"}.get(function, "return 0")  # fmt: skip
    env = {**env, "PATH": f"{other.parent}:{stub.parent}:/usr/bin:/bin",
           f"BASH_FUNC_{function}%%": f"() {{ {body}; }}"}  # fmt: skip
    result = _python_step(script, tmp_path / "prefix", env)
    assert result.returncode != 0 and result.stdout == ""
    assert f"uv ({other}) has sha256 {_sha(other)}, not the pinned" in result.stderr, result.stderr
    assert not Path(f"{other_rec}.path").exists()


def test_an_exported_test_function_cannot_pass_a_linked_interpreter(tmp_path):
    """`test` claiming nothing is a symlink would accept a linked python3.12, if the script
    called `test` by name rather than /usr/bin/test."""
    rec = tmp_path / "rec"
    stub = _stub(tmp_path / "bin" / "uv", rec, "linked-python")
    script = _scripts(tmp_path, _sha(stub))
    body = 'case "$1" in -L|-h) return 1 ;; esac; /usr/bin/test "$@"'
    env = {"PATH": f"{stub.parent}:/usr/bin:/bin", "HOME": str(tmp_path),
           "BASH_FUNC_test%%": f"() {{ {body}; }}"}  # fmt: skip
    result = _python_step(script, tmp_path / "prefix", env)
    assert result.returncode != 0 and result.stdout == ""
    assert "bin/python3.12 is not a regular file" in result.stderr, result.stderr


# The pinned uv (the stub) is reachable only through the relative or empty entry. A trailing
# empty entry is dropped by the shell's field splitting, so only the explicit empty-entry
# check refuses it; the loop over entries refuses the others.
PATH_REFUSALS = {
    "dot": (".:/usr/bin:/bin", "PATH entry '.' is not an absolute path"),
    "relative": ("bin:/usr/bin:/bin", "PATH entry 'bin' is not an absolute path"),
    "empty-leading": (":/usr/bin:/bin", "PATH has an empty entry"),
    "empty-middle": ("/usr/bin::/bin", "PATH has an empty entry"),
    "empty-trailing": ("/usr/bin:/bin:", "PATH has an empty entry"),
}


@pytest.mark.parametrize("case", list(PATH_REFUSALS))
def test_a_uv_found_through_a_relative_path_entry_is_refused(case, mocked, tmp_path):
    script, stub, rec, env = mocked
    path, message = PATH_REFUSALS[case]
    assert not any(Path(d, "uv").exists() for d in ("/usr/bin", "/bin"))
    cwd = tmp_path / "cwd"
    (cwd / "bin").mkdir(parents=True)
    shutil.copy(stub, cwd / "uv")
    shutil.copy(stub, cwd / "bin" / "uv")
    result = _python_step(script, tmp_path / "prefix", {**env, "PATH": path}, cwd=cwd)
    assert result.returncode != 0 and message in result.stderr, result.stderr
    assert not Path(f"{rec}.path").exists()


def _executable_fifo(path: Path) -> threading.Thread:
    """An executable FIFO, and a writer that feeds it one byte once a reader opens it, so
    that a reader (sha256sum, if the regular-file check were gone) never blocks."""
    os.mkfifo(path)
    path.chmod(0o755)

    def feed() -> None:
        try:
            with path.open("wb") as fifo:  # blocks until a reader opens the FIFO
                fifo.write(b"x")
        except BrokenPipeError:  # released by the test without a reader: expected
            pass

    writer = threading.Thread(target=feed, daemon=True)
    writer.start()
    return writer


@pytest.mark.parametrize("kind", ["fifo", "socket"])
def test_a_uv_that_is_not_a_regular_file_is_refused(kind, mocked, tmp_path):
    """An executable FIFO or socket named uv passes `command -v`; it must be refused as not
    a regular file before it is hashed, not by the hash comparison or a hashing error."""
    script, stub, rec, env = mocked
    short = Path(tempfile.mkdtemp(prefix="u16", dir="/tmp"))  # AF_UNIX: at most 107 bytes
    special = short / kind / "uv"
    special.parent.mkdir()
    writer, sock = None, None
    if kind == "fifo":
        writer = _executable_fifo(special)
    else:
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(str(special))
        special.chmod(0o755)
    try:
        env = {**env, "PATH": f"{special.parent}:{stub.parent}:/usr/bin:/bin"}
        result = _python_step(script, tmp_path / "prefix", env)
    finally:
        if writer is not None and writer.is_alive():  # release the writer if nobody read
            os.close(os.open(special, os.O_RDONLY | os.O_NONBLOCK))
            writer.join(5)
        if sock is not None:
            sock.close()
        shutil.rmtree(short)
    assert result.returncode != 0, result.stderr
    assert f"uv ({special}) is not a regular executable file" in result.stderr, result.stderr
    assert not Path(f"{rec}.path").exists()


# Each layout is refused by the check named here, not by an earlier or later one.
RESULT_REFUSALS = {
    "wrong-version": "bin/python3.12 reports 3.12.13, not 3.12.14",
    "two": "a second installation: ",
    "none": "no installation directory ",
    "foreign-link": "does not point to ",
    "extra": "unexpected entry ",
    "linked-python": "bin/python3.12 is not a regular file",
    "fail": f"installing {REQUEST} failed",
}


@pytest.mark.parametrize("mode", list(RESULT_REFUSALS))
def test_the_python_step_refuses_any_other_result(mode, tmp_path):
    rec = tmp_path / "rec"
    stub = _stub(tmp_path / "bin" / "uv", rec, mode)
    script = _scripts(tmp_path, _sha(stub))
    env = {"PATH": f"{stub.parent}:/usr/bin:/bin", "HOME": str(tmp_path)}
    result = _python_step(script, tmp_path / "prefix", env)
    assert result.returncode != 0 and result.stdout == ""
    refusals = [line for line in result.stderr.splitlines() if "install-python: refusing" in line]
    assert len(refusals) == 1 and RESULT_REFUSALS[mode] in refusals[0], result.stderr


def test_an_existing_python_directory_is_refused_before_uv_runs(mocked, tmp_path):
    """uv keeps an installation it finds in --install-dir, whatever its origin."""
    script, _stub_uv, rec, env = mocked
    prefix = tmp_path / "prefix"
    (prefix / "python" / REQUEST).mkdir(parents=True)
    result = _python_step(script, prefix, env)
    assert result.returncode != 0 and "already exists" in result.stderr
    assert not Path(f"{rec}.path").exists()


def test_a_relative_prefix_is_refused(mocked, tmp_path):
    script, _stub_uv, rec, env = mocked
    result = _run(["/bin/sh", str(script), "prefix"], env=env, cwd=tmp_path)
    assert result.returncode != 0 and not Path(f"{rec}.path").exists()


def _wrapped(*args: str, env: dict, cwd: Path) -> subprocess.CompletedProcess:
    return _run(["/bin/sh", str(WRAPPER), *args], env=env, cwd=cwd)


def test_the_wrapper_python_form_runs_the_given_path_not_the_path_lookup(tmp_path):
    rec, other_rec = tmp_path / "rec", tmp_path / "other"
    given = _stub(tmp_path / "given" / "uv", rec)
    other = _stub(tmp_path / "early" / "uv", other_rec)
    env = {"PATH": f"{other.parent}:/usr/bin:/bin", "UV_PYTHON_CACHE_DIR": "/cache"}
    args = ["python", "install", "--no-config", "--install-dir", str(tmp_path / "p"), REQUEST]
    result = _wrapped("--python-install", str(given), *args, env=env, cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert Path(f"{rec}.path").read_text() == f"{given}\n"
    assert not Path(f"{other_rec}.path").exists()
    assert _passed(rec)["UV_PYTHON_CACHE_DIR"] == "/cache"


@pytest.mark.parametrize(
    "args",
    [
        ["relative/uv", "python", "install", "--no-config"],
        ["{uv}", "pip", "install", "--no-config", "x"],
        ["{uv}", "python", "list", "--no-config"],
        ["{uv}", "python", "install", "x"],
        *[["{uv}", "python", "install", "--no-config", option, "v"] for option in FORBIDDEN],
        *[["{uv}", "python", "install", "--no-config", f"{option}=v"] for option in FORBIDDEN],
    ],
)
def test_the_wrapper_python_form_refuses_anything_else(args, tmp_path):
    rec = tmp_path / "rec"
    uv = _stub(tmp_path / "bin" / "uv", rec)
    argv = [a.replace("{uv}", str(uv)) for a in args]
    result = _wrapped("--python-install", *argv, env={"PATH": "/usr/bin:/bin"}, cwd=tmp_path)
    assert result.returncode != 0 and "uv-clean: refusing" in result.stderr
    assert not Path(f"{rec}.path").exists()


@pytest.mark.parametrize(
    "args",
    [
        ["venv", "--no-config", "v"],
        ["pip", "install", "--no-config", "x"],
        ["build", "--no-config", "--wheel"],
    ],
)
def test_other_callers_do_not_receive_the_python_cache(args, tmp_path):
    """The venv, install and build calls keep their environment and their PATH lookup."""
    rec = tmp_path / "rec"
    uv = _stub(tmp_path / "bin" / "uv", rec, "record")
    env = {"PATH": f"{uv.parent}:/usr/bin:/bin", "UV_PYTHON_CACHE_DIR": "/cache", "UV_OFFLINE": "1"}
    result = _wrapped(*args, env=env, cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "UV_PYTHON_CACHE_DIR" not in _passed(rec) and _passed(rec)["UV_OFFLINE"] == "1"
    assert Path(f"{rec}.path").read_text() == f"{uv}\n"
    assert Path(f"{rec}.argv").read_text().splitlines() == args


# -- static --------------------------------------------------------------------------------


def _code_lines(path: Path) -> list[str]:
    return [line for line in path.read_text().splitlines() if not line.lstrip().startswith("#")]


def test_install_sh_installs_python_only_through_install_python_sh():
    code = "\n".join(_code_lines(INSTALL_SCRIPT))
    assert code.count("scripts/service-account/install-python.sh") == 1
    assert "python install" not in code
    assert f"/python/{REQUEST}/bin/python3.12" in code


def test_install_python_sh_requests_exactly_the_pinned_interpreter():
    code = "\n".join(_code_lines(PYTHON_SCRIPT)).replace("\\\n", " ")
    (call,) = [line for line in code.splitlines() if "--python-install" in line]
    words = shlex.split(call.split(">&2")[0])
    assert words[words.index("--python-install") + 2 :] == [
        "python", "install", "--no-config", "--install-dir", "$TARGET", "--no-bin",
        "$PYTHON_REQUEST",
    ]  # fmt: skip
    assert f"PYTHON_REQUEST={REQUEST}" in code
    assert not any(option in code for option in FORBIDDEN)


def test_the_uv_pin_is_the_plans_pinned_input():
    pin = re.search(r"^UV_SHA256=([0-9a-f]{64})", PYTHON_SCRIPT.read_text(), re.M).group(1)
    assert pin in PLAN.read_text()
    assert ARCHIVE_SHA256 in PLAN.read_text()


# -- D1: a uv path containing '=' (review of 2026-11-18) ------------------------------------
# env(1) reads every argument containing '=' before the command as an assignment, so a
# pinned uv under ".../uv=0.12.20/uv" made `env -i ... "$UV" python install ...` run the
# first `python` on PATH, which then laid out an interpreter of its choosing.


def _impostor(path: Path, rec: Path) -> Path:
    """A `python` that records that it ran and lays out a fake 3.12.14 installation."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"""#!/bin/sh
printf '%s\\n' "$*" > "{rec}"
while [ $# -gt 0 ]; do case "$1" in --install-dir) dir=$2; shift ;; esac; shift; done
mkdir -p "$dir/{REQUEST}/bin"
printf '#!/bin/sh\\necho 3.12.14\\n' > "$dir/{REQUEST}/bin/python3.12"
chmod +x "$dir/{REQUEST}/bin/python3.12"
""")
    path.chmod(0o755)
    return path


def test_a_pinned_uv_under_a_path_with_an_equals_sign_is_refused(tmp_path):
    rec, impostor_rec = tmp_path / "rec", tmp_path / "impostor"
    stub = _stub(tmp_path / "tools" / "uv=0.12.20" / "uv", rec)
    script = _scripts(tmp_path, _sha(stub))
    impostor = _impostor(tmp_path / "early" / "python", impostor_rec)
    env = {"PATH": f"{stub.parent}:{impostor.parent}:/usr/bin:/bin", "HOME": str(tmp_path)}
    prefix = tmp_path / "prefix"
    result = _python_step(script, prefix, env)
    assert result.returncode != 0 and result.stdout == "", result.stdout
    assert f"uv's path {stub} contains '='" in result.stderr, result.stderr
    assert not impostor_rec.exists(), "a python found on PATH ran instead of uv"
    assert not Path(f"{rec}.path").exists() and not (prefix / "python").exists()


def test_the_wrapper_refuses_a_uv_path_with_an_equals_sign(tmp_path):
    rec, impostor_rec = tmp_path / "rec", tmp_path / "impostor"
    stub = _stub(tmp_path / "tools" / "uv=0.12.20" / "uv", rec, "record")
    impostor = _impostor(tmp_path / "early" / "python", impostor_rec)
    result = _wrapped("--python-install", str(stub), "python", "install", "--no-config",
                      "--install-dir", str(tmp_path / "t"), "--no-bin", REQUEST,
                      env={"PATH": f"{impostor.parent}:/usr/bin:/bin"}, cwd=tmp_path)  # fmt: skip
    assert result.returncode != 0 and "contains '='" in result.stderr, result.stderr
    assert not impostor_rec.exists() and not Path(f"{rec}.path").exists()


# -- D2: the environment install.sh starts the Python step with (review of 2026-11-18) -----
# /bin/sh is bash in POSIX mode: it imports SHELLOPTS, BASHOPTS, PS4 and exported functions,
# and the dynamic loader reads LD_* before any script line runs. With SHELLOPTS=xtrace,
# PS4 is expanded before each command, so an arithmetic PS4 rewrote the hash and the pin
# and an unpinned uv ran. install.sh therefore starts the step through /usr/bin/env -i
# with an allow-list and /bin/sh: none of these reach the shell that decides.

STEP_ENVIRONMENT = {"PATH", "HOME", "TMPDIR", "XDG_DATA_HOME", "XDG_CACHE_HOME", "UV_OFFLINE",
                    "UV_CACHE_DIR", "UV_LINK_MODE", "UV_PYTHON_CACHE_DIR", "HTTP_PROXY",
                    "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "http_proxy", "https_proxy",
                    "no_proxy", "all_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR"}  # fmt: skip
SHELL_ADDED = {"PWD", "OLDPWD", "SHLVL", "_"}  # exported by the shell that runs python3.12


@pytest.fixture
def step(tmp_path):
    """A source tree whose install-python.sh pins a stub uv, and an environment for it."""
    rec = tmp_path / "rec"
    stub = _stub(tmp_path / "bin" / "uv", rec, "envdump")
    _scripts(tmp_path, _sha(stub))
    other_rec = tmp_path / "other"
    other = _stub(tmp_path / "early" / "uv", other_rec, tag="not the pinned file")
    env = {"PATH": f"{stub.parent}:/usr/bin:/bin", "HOME": str(tmp_path / "home"),
           "UV_OFFLINE": "1", "UV_PYTHON_CACHE_DIR": str(tmp_path / "pycache")}  # fmt: skip
    return tmp_path / "repo", stub, rec, other, other_rec, env


def test_install_sh_starts_the_step_without_shellopts_or_ps4(step, tmp_path):
    src, _stub_uv, rec, other, other_rec, env = step
    env = {**env, "PATH": f"{other.parent}:{env['PATH']}", "SHELLOPTS": "xtrace",
           "PS4": "$((SUM=1,UV_SHA256=1))"}  # fmt: skip
    prefix, result = _install_sh_python_step(tmp_path, env, tmp_path, src)
    assert result.returncode != 0 and "RECORD=" not in result.stdout, result.stdout
    assert f"uv ({other}) has sha256 {_sha(other)}, not the pinned" in result.stderr
    assert not Path(f"{other_rec}.path").exists(), "an unpinned uv ran"
    assert not Path(f"{rec}.path").exists() and not (prefix / "python").exists()


def test_exported_functions_cannot_skip_the_step_or_forge_its_record(step, tmp_path):
    """`sh` and `printf` replaced by exported functions: the step must still run, and the
    record must be the one the real step printed."""
    src, stub, rec, _other, _other_rec, env = step
    env = {**env, "BASH_FUNC_sh%%": '() { echo "/forged/uv 0"; }',
           "BASH_FUNC_printf%%": '() { echo "/forged/uv 0"; }'}  # fmt: skip
    _prefix, result = _install_sh_python_step(tmp_path, env, tmp_path, src)
    assert result.returncode == 0, result.stderr
    assert f"RECORD={stub} {_sha(stub)}\n" in result.stdout, result.stdout
    assert Path(f"{rec}.path").read_text() == f"{stub}\n"


def test_install_sh_starts_the_step_with_only_the_allowed_environment(step, tmp_path):
    src, stub, rec, _other, _other_rec, env = step
    hostile = {"SHELLOPTS": "xtrace", "PS4": "+ ", "BASHOPTS": "dotglob:nocasematch",
               "LD_PRELOAD": "/nonexistent/u16.so", "LD_LIBRARY_PATH": "/nonexistent",
               "BASH_FUNC_u16%%": "() { :; }", "ENV": "/nonexistent", "PYTHONPATH": "/x",
               "UV_PYTHON_DOWNLOADS_JSON_URL": "/x", "KEEP_ME": "x"}  # fmt: skip
    _prefix, result = _install_sh_python_step(tmp_path, {**env, **hostile}, tmp_path, src)
    assert result.returncode == 0, result.stderr
    assert f"RECORD={stub} {_sha(stub)}\n" in result.stdout, result.stdout
    seen = dict(
        line.split("=", 1) for line in Path(f"{rec}.pyenv").read_text().splitlines() if "=" in line
    )
    assert set(seen) - SHELL_ADDED <= STEP_ENVIRONMENT, sorted(set(seen) - SHELL_ADDED)
    assert seen["UV_PYTHON_CACHE_DIR"] == env["UV_PYTHON_CACHE_DIR"]
    passed = _passed(rec)  # what reached uv
    assert passed["UV_PYTHON_CACHE_DIR"] == env["UV_PYTHON_CACHE_DIR"]
    assert passed["UV_OFFLINE"] == "1", "an offline install must stay offline"


def _allowed_names(text: str) -> set[str]:
    return set(re.findall(r'\$\{(\w+)\+"\1=\$\1"\}', text))


def test_the_step_gets_exactly_the_wrappers_allow_list():
    """install.sh's copy of the allow-list must not drift from uv-clean.sh's: dropping
    UV_OFFLINE would let an offline install go online."""
    step = _python_step_block()
    assert "/usr/bin/env -i" in step and "/bin/sh " in step
    assert _allowed_names(step) == _allowed_names(WRAPPER.read_text()) == STEP_ENVIRONMENT


def test_a_missing_uv_is_refused(mocked, tmp_path):
    script, _stub_uv, rec, env = mocked
    result = _python_step(script, tmp_path / "prefix", {**env, "PATH": "/usr/bin:/bin"})
    assert result.returncode != 0 and result.stdout == ""
    assert "uv not found on PATH" in result.stderr and not Path(f"{rec}.path").exists()


def test_the_scripts_run_tools_only_by_absolute_path():
    """Decisions must not depend on a command an exported function can replace."""
    bare = re.compile(r"(^|[\s;&|(!`$])(test|\[|readlink|sha256sum|env|sh|printf)\s")
    for script in (PYTHON_SCRIPT, WRAPPER):
        offenders = [line for line in _code_lines(script) if bare.search(line)]
        assert not offenders, (script.name, offenders)


def test_a_shell_earlier_on_path_does_not_run_the_step(step, tmp_path):
    """PATH is not trusted: the step's shell is /bin/sh, not the first `sh` on PATH."""
    src, stub, rec, _other, _other_rec, env = step
    fake_rec = tmp_path / "fake-sh"
    fake = tmp_path / "early-sh" / "sh"
    fake.parent.mkdir()
    fake.write_text(f'#!/bin/sh\necho ran > "{fake_rec}"\necho "/forged/uv 0"\n')
    fake.chmod(0o755)
    env = {**env, "PATH": f"{fake.parent}:{env['PATH']}"}
    _prefix, result = _install_sh_python_step(tmp_path, env, tmp_path, src)
    assert result.returncode == 0, result.stderr
    assert not fake_rec.exists(), "a sh found on PATH ran the step"
    assert f"RECORD={stub} {_sha(stub)}\n" in result.stdout, result.stdout
    assert Path(f"{rec}.path").read_text() == f"{stub}\n"

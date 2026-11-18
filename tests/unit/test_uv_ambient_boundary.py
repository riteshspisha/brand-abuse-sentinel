"""No ambient uv, Python or backend setting changes what the build installs or builds (B7 U10).

`install.sh` creates the venv, installs the hash-pinned requirements and the wheel, and
both wheel paths (`build-sandbox-image.sh`, `install.sh`) run the pinned `uv build`.
With uv 0.12.20, left to the caller's environment:

- `UV_EXCLUDE` drops a hash-pinned package from `uv pip install`, exit 0;
- `UV_COMPILE_BYTECODE`, or a `uv.toml` in the user's configuration or in the working
  directory, adds bytecode to the installation;
- `UV_PROJECT` or `UV_WORKING_DIR` makes `uv build` build another project, exit 0;
- `PYTHONPATH` reaches the build backend, so a module on it replaces the hash-pinned one.

- `_PYTHON_HOST_PLATFORM` makes the hash-pinned install take another platform's wheels;
- `VIRTUAL_ENV` or `CONDA_PREFIX` chooses the interpreter that runs the backend.

Every such uv call therefore goes through `scripts/uv-clean.sh`, which passes uv only an
allow-listed environment (where uv and interpreters live, the release build's
`UV_OFFLINE`, `UV_CACHE_DIR` and `UV_LINK_MODE`, proxies and CAs) and refuses to run
without `--no-config`.

The real-uv tests are offline and need no cache: they install and build from small
hash-pinned wheels made here, with `--no-index --find-links`.
"""

import base64
import hashlib
import os
import re
import shlex
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).parents[2]
WRAPPER = REPO / "scripts" / "uv-clean.sh"
IMAGE_SCRIPT = REPO / "scripts" / "build-sandbox-image.sh"
INSTALL_SCRIPT = REPO / "scripts" / "service-account" / "install.sh"
PYTHON_SCRIPT = REPO / "scripts" / "service-account" / "install-python.sh"
ALLOWED = ("PATH", "HOME", "TMPDIR", "XDG_DATA_HOME", "XDG_CACHE_HOME", "UV_OFFLINE",
           "UV_CACHE_DIR", "UV_LINK_MODE", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
           "ALL_PROXY", "http_proxy", "https_proxy", "no_proxy", "all_proxy",
           "SSL_CERT_FILE", "SSL_CERT_DIR")  # fmt: skip
CLEARED = ("UV_EXCLUDE", "UV_PROJECT", "UV_WORKING_DIR", "UV_COMPILE_BYTECODE",
           "UV_VENV_SEED", "UV_NO_VERIFY_HASHES", "UV_CONFIG_FILE", "UV_SOMETHING_FUTURE",
           "UV_PYTHON_DOWNLOADS_JSON_URL", "UV_PYTHON_CACHE_DIR", "UV_PYTHON_INSTALL_MIRROR",
           "UV_PYPY_INSTALL_MIRROR", "UV_PYTHON_DOWNLOADS", "PYTHONPATH", "PYTHONHOME",
           "PYTHONUSERBASE",
           "_PYTHON_HOST_PLATFORM", "VIRTUAL_ENV", "CONDA_PREFIX", "CONDA_DEFAULT_ENV",
           "XDG_CONFIG_HOME", "XDG_CONFIG_DIRS", "HATCH_BUILD_HOOKS_ENABLE",
           "SOURCE_DATE_EPOCH", "LD_LIBRARY_PATH", "KEEP_ME")  # fmt: skip


def _uv() -> str:
    uv = shutil.which("uv")
    assert uv, "uv must be on PATH for these tests (the build scripts need it too)"
    return uv


def _base_env(tmp_path: Path) -> dict[str, str]:
    """A minimal environment: no uv, Python or backend settings, no user uv.toml."""
    return {"PATH": os.environ["PATH"], "HOME": str(tmp_path / "home"),
            "XDG_CONFIG_HOME": str(tmp_path / "xdg"), "UV_CACHE_DIR": str(tmp_path / "cache"),
            "UV_OFFLINE": "1"}  # fmt: skip


def _wrapped(*args: str, env: dict, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - fixed argv
        ["/bin/sh", str(WRAPPER), *args], env=env, cwd=cwd, capture_output=True, text=True
    )


def _plain(*args: str, env: dict, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - fixed argv
        [_uv(), *args], env=env, cwd=cwd, capture_output=True, text=True
    )


# -- small hash-pinned distributions -------------------------------------------------------


def _record_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


WHEEL = b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"


def _wheel(directory: Path, name: str, version: str, files: dict[str, str]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    info = f"{name}-{version}.dist-info"
    metadata = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n".encode()
    members = {**{k: v.encode() for k, v in files.items()},
               f"{info}/METADATA": metadata, f"{info}/WHEEL": WHEEL}  # fmt: skip
    record = "".join(f"{n},{_record_hash(d)},{len(d)}\n" for n, d in members.items())
    record += f"{info}/RECORD,,\n"
    path = directory / f"{name}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as whl:
        for n, d in members.items():
            whl.writestr(n, d)
        whl.writestr(f"{info}/RECORD", record)
    return path


def _pin(wheel: Path) -> str:
    name, version = wheel.name.split("-")[:2]
    return f"{name}=={version} --hash=sha256:{hashlib.sha256(wheel.read_bytes()).hexdigest()}\n"


BACKEND = """
import base64, hashlib, os, pathlib, zipfile
WHEEL = (b"Wheel-Version: 1.0\\nGenerator: tinybackend 1.0\\n"
         b"Root-Is-Purelib: true\\nTag: py3-none-any\\n")
def _h(d):
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(d).digest()).rstrip(b"=").decode()
def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    payload = pathlib.Path("payload.txt").read_bytes()
    info = "demo-1.0.dist-info"
    members = {"demo_payload.txt": payload,
               info + "/METADATA": b"Metadata-Version: 2.1\\nName: demo\\nVersion: 1.0\\n",
               info + "/WHEEL": WHEEL}
    record = "".join(f"{n},{_h(d)},{len(d)}\\n" for n, d in members.items()) + info + "/RECORD,,\\n"
    name = "demo-1.0-py3-none-any.whl"
    with zipfile.ZipFile(os.path.join(wheel_directory, name), "w") as whl:
        for n, d in members.items():
            whl.writestr(zipfile.ZipInfo(n, (1980, 1, 1, 0, 0, 0)), d)
        whl.writestr(zipfile.ZipInfo(info + "/RECORD", (1980, 1, 1, 0, 0, 0)), record)
    return name
def get_requires_for_build_wheel(config_settings=None):
    return []
"""


@pytest.fixture
def index(tmp_path):
    """alpha and beta (installable), and tinybackend (a PEP 517 backend), all hash-pinned."""
    links = tmp_path / "links"
    alpha = _wheel(links, "alpha", "1.0", {"alpha.py": "A = 1\n"})
    beta = _wheel(links, "beta", "1.0", {"beta.py": "B = 1\n"})
    backend = _wheel(links, "tinybackend", "1.0", {"tinybackend.py": BACKEND})
    (tmp_path / "requirements.txt").write_text(_pin(alpha) + _pin(beta))
    (tmp_path / "build-constraints.txt").write_text(_pin(backend))
    return links


def _project(directory: Path, payload: str) -> Path:
    directory.mkdir(parents=True)
    (directory / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "1.0"\n'
        '[build-system]\nrequires = ["tinybackend==1.0"]\nbuild-backend = "tinybackend"\n'
    )
    (directory / "payload.txt").write_text(payload)
    return directory


def _venv(tmp_path: Path, env: dict) -> Path:
    venv = tmp_path / "venv"
    result = _plain("venv", "--no-config", "--python", sys.executable, str(venv), env=env,
                    cwd=tmp_path)  # fmt: skip
    assert result.returncode == 0, result.stderr
    return venv


def _install(tmp_path, index, env, *, wrapped: bool, cwd: Path | None = None):
    venv = _venv(tmp_path, _base_env(tmp_path))
    args = ["pip", "install", "--no-config", "--python", str(venv / "bin" / "python"),
            "--require-hashes", "--no-index", "--find-links", str(index),
            "--requirement", str(tmp_path / "requirements.txt")]  # fmt: skip
    run = _wrapped if wrapped else _plain
    result = run(*args, env=env, cwd=cwd or tmp_path)
    site = next((venv / "lib").glob("python3.*/site-packages"))
    return result, site


def _build(tmp_path, index, project, env, *, wrapped: bool):
    out = tmp_path / "out"
    args = ["build", "--no-config", "--wheel", "--no-index", "--find-links", str(index),
            "--build-constraints", str(tmp_path / "build-constraints.txt"), "--require-hashes",
            "--out-dir", str(out)]  # fmt: skip
    result = (_wrapped if wrapped else _plain)(*args, env=env, cwd=project)
    wheels = list(out.glob("*.whl")) if out.exists() else []
    payload = zipfile.ZipFile(wheels[0]).read("demo_payload.txt").decode() if wheels else None
    return result, payload


# -- uv pip install --------------------------------------------------------------------------


def test_a_clean_install_has_every_pinned_package(tmp_path, index):
    result, site = _install(tmp_path, index, _base_env(tmp_path), wrapped=True)
    assert result.returncode == 0, result.stderr
    assert (site / "alpha.py").exists() and (site / "beta.py").exists()
    assert not list(site.rglob("*.pyc"))


def test_uv_exclude_drops_a_pinned_package_from_a_plain_install(tmp_path, index):
    """Control: the bypass is real without the wrapper."""
    (tmp_path / "exclude.txt").write_text("beta\n")
    env = {**_base_env(tmp_path), "UV_EXCLUDE": str(tmp_path / "exclude.txt")}
    result, site = _install(tmp_path, index, env, wrapped=False)
    assert result.returncode == 0 and not (site / "beta.py").exists()


def test_the_wrapper_keeps_every_pinned_package_under_uv_exclude(tmp_path, index):
    (tmp_path / "exclude.txt").write_text("beta\n")
    env = {**_base_env(tmp_path), "UV_EXCLUDE": str(tmp_path / "exclude.txt")}
    result, site = _install(tmp_path, index, env, wrapped=True)
    assert result.returncode == 0, result.stderr
    assert (site / "alpha.py").exists() and (site / "beta.py").exists()


@pytest.mark.parametrize("source", ["variable", "user-config", "working-directory-config"])
def test_the_wrapper_adds_no_bytecode_from_ambient_settings(source, tmp_path, index):
    env, cwd = _base_env(tmp_path), tmp_path / "cwd"
    cwd.mkdir()
    config = "[pip]\ncompile-bytecode = true\n"
    if source == "variable":
        env["UV_COMPILE_BYTECODE"] = "1"
    elif source == "user-config":
        (tmp_path / "xdg" / "uv").mkdir(parents=True)
        (tmp_path / "xdg" / "uv" / "uv.toml").write_text(config)
    else:
        (cwd / "uv.toml").write_text(config)
    result, site = _install(tmp_path, index, env, wrapped=True, cwd=cwd)
    assert result.returncode == 0, result.stderr
    assert not list(site.rglob("*.pyc")), source


def test_uv_compile_bytecode_adds_bytecode_to_a_plain_install(tmp_path, index):
    """Control: the variable alone compiles the installed modules."""
    env = {**_base_env(tmp_path), "UV_COMPILE_BYTECODE": "1"}
    result, site = _install(tmp_path, index, env, wrapped=False)
    assert result.returncode == 0 and list(site.rglob("alpha*.pyc"))


def test_a_working_directory_config_adds_bytecode_to_a_plain_install(tmp_path, index):
    """Control: install.sh runs from the caller's directory, whose uv.toml applies."""
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    (cwd / "uv.toml").write_text("[pip]\ncompile-bytecode = true\n")
    args = ["pip", "install", "--python"]
    venv = _venv(tmp_path, _base_env(tmp_path))
    result = _plain(*args, str(venv / "bin" / "python"), "--require-hashes", "--no-index",
                    "--find-links", str(index), "--requirement", str(tmp_path / "requirements.txt"),
                    env=_base_env(tmp_path), cwd=cwd)  # fmt: skip
    assert result.returncode == 0, result.stderr
    assert list((venv / "lib").rglob("alpha*.pyc"))


def _platform_index(tmp_path: Path) -> tuple[Path, str]:
    """gamma for this machine and for another architecture, both hash-pinned."""
    links = tmp_path / "plinks"
    here = "x86_64" if os.uname().machine == "x86_64" else "aarch64"
    other = "aarch64" if here == "x86_64" else "x86_64"
    pins = ""
    for arch in (here, other):
        wheel = _wheel(links, "gamma", "1.0", {"gamma.py": f"ARCH = {arch!r}\n"})
        tagged = wheel.with_name(f"gamma-1.0-py3-none-manylinux_2_17_{arch}.whl")
        wheel.rename(tagged)
        pins += f" --hash=sha256:{hashlib.sha256(tagged.read_bytes()).hexdigest()}"
    (tmp_path / "requirements.txt").write_text(f"gamma==1.0{pins}\n")
    return links, other


def _installed_arch(tmp_path, links, env, *, wrapped):
    result, site = _install(tmp_path, links, env, wrapped=wrapped)
    assert result.returncode == 0, result.stderr
    return re.search(r"ARCH = '(\w+)'", (site / "gamma.py").read_text()).group(1)


def test_python_host_platform_installs_another_platforms_wheel_plainly(tmp_path):
    """Control: _PYTHON_HOST_PLATFORM picks the other architecture's pinned wheel."""
    links, other = _platform_index(tmp_path)
    env = {**_base_env(tmp_path), "_PYTHON_HOST_PLATFORM": f"linux-{other}"}
    assert _installed_arch(tmp_path, links, env, wrapped=False) == other


def test_the_wrapper_installs_this_platforms_wheel(tmp_path):
    links, other = _platform_index(tmp_path)
    env = {**_base_env(tmp_path), "_PYTHON_HOST_PLATFORM": f"linux-{other}"}
    assert _installed_arch(tmp_path, links, env, wrapped=True) != other


# -- uv build --------------------------------------------------------------------------------


def test_a_clean_build_builds_the_project_with_the_pinned_backend(tmp_path, index):
    project = _project(tmp_path / "project", "real")
    result, payload = _build(tmp_path, index, project, _base_env(tmp_path), wrapped=True)
    assert result.returncode == 0, result.stderr
    assert payload == "real"


@pytest.mark.parametrize("variable", ["UV_PROJECT", "UV_WORKING_DIR"])
def test_a_variable_naming_another_project_redirects_a_plain_build(variable, tmp_path, index):
    """Control: without the wrapper, the decoy is built, exit 0."""
    project = _project(tmp_path / "project", "real")
    decoy = _project(tmp_path / "decoy", "decoy")
    env = {**_base_env(tmp_path), variable: str(decoy)}
    result, payload = _build(tmp_path, index, project, env, wrapped=False)
    assert result.returncode == 0 and payload == "decoy"


@pytest.mark.parametrize("variable", ["UV_PROJECT", "UV_WORKING_DIR"])
def test_the_wrapper_builds_the_project_it_is_run_in(variable, tmp_path, index):
    project = _project(tmp_path / "project", "real")
    decoy = _project(tmp_path / "decoy", "decoy")
    env = {**_base_env(tmp_path), variable: str(decoy)}
    result, payload = _build(tmp_path, index, project, env, wrapped=True)
    assert result.returncode == 0, result.stderr
    assert payload == "real"


def _shadow(tmp_path: Path) -> Path:
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    (shadow / "tinybackend.py").write_text(
        BACKEND.replace('pathlib.Path("payload.txt").read_bytes()', 'b"shadowed"')
    )
    return shadow


def test_pythonpath_replaces_the_pinned_backend_in_a_plain_build(tmp_path, index):
    """Control: a module on PYTHONPATH wins over the hash-pinned backend."""
    project = _project(tmp_path / "project", "real")
    env = {**_base_env(tmp_path), "PYTHONPATH": str(_shadow(tmp_path))}
    result, payload = _build(tmp_path, index, project, env, wrapped=False)
    assert result.returncode == 0 and payload == "shadowed"


def test_the_wrapper_builds_with_the_pinned_backend_under_pythonpath(tmp_path, index):
    project = _project(tmp_path / "project", "real")
    env = {**_base_env(tmp_path), "PYTHONPATH": str(_shadow(tmp_path))}
    result, payload = _build(tmp_path, index, project, env, wrapped=True)
    assert result.returncode == 0, result.stderr
    assert payload == "real"


# -- the wrapper's own contract (a stub uv records what it receives) -------------------------


@pytest.fixture
def stub(tmp_path):
    seen = tmp_path / "seen"
    uv = tmp_path / "bin" / "uv"
    uv.parent.mkdir()
    uv.write_text(f'#!/bin/sh\nenv > "{seen}.env"\nprintf "%s\\n" "$@" > "{seen}.argv"\n')
    uv.chmod(0o755)
    return uv, seen


def _stub_env(uv: Path) -> dict[str, str]:
    env = {name: f"kept {name}" for name in ALLOWED}
    env["PATH"] = f"{uv.parent}:/usr/bin:/bin"
    env.update({name: "x" for name in CLEARED})
    return env


def _passed(seen: Path) -> dict[str, str]:
    lines = Path(f"{seen}.env").read_text().splitlines()
    return dict(line.split("=", 1) for line in lines if "=" in line)


def test_the_wrapper_passes_only_the_allowed_environment(stub, tmp_path):
    uv, seen = stub
    env = _stub_env(uv)
    result = _wrapped("build", "--no-config", "a b", env=env, cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    passed = _passed(seen)
    assert set(passed) <= set(ALLOWED) | {"PWD", "SHLVL", "_"}  # set by the stub's shell
    assert {name: passed[name] for name in ALLOWED} == {name: env[name] for name in ALLOWED}
    assert Path(f"{seen}.argv").read_text().splitlines() == ["build", "--no-config", "a b"]


@pytest.mark.parametrize("function", ["env", "sed", "uv", "printf", "test"])
def test_an_exported_shell_function_cannot_widen_the_environment(function, stub, tmp_path):
    """/bin/sh may be bash, which imports exported functions from the environment."""
    uv, seen = stub
    env = {**_stub_env(uv), f"BASH_FUNC_{function}%%": "() { :; }"}
    result = _wrapped("build", "--no-config", env=env, cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert set(_passed(seen)) <= set(ALLOWED) | {"PWD", "SHLVL", "_"}


@pytest.mark.parametrize("args", [["build", "--wheel"], ["pip", "install", "x"], []])
def test_the_wrapper_refuses_without_no_config(args, stub, tmp_path):
    uv, seen = stub
    result = _wrapped(*args, env=_stub_env(uv), cwd=tmp_path)
    assert result.returncode != 0 and "--no-config" in result.stderr
    assert not Path(f"{seen}.argv").exists(), "uv must not run"


# -- every installing or building uv call in the build paths uses the wrapper ----------------


def _logical(text: str) -> list[str]:
    out, cur = [], ""
    for raw in text.splitlines():
        line = "" if raw.lstrip().startswith("#") else raw
        if line.rstrip().endswith("\\"):
            cur += line.rstrip()[:-1] + " "
            continue
        cur += line
        if cur.strip():
            out.append(cur.strip())
        cur = ""
    return out


GUARDED = re.compile(r"\buv(\s+-\S+)*\s+(build|pip|venv|sync|run|tool|python)\b")


@pytest.mark.parametrize(
    "script", [IMAGE_SCRIPT, INSTALL_SCRIPT, PYTHON_SCRIPT], ids=["image", "install", "python"]
)
def test_no_build_path_runs_uv_to_build_or_install_without_the_wrapper(script):
    for line in _logical(script.read_text()):
        assert not GUARDED.search(line), f"{script.name}: {line}"


def _wrapped_calls(script: Path) -> list[list[str]]:
    calls = []
    for line in _logical(script.read_text()):
        if "uv-clean.sh" in line:
            words = shlex.split(line.split(")", 1)[0].split("&&")[-1])
            i = next(i for i, w in enumerate(words) if w.endswith("uv-clean.sh"))
            calls.append(
                words[i + 1 : words.index(">/dev/null") if ">/dev/null" in words else None]
            )
    return calls


def test_install_sh_creates_the_venv_and_installs_only_through_the_wrapper():
    calls = [c[:2] for c in _wrapped_calls(INSTALL_SCRIPT)]
    assert calls.count(["pip", "install"]) == 2
    assert ["venv", "--no-config"] in calls
    assert all("--no-config" in c for c in _wrapped_calls(INSTALL_SCRIPT))


def test_both_wheel_paths_run_the_same_wrapped_build():
    def build(script):
        (call,) = [c for c in _wrapped_calls(script) if c[0] == "build"]
        i = call.index("--out-dir")
        return call[:i] + call[i + 2 :]

    assert build(IMAGE_SCRIPT) == build(INSTALL_SCRIPT)
    assert build(IMAGE_SCRIPT)[:3] == ["build", "--no-config", "--wheel"]

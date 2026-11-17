"""The build backend is pinned, with hashes, for both wheel-build paths (B7 U11, X16).

`scripts/build-sandbox-image.sh` (the image wheel) and `scripts/service-account/install.sh`
(the installed wheel) must build with the same backend, so that the two wheels are
byte-equal. These checks are static; the offline wheel-equality and hash-refusal evidence
is described in docs/development/testing.md.
"""

import hashlib
import io
import re
import shlex
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

import pytest
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name

REPO = Path(__file__).parents[2]
PIN = REPO / "build-constraints.txt"
IMAGE_SCRIPT = REPO / "scripts" / "build-sandbox-image.sh"
INSTALL_SCRIPT = REPO / "scripts" / "service-account" / "install.sh"
# hatchling's build environment on Python >= 3.11 (tomli is only needed below 3.11).
BACKEND_CLOSURE = {"hatchling", "packaging", "pathspec", "pluggy", "tomlkit", "trove-classifiers"}
HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})")


def _logical_lines(text: str) -> list[str]:
    """Shell or requirements lines with comments dropped and continuations joined."""
    out, cur = [], ""
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0] if not raw.lstrip().startswith("#") else ""
        if line.rstrip().endswith("\\"):
            cur += line.rstrip()[:-1] + " "
            continue
        cur += line
        if cur.strip():
            out.append(cur.strip())
        cur = ""
    return out


def _pins() -> dict[str, tuple[str, set[str]]]:
    pins: dict[str, tuple[str, set[str]]] = {}
    for entry in _logical_lines(PIN.read_text()):
        tokens = entry.split()
        assert not tokens[0].startswith("-"), f"option in the pin file: {entry}"
        name, sep, version = tokens[0].partition("==")
        assert sep and re.fullmatch(r"[0-9][0-9A-Za-z.]*", version), f"not exact: {entry}"
        assert all(HASH.fullmatch(t) for t in tokens[1:]), f"unexpected token: {entry}"
        hashes = {HASH.fullmatch(t).group(1) for t in tokens[1:]}
        assert hashes, f"no hash: {entry}"
        key = canonicalize_name(name)
        assert key not in pins, f"duplicate entry: {name}"
        pins[key] = (version, hashes)
    return pins


def _uv_build(script: Path) -> list[str]:
    """The single wheel-build command of a script, from its `env` prefix, without --out-dir."""
    commands = [line for line in _logical_lines(script.read_text()) if "uv build" in line]
    assert len(commands) == 1, f"{script.name}: {commands}"
    command = commands[0]
    command = command[command.index("env -u") :].split(")", 1)[0]
    words = [w for w in shlex.split(command) if w != ">/dev/null"]
    i = words.index("--out-dir")
    del words[i : i + 2]
    return words


def test_the_pin_file_names_exact_versions_with_hashes():
    pins = _pins()
    assert pins["hatchling"][0] == "1.32.4"
    assert all(len(hashes) >= 1 for _, hashes in pins.values())


def test_the_pin_covers_the_backend_and_every_build_dependency():
    assert set(_pins()) == BACKEND_CLOSURE


def test_the_pinned_backend_satisfies_the_project_build_system():
    build = tomllib.loads((REPO / "pyproject.toml").read_text())["build-system"]
    assert build["build-backend"] == "hatchling.build"
    (requirement,) = build["requires"]
    name, spec = re.fullmatch(r"([A-Za-z0-9_.-]+)\s*(.*)", requirement).groups()
    assert canonicalize_name(name) == "hatchling"
    assert _pins()["hatchling"][0] in SpecifierSet(spec)


def test_pins_shared_with_the_lock_have_the_locked_version_and_hashes():
    lock = tomllib.loads((REPO / "uv.lock").read_text())
    locked = {canonicalize_name(p["name"]): p for p in lock["package"]}
    shared = set(_pins()) & set(locked)
    assert shared >= {"packaging", "pluggy"}
    for name in shared:
        version, hashes = _pins()[name]
        package = locked[name]
        files = [package.get("sdist", {}), *package.get("wheels", [])]
        assert version == package["version"], name
        assert hashes == {f["hash"].removeprefix("sha256:") for f in files if f}, name


def test_both_wheel_paths_build_with_the_same_pinned_command():
    image, install = _uv_build(IMAGE_SCRIPT), _uv_build(INSTALL_SCRIPT)
    assert image == install
    build = image.index("uv")
    assert image[build : build + 4] == ["uv", "build", "--no-config", "--wheel"]
    i = image.index("--build-constraints")
    assert image[i + 1] == "build-constraints.txt"
    assert "--require-hashes" in image


def test_the_build_clears_every_override_of_isolation_hashes_or_timestamps():
    # Each of these, inherited from the caller, either switches off build isolation (the
    # pin is then ignored and the ambient backend builds the wheel), turns off hash
    # checks, or changes the wheel's bytes. --no-config ignores uv.toml and [tool.uv].
    words = _uv_build(IMAGE_SCRIPT)
    prefix = words[: words.index("uv")]
    assert prefix[0] == "env"
    cleared = {prefix[i + 1] for i, w in enumerate(prefix) if w == "-u"}
    assert len(prefix) == 1 + 2 * len(cleared)
    assert cleared == {
        "UV_NO_BUILD_ISOLATION",
        "UV_NO_BUILD_ISOLATION_PACKAGE",
        "UV_NO_VERIFY_HASHES",
        "UV_CONFIG_FILE",
        "SOURCE_DATE_EPOCH",
    }


@pytest.mark.parametrize("script", [IMAGE_SCRIPT, INSTALL_SCRIPT], ids=["image", "install"])
def test_no_script_disables_hash_checks_or_build_isolation(script):
    text = script.read_text()
    assert "--no-verify-hashes" not in text
    assert "--no-build-isolation" not in text
    assert not re.search(r"\bUV_(NO_BUILD_ISOLATION\w*|NO_VERIFY_HASHES|CONFIG_FILE)=", text)


def test_the_pin_file_is_at_the_root_both_scripts_build_from():
    # build-sandbox-image.sh builds from the repository root; install.sh from
    # $PREFIX/src, a `git archive` of it. An export-ignore would drop the file there.
    assert PIN.is_file()
    assert 'cd "$(dirname "$0")/.."' in IMAGE_SCRIPT.read_text()
    assert '(cd "$PREFIX/src" && env -u' in INSTALL_SCRIPT.read_text()
    attributes = REPO / ".gitattributes"
    assert not attributes.exists() or "export-ignore" not in attributes.read_text()


def test_the_image_script_records_the_wheel_before_cleanup():
    text = IMAGE_SCRIPT.read_text()
    build = text.index("uv build")
    record = text.index("python3 -I -S - docker/dist build-constraints.txt")
    assert build < record < text.index("docker build") < text.rindex("rm -rf docker/dist")


def _record_block() -> str:
    text = IMAGE_SCRIPT.read_text()
    start = text.index("<<'EOF'\n") + len("<<'EOF'\n")
    return text[start : text.index("\nEOF\n", start)]


def _wheel(directory: Path, generator: str | None, name="brandsentinel-0.2.1-py3-none-any.whl"):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as whl:
        whl.writestr("brandsentinel/__init__.py", "")
        if generator is not None:
            line = f"Generator: {generator}\n" if generator else ""
            body = f"Wheel-Version: 1.0\n{line}Root-Is-Purelib: true\n"
            whl.writestr("brandsentinel-0.2.1.dist-info/WHEEL", body)
    directory.mkdir(exist_ok=True)
    (directory / name).write_bytes(buffer.getvalue())
    return directory / name


def _record(dist: Path, pin: Path = PIN) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, "-I", "-S", "-", str(dist), str(pin)],
        input=_record_block(),
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_the_record_prints_the_sha256_and_backend_of_a_pinned_wheel(tmp_path):
    wheel = _wheel(tmp_path / "dist", "hatchling 1.32.4")
    done = _record(tmp_path / "dist")
    assert done.returncode == 0, done.stderr
    assert f"sha256 {hashlib.sha256(wheel.read_bytes()).hexdigest()}" in done.stdout
    assert "wheel Generator: hatchling 1.32.4" in done.stdout


@pytest.mark.parametrize(
    "generator",
    ["hatchling 1.33.0", "hatchling 1.32.40", "setuptools (80.0)", "", None],
    ids=["other-version", "prefix-version", "other-backend", "no-Generator", "no-WHEEL-file"],
)
def test_the_record_refuses_a_wheel_from_another_backend(tmp_path, generator):
    _wheel(tmp_path / "dist", generator)
    done = _record(tmp_path / "dist")
    assert done.returncode != 0
    assert "pinned backend" in done.stderr


@pytest.mark.parametrize("count", [0, 2])
def test_the_record_refuses_anything_but_one_wheel(tmp_path, count):
    (tmp_path / "dist").mkdir()
    for i in range(count):
        _wheel(
            tmp_path / "dist", "hatchling 1.32.4", name=f"brandsentinel-0.2.{i}-py3-none-any.whl"
        )
    done = _record(tmp_path / "dist")
    assert done.returncode != 0
    assert "expected one wheel" in done.stderr


def test_the_record_refuses_without_a_backend_pin(tmp_path):
    _wheel(tmp_path / "dist", "hatchling 1.32.4")
    empty = tmp_path / "constraints.txt"
    empty.write_text("# no pin\n")
    done = _record(tmp_path / "dist", empty)
    assert done.returncode != 0
    assert "pinned backend" in done.stderr

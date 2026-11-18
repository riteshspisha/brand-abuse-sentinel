"""Only the named project's committed lock decides the exported dependency set (B7 U10).

`uv export` turns `uv.lock` into the pins the image is built from
(`scripts/build-sandbox-image.sh`), the pins the installation is built from
(`scripts/service-account/install.sh`) and the pins the image is verified against
(`image_manifest.py --profile release`). Left to itself, uv 0.12.20 also follows
`UV_PROJECT` or `UV_WORKING_DIR` to another project, drops the dev group on `UV_NO_DEV`,
and exports the lock of a workspace declared in an ancestor directory, all with exit 0.
If the build and the verifier followed the same decoy, the image would pass.

These tests run the real uv, offline, against a copy of this repository's
`pyproject.toml` and `uv.lock`; uv must be on PATH.
"""

import importlib.util
import os
import re
import shlex
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

REPO = Path(__file__).parents[2]
HELPER = REPO / "scripts" / "uv-export-locked.sh"
IMAGE_SCRIPT = REPO / "scripts" / "build-sandbox-image.sh"
INSTALL_SCRIPT = REPO / "scripts" / "service-account" / "install.sh"
VERIFIER = REPO / "scripts" / "service-account" / "image_manifest.py"
SANDBOX = ["--no-dev", "--extra", "sandbox", "--no-emit-project", "--no-hashes",
           "--no-annotate", "--no-header", "--format", "requirements-txt"]  # fmt: skip


def _verifier():
    spec = importlib.util.spec_from_file_location("image_manifest_boundary", VERIFIER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


im = _verifier()


def _uv() -> str:
    uv = shutil.which("uv")
    assert uv, "uv must be on PATH for these tests (the release verifier needs it too)"
    return uv


def _project(directory: Path, lock: str | None = None) -> Path:
    directory.mkdir(parents=True)
    shutil.copy(REPO / "pyproject.toml", directory / "pyproject.toml")
    (directory / "uv.lock").write_text(lock if lock is not None else (REPO / "uv.lock").read_text())
    return directory


def _clean_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if not k.startswith("UV_")}


def _plain_export(project: Path) -> str:
    """What uv exports for the project with nothing ambient (the reference)."""
    return subprocess.run(  # noqa: S603 - fixed argv
        [_uv(), "export", "--frozen", "--offline", *SANDBOX],
        cwd=project, env=_clean_env(), check=True, capture_output=True, text=True,
    ).stdout  # fmt: skip


def _tampered_lock(reference: Path) -> tuple[str, str]:
    """The repository lock with one exported package moved to another version.

    uv rejects a lock whose artifact file names disagree with the version, so the
    package's sdist and wheel names move too: the decoy is a well-formed lock."""
    text = (REPO / "uv.lock").read_text()
    clean = _plain_export(reference)
    name, version = re.search(r"^([a-z0-9][a-z0-9._-]*)==(\S+)", clean, re.M).groups()
    entry = f'name = "{name}"\nversion = "{version}"\n'
    assert text.count(entry) == 1, entry
    start = text.index(entry)
    end = text.find("\n[[package]]", start)
    end = len(text) if end < 0 else end
    block = text[start:end].replace(entry, f'name = "{name}"\nversion = "999.0"\n')
    for stem in {name, name.replace("-", "_")}:
        block = block.replace(f"/{stem}-{version}", f"/{stem}-999.0")
    return text[:start] + block + text[end:], name


def _ancestor_workspace(root: Path, reference: Path) -> Path:
    """A workspace one level up that lists the project as a member, with its own lock."""
    lock, _ = _tampered_lock(reference)
    lock = lock.replace('source = { editable = "." }', 'source = { editable = "member" }', 1)
    head, rest = lock.split("\n[[package]]", 1)
    lock = (
        head + '\n\n[manifest]\nmembers = [\n    "brandsentinel",\n    "ws-root",\n]\n'
        "\n[[package]]" + rest + '\n[[package]]\nname = "ws-root"\nversion = "0"\n'
        'source = { virtual = "." }\n'
    )
    root.mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        '[project]\nname = "ws-root"\nversion = "0"\nrequires-python = ">=3.12, <3.14"\n'
        'dependencies = []\n[tool.uv.workspace]\nmembers = ["member"]\n'
    )
    (root / "uv.lock").write_text(lock)
    return _project(root / "member")


def _pins_text(pins) -> str:
    return "\n".join(f"{n}=={v}" for n, v, _ in pins)


# -- the verifier (image_manifest.expected_pins) ------------------------------------------


REFUSED = "uv-export-locked: refusing:"


@pytest.fixture
def source(tmp_path):
    return _project(tmp_path / "source")


@pytest.fixture
def decoy(tmp_path, source):
    lock, _ = _tampered_lock(source)
    return _project(tmp_path / "decoy", lock)


def _stub_uv(tmp_path: Path) -> tuple[Path, Path]:
    """A uv that records its argv and environment and prints one pin."""
    seen = tmp_path / "seen"
    stub = tmp_path / "bin" / "uv"
    stub.parent.mkdir()
    stub.write_text(f'#!/bin/sh\nenv > "{seen}.env"\nprintf "%s\\n" "$@" > "{seen}.argv"\n'
                    'echo "dep-a==1.0"\n')  # fmt: skip
    stub.chmod(0o755)
    return stub, seen


def _assert_clean_invocation(seen: Path, project: Path) -> None:
    passed = Path(f"{seen}.env").read_text().splitlines()
    assert not [line for line in passed if line.startswith("UV_")]
    argv = Path(f"{seen}.argv").read_text().splitlines()
    assert argv[0] == "export"
    assert {"--no-config", "--no-cache", "--frozen", "--offline"} <= set(argv)
    assert argv[argv.index("--project") + 1] == str(project.resolve())


AMBIENT = ("UV_NO_DEV", "UV_NO_DEFAULT_GROUPS", "UV_CONFIG_FILE", "UV_INDEX_URL", "UV_CACHE_DIR",
           "UV_SOMETHING_FUTURE")  # fmt: skip


def test_the_verifier_exports_the_source_lock(source):
    pins = im.expected_pins(source)
    reference = [line for line in _plain_export(source).splitlines() if "==" in line]
    assert _pins_text(pins).splitlines() == [line.split(";")[0].strip() for line in reference]


@pytest.mark.parametrize("variable", ["UV_PROJECT", "UV_WORKING_DIR"])
def test_the_verifier_ignores_a_variable_naming_another_project(variable, source, decoy,
                                                                monkeypatch):  # fmt: skip
    clean = im.expected_pins(source)
    monkeypatch.setenv(variable, str(decoy))
    pins = im.expected_pins(source)
    assert pins == clean
    assert "999.0" not in _pins_text(pins), f"{variable} redirected the export"


def test_the_verifier_passes_uv_no_variable_config_or_cache(source, tmp_path, monkeypatch):
    stub, seen = _stub_uv(tmp_path)
    monkeypatch.setattr(im.shutil, "which", lambda name: str(stub) if name == "uv" else None)
    for name in AMBIENT:
        monkeypatch.setenv(name, "1")
    assert im.expected_pins(source) == [("dep-a", "1.0", None)]
    _assert_clean_invocation(seen, source)


def test_the_verifier_reads_a_relative_source_once(tmp_path, monkeypatch):
    """A relative --source names one directory, not <source>/<source>."""
    outer = _project(tmp_path / "w" / "proj")
    lock, _ = _tampered_lock(outer)
    _project(outer / "w" / "proj", lock)  # what a doubled relative path would reach
    monkeypatch.chdir(tmp_path)
    assert "999.0" not in _pins_text(im.expected_pins(Path("w/proj")))
    assert im.expected_pins(Path("w/proj")) == im.expected_pins(outer)


# -- the shell helper both build paths use ------------------------------------------------


def _helper(project, *args: str, env: dict | None = None, cwd: Path | None = None):
    return subprocess.run(  # noqa: S603 - fixed argv
        ["/bin/sh", str(HELPER), str(project), *args], cwd=cwd or project,
        env=env if env is not None else _clean_env(), capture_output=True, text=True,
    )  # fmt: skip


def _refused(result) -> bool:
    return result.returncode == 1 and result.stdout == "" and REFUSED in result.stderr


def test_the_helper_exports_the_project_lock(source):
    result = _helper(source, *SANDBOX)
    assert result.returncode == 0, result.stderr
    assert result.stdout == _plain_export(source)


@pytest.mark.parametrize("variable", ["UV_PROJECT", "UV_WORKING_DIR"])
def test_the_helper_ignores_a_variable_naming_another_project(variable, source, decoy, tmp_path):
    result = _helper(source, *SANDBOX, env={**_clean_env(), variable: str(decoy)}, cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout == _plain_export(source)


def test_the_helper_keeps_the_dev_group_under_uv_no_dev(source):
    dev = ["--group", "dev", "--no-emit-project", "--no-hashes", "--no-header",
           "--format", "requirements-txt"]  # fmt: skip
    clean = _helper(source, *dev)
    ambient = _helper(source, *dev, env={**_clean_env(), "UV_NO_DEV": "1",
                                          "UV_NO_DEFAULT_GROUPS": "1"})  # fmt: skip
    assert clean.returncode == ambient.returncode == 0, ambient.stderr
    assert re.search(r"^pytest==", clean.stdout, re.M)
    assert ambient.stdout == clean.stdout


def test_the_helper_passes_uv_no_variable_config_or_cache(tmp_path):
    """Through a symlinked project, uv gets the physical path and a clean environment."""
    real = _project(tmp_path / "real" / "source")
    (tmp_path / "link").symlink_to(real)
    stub, seen = _stub_uv(tmp_path)
    env = {**_clean_env(), "PATH": f"{stub.parent}:{os.environ['PATH']}"}
    env.update({name: "1" for name in AMBIENT})
    result = _helper(tmp_path / "link", "--format", "requirements-txt", env=env, cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    _assert_clean_invocation(seen, real)


@pytest.mark.parametrize("project", ["-P", "-L", "-"])
def test_the_helper_refuses_an_option_like_project(project, tmp_path):
    """A directory really named like an option, holding a project: `cd -P` would go to
    $HOME and `cd -` to $OLDPWD, exporting whatever lock is there."""
    _project(tmp_path / project)
    assert _refused(_helper(project, *SANDBOX, cwd=tmp_path))


def test_the_helper_refuses_an_empty_project(tmp_path):
    assert _refused(_helper("", *SANDBOX, cwd=tmp_path))


def test_the_helper_refuses_a_project_path_with_a_newline(tmp_path, source):
    """$(...) strips a trailing newline, which would name the sibling without it."""
    twin = _project(tmp_path / "source\n")
    assert _refused(_helper(twin, *SANDBOX, cwd=tmp_path))


@pytest.mark.parametrize("missing", ["pyproject.toml", "uv.lock"])
def test_the_helper_refuses_a_directory_without_a_project_and_lock(missing, source):
    (source / missing).unlink()
    assert _refused(_helper(source, *SANDBOX))


# -- one table of layouts, both implementations -------------------------------------------


def _layout_workspace(tmp_path: Path, reference: Path) -> Path:
    return _ancestor_workspace(tmp_path / "ws", reference)


def _layout_logical_ancestor(tmp_path: Path, reference: Path) -> Path:
    """Clean physical path; the symlink's directory has a project above the link."""
    real = _project(tmp_path / "real" / "source")
    outer = tmp_path / "outer"
    outer.mkdir()
    (outer / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "0"\n')
    (outer / "link").symlink_to(real)
    return outer / "link"


def _layout_physical_ancestor(tmp_path: Path, reference: Path) -> Path:
    """Clean logical path; the symlink's target sits below a project."""
    hidden = tmp_path / "hidden"
    hidden.mkdir()
    (hidden / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "0"\n')
    real = _project(hidden / "source")
    (tmp_path / "clean").mkdir()
    (tmp_path / "clean" / "link").symlink_to(real)
    return tmp_path / "clean" / "link"


LAYOUTS = [_layout_workspace, _layout_logical_ancestor, _layout_physical_ancestor]


@pytest.mark.parametrize("layout", LAYOUTS, ids=["workspace", "logical", "physical"])
def test_both_implementations_refuse_a_project_above_the_source(layout, tmp_path, source):
    project = layout(tmp_path, source)
    with pytest.raises(im.Incomplete, match=r"pyproject\.toml"):
        im.expected_pins(project)
    assert _refused(_helper(project, *SANDBOX, cwd=tmp_path))


def test_the_workspace_layout_does_redirect_a_plain_export(tmp_path, source):
    """Control: without the refusal, uv really exports the ancestor's decoy lock."""
    member = _ancestor_workspace(tmp_path / "ws", source)
    assert "==999.0" in _plain_export(member)


def test_the_project_declares_no_uv_settings_that_no_config_would_ignore():
    """--no-config also drops the project's own [tool.uv] table. There is none today; one
    added later (default-groups, sources, ...) would make the export diverge from uv sync."""
    pyproject = tomllib.loads((REPO / "pyproject.toml").read_text())
    assert "uv" not in pyproject.get("tool", {})
    assert not (REPO / "uv.toml").exists()


# -- every export in the build paths goes through the helper ------------------------------


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


@pytest.mark.parametrize(
    ("script", "project", "selection"),
    [(IMAGE_SCRIPT, ".", ["--no-dev", "--extra", "sandbox", "--no-header"]),
     (INSTALL_SCRIPT, "$PREFIX/src", ["--group", "dev"])],
    ids=["image", "install"],
)  # fmt: skip
def test_each_build_path_exports_only_through_the_helper(script, project, selection):
    lines = _logical(script.read_text())
    exports = [line for line in lines if "uv-export-locked.sh" in line]
    assert len(exports) == 1, exports
    words = shlex.split(exports[0])
    assert words[0] == "sh" and words[1].endswith("scripts/uv-export-locked.sh")
    assert words[2] == project
    assert all(flag in words for flag in selection)
    assert not [line for line in lines if re.search(r"\buv\s+export\b", line)], script.name


def test_no_other_script_calls_uv_export_directly():
    offenders = []
    for path in (REPO / "scripts").rglob("*"):
        if path in (HELPER, VERIFIER) or not path.is_file():
            continue  # the helper and the verifier are checked behaviourally above
        if path.suffix in {".sh", ".py", ""}:
            text = "\n".join(_logical(path.read_text(errors="replace")))
            if re.search(r"\buv\s+export\b", text):
                offenders.append(path.relative_to(REPO).as_posix())
    assert offenders == []

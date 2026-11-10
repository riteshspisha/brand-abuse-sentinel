"""The installed-bytecode verifier (scripts/service-account/check_bytecode.py).

Every damage case starts from a tree asserted to pass and must flip the result, and
a completeness test ties each rule to a case, so a verifier that passes too easily
fails here.
"""

import importlib.util
import marshal
import os
import py_compile
import shutil
import subprocess
import sys
import types
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[2] / "scripts" / "service-account" / "check_bytecode.py"
VER = f"python{sys.version_info[0]}.{sys.version_info[1]}"
TAG = sys.implementation.cache_tag


def _load():
    spec = importlib.util.spec_from_file_location("check_bytecode", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_bytecode"] = module
    spec.loader.exec_module(module)
    return module


cb = _load()


def _pyc(source: Path) -> Path:
    return source.parent / "__pycache__" / f"{source.stem}.{TAG}.pyc"


def _compile(source: Path, mode=py_compile.PycInvalidationMode.CHECKED_HASH) -> None:
    py_compile.compile(str(source), invalidation_mode=mode, doraise=True)


class Tree:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.home = root / "python" / "cpython" / "bin"
        self.std = root / "python" / "cpython" / "lib" / VER
        self.bin = root / "venv" / "bin"
        self.site = root / "venv" / "lib" / VER / "site-packages"

    @property
    def module(self) -> Path:
        return self.site / "brandsentinel" / "mod.py"

    def launcher(self, first_line: str, name: str = "tool") -> Path:
        path = self.bin / name
        path.write_text(f"{first_line}\nimport sys\n")
        return path

    def shebang(self, suffix: str = " -B") -> str:
        return f"#!{self.bin}/python{suffix}"

    def sources(self) -> int:
        return sum(1 for base in (self.std, self.site) for p in base.rglob("*.py") if p.is_file())


@pytest.fixture
def tree(tmp_path: Path) -> Tree:
    t = Tree(tmp_path / "prefix")
    for d in (t.home, t.std / "encodings", t.bin, t.site / "brandsentinel"):
        d.mkdir(parents=True)
    (t.home / "python3.12").write_text("")
    (t.root / "venv" / "pyvenv.cfg").write_text(f"home = {t.home}\nversion_info = 3.12\n")
    (t.bin / "python").symlink_to(t.home / "python3.12")
    (t.bin / "python3").symlink_to("python")
    t.launcher(t.shebang(), "brandsentinel")
    (t.bin / "activate").write_text("# activate\n")
    (t.bin / "activate_this.py").write_text("# activate\n")
    (t.bin / "ruff").write_bytes(b"\x7fELF\x02\x01\x01\x00")
    for name, body in (
        (t.std / "os.py", "A = 1\n"),
        (t.std / "encodings" / "__init__.py", "B = 2\n"),
        (t.site / "brandsentinel" / "__init__.py", '"""doc"""\n'),
        (t.module, "def f():\n    return 1\n"),
    ):
        name.write_text(body)
        _compile(name)
    (t.root / "src").mkdir()
    (t.root / "src" / "app.py").write_text("X = 1\n")
    (t.root / "etc").mkdir()
    (t.root / "etc" / "service.yaml").write_text("{}\n")
    assert cb.inspect_prefix(str(t.root)).exit_code == 0, "the starting tree must pass"
    return t


def _delete(t: Tree) -> str:
    _pyc(t.module).unlink()
    return str(t.module)


def _timestamp(t: Tree) -> str:
    _compile(t.module, py_compile.PycInvalidationMode.TIMESTAMP)
    return str(_pyc(t.module))


def _unchecked(t: Tree) -> str:
    _compile(t.module, py_compile.PycInvalidationMode.UNCHECKED_HASH)
    return str(_pyc(t.module))


def _magic(t: Tree) -> str:
    p = _pyc(t.module)
    p.write_bytes(b"\x00\x00\r\n" + p.read_bytes()[4:])
    return str(p)


def _header(t: Tree) -> str:
    p = _pyc(t.module)
    p.write_bytes(p.read_bytes()[:7])
    return str(p)


def _edit_source(t: Tree) -> str:
    with t.module.open("a") as f:
        f.write("# edited\n")
    return str(_pyc(t.module))


def _body_truncated(t: Tree) -> str:
    p = _pyc(t.module)
    p.write_bytes(p.read_bytes()[:30])
    return str(p)


def _body_not_code(t: Tree) -> str:
    p = _pyc(t.module)
    p.write_bytes(p.read_bytes()[:16] + marshal.dumps({"not": "code"}))
    return str(p)


def _body_swapped(t: Tree) -> str:
    # Still a code object, still the right header: only a recompile can tell.
    p = _pyc(t.module)
    other = compile("def g():\n    return 2\n", "x", "exec")
    p.write_bytes(p.read_bytes()[:16] + marshal.dumps(other))
    return str(p)


def _source_invalid(t: Tree) -> str:
    # The header is regenerated so that only the syntax of the source is wrong.
    source = b"def broken(:\n"
    p = _pyc(t.module)
    t.module.write_bytes(source)
    p.write_bytes(p.read_bytes()[:8] + importlib.util.source_hash(source) + p.read_bytes()[16:])
    return str(t.module)


def _pyc_symlink(t: Tree) -> str:
    p = _pyc(t.module)
    real = p.with_suffix(".real")
    p.rename(real)
    p.symlink_to(real)
    real.rename(t.root / "elsewhere")
    p.unlink()
    p.symlink_to(t.root / "elsewhere")
    return str(p)


def _pycache_symlink(t: Tree) -> str:
    outside = t.root.parent / "outside"
    outside.mkdir()
    d = t.module.parent / "__pycache__"
    os.rename(d, outside / "moved")
    d.symlink_to(outside / "moved")
    return str(d)


def _dir_symlink(t: Tree) -> str:
    # Importable code that the walk would otherwise never see.
    outside = t.root.parent / "hidden"
    outside.mkdir()
    (outside / "uncompiled.py").write_text("X = 1\n")
    link = t.site / "hidden_pkg"
    link.symlink_to(outside)
    return str(link)


def _source_symlink(t: Tree) -> str:
    link = t.module.parent / "linked.py"
    link.symlink_to(t.module)
    return str(link)


def _orphan(t: Tree) -> str:
    p = t.module.parent / "__pycache__" / f"gone.{TAG}.pyc"
    p.write_bytes(_pyc(t.module).read_bytes())
    return str(p)


def _orphan_directory_namesake(t: Tree) -> str:
    # A directory named like the source does not make the bytecode legitimate.
    (t.module.parent / "gone.py").mkdir()
    return _orphan(t)


def _orphan_nested_cache(t: Tree) -> str:
    # A source placed inside __pycache__ must not legitimize a nested cache.
    outer = t.module.parent / "__pycache__"
    (outer / "x.py").write_text("X = 1\n")
    (outer / "__pycache__").mkdir()
    p = outer / "__pycache__" / f"x.{TAG}.pyc"
    p.write_bytes(_pyc(t.module).read_bytes())
    return str(p)


def _optimized(t: Tree) -> str:
    p = t.module.parent / "__pycache__" / f"mod.{TAG}.opt-1.pyc"
    p.write_bytes(_pyc(t.module).read_bytes())
    return str(p)


def _wrong_tag(t: Tree) -> str:
    p = t.module.parent / "__pycache__" / "mod.cpython-311.pyc"
    p.write_bytes(_pyc(t.module).read_bytes())
    return str(p)


def _temporary(t: Tree) -> str:
    p = t.module.parent / "__pycache__" / f"mod.{TAG}.pyc.140212"
    p.write_bytes(b"partial")
    return str(p)


def _sourceless(t: Tree) -> str:
    p = t.module.parent / "standalone.pyc"
    p.write_bytes(_pyc(t.module).read_bytes())
    return str(p)


def _outside(t: Tree) -> str:
    d = t.root / "src" / "__pycache__"
    d.mkdir()
    p = d / f"app.{TAG}.pyc"
    p.write_bytes(b"x")
    return str(p)


def _no_flag(t: Tree) -> str:
    return str(t.launcher(t.shebang("")))


def _extra_flag(t: Tree) -> str:
    return str(t.launcher(t.shebang(" -E")))


def _env_python(t: Tree) -> str:
    return str(t.launcher("#!/usr/bin/env python"))


def _unrewritten(t: Tree) -> str:
    return str(t.launcher("#!python"))


def _foreign(t: Tree) -> str:
    return str(t.launcher("#!/usr/bin/python3 -B"))


def _trampoline(t: Tree) -> str:
    return str(t.launcher(f"#!/bin/sh\n'''exec' '{t.bin}/python' \"$0\" \"$@\"\n' '''"))


def _shell(t: Tree) -> str:
    return str(t.launcher("#!/bin/sh"))


def _no_shebang(t: Tree) -> str:
    return str(t.launcher("import sys"))


def _activate_shebang(t: Tree) -> str:
    return str(t.launcher("#!/bin/sh", "activate"))


def _subdirectory(t: Tree) -> str:
    d = t.bin / "nested"
    d.mkdir()
    return str(d)


def _cli_symlinked_to_python(t: Tree) -> str:
    # It resolves to the interpreter, but runs as a bare interpreter without -B.
    (t.bin / "brandsentinel").unlink()
    link = t.bin / "brandsentinel"
    link.symlink_to("python")
    return str(link)


def _symlink_escape(t: Tree) -> str:
    link = t.bin / "tool"
    link.symlink_to("/bin/sh")
    return str(link)


MUTATIONS = {
    "missing": _delete,
    "not_checked_hash": _timestamp,
    "not_checked_hash ": _unchecked,
    "bad_magic": _magic,
    "bad_header": _header,
    "hash_mismatch": _edit_source,
    "bad_body": _body_truncated,
    "bad_body ": _body_not_code,
    "body_differs": _body_swapped,
    "source_invalid": _source_invalid,
    "pyc_not_regular": _pyc_symlink,
    "pycache_symlink": _pycache_symlink,
    "dir_symlink": _dir_symlink,
    "source_symlink": _source_symlink,
    "orphan": _orphan,
    "orphan ": _orphan_directory_namesake,
    "orphan  ": _orphan_nested_cache,
    "optimized": _optimized,
    "wrong_tag": _wrong_tag,
    "temporary": _temporary,
    "sourceless": _sourceless,
    "outside": _outside,
    "launcher_unhardened": _no_flag,
    "launcher_unknown": _extra_flag,
    "launcher_unknown ": _env_python,
    "launcher_unknown  ": _unrewritten,
    "launcher_unknown   ": _foreign,
    "launcher_unknown    ": _trampoline,
    "launcher_unknown     ": _shell,
    "launcher_unknown      ": _no_shebang,
    "launcher_unknown       ": _activate_shebang,
    "launcher_unknown        ": _subdirectory,
    "launcher_symlink": _symlink_escape,
    "launcher_symlink ": _cli_symlinked_to_python,
}


@pytest.mark.parametrize("key", list(MUTATIONS), ids=lambda k: MUTATIONS[k].__name__)
def test_each_damage_flips_a_passing_tree_to_a_named_violation(tree, key):
    expected_path = MUTATIONS[key](tree)
    report = cb.inspect_prefix(str(tree.root))
    assert report.exit_code == 1, report.render()
    assert (key.strip(), expected_path) in report.violations, report.render()


def test_every_rule_has_a_damage_case_that_triggers_it():
    assert {k.strip() for k in MUTATIONS} == set(cb.RULES)


def test_a_passing_report_counts_every_source_independently(tree):
    report = cb.inspect_prefix(str(tree.root))
    assert report.exit_code == 0
    assert report.sources == tree.sources() == 4
    assert report.launchers == 1
    assert report.native == 1


def test_inspection_writes_nothing(tree):
    def state():
        return sorted(
            (str(p), p.lstat().st_size, p.lstat().st_mtime_ns) for p in tree.root.rglob("*")
        )

    before = state()
    cb.inspect_prefix(str(tree.root))
    assert state() == before


def test_a_bytecode_free_unrelated_file_is_not_judged(tree):
    (tree.root / "src" / "notes.txt").write_text("hello")
    (tree.site / "brandsentinel" / "data.bin").write_bytes(b"\x00")
    (tree.root / "src" / "__pycache__").mkdir()  # empty: no bytecode in it
    assert cb.inspect_prefix(str(tree.root)).exit_code == 0


def _tree_root_symlink(t: Tree) -> None:
    moved = t.root.parent / "elsewhere-site"
    t.site.rename(moved)
    t.site.symlink_to(moved)


@pytest.mark.parametrize(
    "damage",
    [
        pytest.param(lambda t: (t.root / "venv" / "pyvenv.cfg").unlink(), id="no-pyvenv-cfg"),
        pytest.param(
            lambda t: (t.root / "venv" / "pyvenv.cfg").write_text("version = 3.12\n"), id="no-home"
        ),
        pytest.param(
            lambda t: (t.root / "venv" / "pyvenv.cfg").write_text("home = /usr/bin\n"),
            id="stdlib-outside-prefix",
        ),
        pytest.param(lambda t: (t.std / "os.py").unlink(), id="no-stdlib-sentinel"),
        pytest.param(
            lambda t: (t.site / "brandsentinel" / "__init__.py").unlink(), id="no-package-sentinel"
        ),
        pytest.param(lambda t: (t.bin / "brandsentinel").unlink(), id="no-cli-launcher"),
        pytest.param(lambda t: (t.bin / "python").unlink(), id="no-interpreter"),
        pytest.param(lambda t: shutil.rmtree(t.site), id="no-site-packages"),
        pytest.param(lambda t: shutil.rmtree(t.std), id="no-stdlib"),
        pytest.param(_tree_root_symlink, id="site-packages-is-a-symlink"),
    ],
)
def test_a_tree_that_cannot_be_evaluated_exits_2(tree, damage):
    damage(tree)
    report = cb.inspect_prefix(str(tree.root))
    assert report.exit_code == 2, report.render()
    assert report.incomplete


def test_a_prefix_reached_through_a_symlink_passes(tree):
    link = tree.root.parent / "current"
    link.symlink_to(tree.root)
    (tree.bin / "brandsentinel").write_text(f"#!{link}/venv/bin/python -B\nimport sys\n")
    assert cb.inspect_prefix(str(link)).exit_code == 0


def test_no_cache_tag_is_incomplete(tree, monkeypatch):
    monkeypatch.setattr(cb.sys, "implementation", types.SimpleNamespace(cache_tag=None))
    assert cb.inspect_prefix(str(tree.root)).exit_code == 2


def test_an_unlistable_bin_directory_is_incomplete(tree, monkeypatch):
    def denied(_path):
        raise PermissionError(13, "denied")

    monkeypatch.setattr(cb.os, "scandir", denied)
    assert cb.inspect_prefix(str(tree.root)).exit_code == 2


def test_a_symlinked_pycache_is_not_read_through(tree, monkeypatch):
    _pycache_symlink(tree)
    opened = []
    real = open

    def spying(path, *a, **k):
        opened.append(str(path))
        return real(path, *a, **k)

    monkeypatch.setattr("builtins.open", spying)
    report = cb.inspect_prefix(str(tree.root))
    assert report.exit_code == 1
    assert not [p for p in opened if "__pycache__" in p and "brandsentinel" in p]


def test_a_missing_prefix_exits_2(tmp_path):
    assert cb.inspect_prefix(str(tmp_path / "absent")).exit_code == 2


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory modes")
def test_an_unreadable_directory_is_incomplete_not_a_pass(tree):
    target = tree.root / "src"
    target.chmod(0)
    try:
        report = cb.inspect_prefix(str(tree.root))
    finally:
        target.chmod(0o755)
    assert report.exit_code == 2, report.render()


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file modes")
@pytest.mark.parametrize("which", ["source", "pyc", "launcher"])
def test_an_unreadable_file_is_incomplete_not_a_pass(tree, which):
    target = {
        "source": tree.module,
        "pyc": _pyc(tree.module),
        "launcher": tree.bin / "brandsentinel",
    }[which]
    target.chmod(0)
    try:
        report = cb.inspect_prefix(str(tree.root))
    finally:
        target.chmod(0o644)
    assert report.exit_code == 2, report.render()


def test_a_walk_error_is_incomplete_even_with_nothing_else_wrong(tree, monkeypatch):
    real = os.walk

    def failing(top, *a, onerror=None, **k):
        onerror(PermissionError(13, "denied", str(tree.root / "src")))
        yield from real(top, *a, onerror=onerror, **k)

    monkeypatch.setattr(cb.os, "walk", failing)
    report = cb.inspect_prefix(str(tree.root))
    assert report.exit_code == 2, report.render()


def test_incomplete_outranks_violations(tree):
    _delete(tree)
    (tree.bin / "python").unlink()
    report = cb.inspect_prefix(str(tree.root))
    assert report.violations
    assert report.exit_code == 2


def test_an_unexpected_exception_exits_2_through_main(tree, monkeypatch, capsys):
    def boom(_prefix):
        raise RuntimeError("secret detail")

    monkeypatch.setattr(cb, "inspect_prefix", boom)
    monkeypatch.setattr(cb, "_interpreter_problem", lambda _p: None)
    assert cb.main([str(tree.root)]) == 2
    out = capsys.readouterr().out
    assert "RuntimeError" in out
    assert "secret detail" not in out


def test_the_report_is_bounded_and_escapes_paths(tree):
    for i in range(cb.MAX_LISTED + 5):
        (tree.module.parent / "__pycache__" / f"o{i}.{TAG}.pyc").write_bytes(b"x")
    (tree.module.parent / "__pycache__" / f"evil\x1b[31m.{TAG}.pyc").write_bytes(b"x")
    text = cb.inspect_prefix(str(tree.root)).render()
    assert sum(1 for line in text.splitlines() if line.startswith("VIOLATION")) == cb.MAX_LISTED
    assert "more" in text
    assert "\x1b" not in text


def _cli(*args, python=sys.executable):
    return subprocess.run(  # noqa: S603 - fixed argv
        [python, *args], capture_output=True, text=True, timeout=30, check=False
    )


def test_the_wrong_interpreter_exits_2(tree):
    done = _cli("-I", "-B", "-S", str(SCRIPT), str(tree.root))
    assert done.returncode == 2, done.stdout + done.stderr
    assert "interpreter" in done.stdout


def test_running_without_bytecode_writes_disabled_exits_2(tree):
    done = _cli("-I", "-S", str(SCRIPT), str(tree.root))
    assert done.returncode == 2, done.stdout + done.stderr


@pytest.mark.parametrize("argv", [[], ["a", "b"]])
def test_bad_usage_exits_2(argv):
    done = _cli("-I", "-B", "-S", str(SCRIPT), *argv)
    assert done.returncode == 2

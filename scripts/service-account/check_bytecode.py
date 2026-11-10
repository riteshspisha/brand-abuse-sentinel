"""Verify the bytecode and launchers of an installation, without changing anything.

    <prefix>/venv/bin/python -I -B -S check_bytecode.py <prefix>

Exit codes: 0 every check passed; 1 violations; 2 the inspection is incomplete, so
nothing can be concluded. An incomplete inspection outranks violations, and any
failure to look counts as incomplete, never as a pass.

What a pass means: each source in the virtual environment's site-packages and the
bundled standard library has exactly the checked-hash bytecode compiled from it, there
is no other bytecode under the prefix, and every console script starts Python with
bytecode writing off. It does not mean that the installation is immutable or unmodified,
or that no root process has run: a root run through a hardened launcher leaves no trace.
Only bytecode and launchers are judged. Other files are not inventoried.

Uses only modules that are available with -S, and executes nothing that it reads.
"""

import importlib.util
import marshal
import os
import stat
import sys
import types

MAX_LISTED = 50

RULES = {
    "missing": "a source has no bytecode for this interpreter",
    "pyc_not_regular": "the bytecode is not a regular file",
    "bad_header": "the bytecode is shorter than its header",
    "bad_magic": "the bytecode is for another interpreter version",
    "not_checked_hash": "the bytecode is not checked-hash",
    "hash_mismatch": "the source changed since it was compiled",
    "bad_body": "the bytecode body does not load as a code object",
    "body_differs": "the bytecode body was not compiled from this source",
    "source_invalid": "the source does not compile",
    "source_symlink": "a source is not a regular file",
    "pycache_symlink": "a __pycache__ directory is a symlink",
    "dir_symlink": "a directory inside a compiled tree is a symlink",
    "orphan": "bytecode with no source",
    "optimized": "bytecode for an optimization level",
    "wrong_tag": "bytecode for another interpreter's cache tag",
    "temporary": "the leftover of an interrupted bytecode write",
    "sourceless": "bytecode outside __pycache__",
    "outside": "bytecode outside the compiled trees",
    "launcher_unhardened": "a console script without -B",
    "launcher_unknown": "a file in venv/bin that is not a recognized launcher",
    "launcher_symlink": "a venv/bin symlink that is not the installed interpreter",
}

# Installed by the virtual environment itself. None of them start Python.
ACTIVATION_FILES = frozenset(
    {
        "activate",
        "activate.bat",
        "activate.csh",
        "activate.fish",
        "activate.nu",
        "activate.ps1",
        "activate.xsh",
        "activate_this.py",
        "deactivate.bat",
        "pydoc.bat",
    }
)
HEADER_SIZE = 16
CHECKED_HASH_FLAGS = 0b11


class Report:
    def __init__(self, root: str) -> None:
        self.root = root
        self.violations: list[tuple[str, str]] = []
        self.incomplete: list[str] = []
        self.sources = 0
        self.launchers = 0
        self.native = 0

    def violation(self, rule: str, path: str) -> None:
        if rule not in RULES:
            raise ValueError(rule)
        self.violations.append((rule, path))

    def cannot_evaluate(self, reason: str) -> None:
        self.incomplete.append(reason)

    @property
    def exit_code(self) -> int:
        if self.incomplete:
            return 2
        return 1 if self.violations else 0

    def _shown(self, path: str) -> str:
        relative = os.path.relpath(path, self.root) if os.path.isabs(path) else path
        return ascii(relative)[1:-1]

    def render(self) -> str:
        lines = [f"INCOMPLETE {self._shown(reason)}" for reason in self.incomplete[:MAX_LISTED]]
        lines += [
            f"VIOLATION {rule} {self._shown(path)}" for rule, path in self.violations[:MAX_LISTED]
        ]
        for kind, items in (("incomplete", self.incomplete), ("violations", self.violations)):
            if len(items) > MAX_LISTED:
                lines.append(f"... and {len(items) - MAX_LISTED} more {kind}")
        verdict = {0: "PASS", 1: "FAIL", 2: "INCOMPLETE"}[self.exit_code]
        lines.append(
            f"bytecode check: {verdict} sources={self.sources} launchers={self.launchers} "
            f"native={self.native} violations={len(self.violations)} "
            f"incomplete={len(self.incomplete)}"
        )
        return "\n".join(lines)


def _inside(path: str, root: str) -> bool:
    return path.startswith(root + os.sep)


def _read(path: str, report: Report, limit: int = -1) -> bytes | None:
    try:
        with open(path, "rb") as handle:
            return handle.read(limit)
    except OSError:
        report.cannot_evaluate(f"unreadable: {path}")
        return None


def _layout(root: str, report: Report) -> tuple[str, str] | None:
    """Return the two compiled trees: the standard library and site-packages."""
    version = f"python{sys.version_info[0]}.{sys.version_info[1]}"
    config = _read(os.path.join(root, "venv", "pyvenv.cfg"), report)
    if config is None:
        return None
    home = None
    for line in config.decode("utf-8", "surrogateescape").splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "home":
            home = value.strip()
    if not home:
        report.cannot_evaluate("venv/pyvenv.cfg names no interpreter home")
        return None
    real_home = os.path.realpath(home)
    if not _inside(real_home, root):
        report.cannot_evaluate("the interpreter home is outside the prefix")
        return None
    stdlib = os.path.join(os.path.dirname(real_home), "lib", version)
    site = os.path.join(root, "venv", "lib", version, "site-packages")
    for tree in (stdlib, site):
        if not os.path.isdir(tree):
            report.cannot_evaluate(f"missing tree: {tree}")
            return None
        if os.path.realpath(tree) != tree:
            report.cannot_evaluate(f"a compiled tree is reached through a symlink: {tree}")
            return None
    return stdlib, site


def _check_launchers(root: str, given: str, report: Report) -> None:
    bin_dir = os.path.join(root, "venv", "bin")
    interpreter = os.path.realpath(os.path.join(bin_dir, "python"))
    if not os.path.isfile(interpreter) or not _inside(interpreter, root):
        report.cannot_evaluate("venv/bin/python is not an interpreter inside the prefix")
        return
    names = ("python", "python3", f"python{sys.version_info[0]}.{sys.version_info[1]}")
    plain = {f"#!{base}/venv/bin/{name}" for base in (root, given) for name in names}
    hardened = {f"{line} -B" for line in plain}
    try:
        entries = sorted(os.scandir(bin_dir), key=lambda entry: entry.name)
    except OSError:
        report.cannot_evaluate("venv/bin cannot be listed")
        return
    found_cli = False
    for entry in entries:
        if entry.name == "brandsentinel":
            found_cli = True
        if entry.is_symlink():
            if entry.name not in names or os.path.realpath(entry.path) != interpreter:
                report.violation("launcher_symlink", entry.path)
            continue
        if not entry.is_file(follow_symlinks=False):
            report.violation("launcher_unknown", entry.path)
            continue
        head = _read(entry.path, report, 4096)
        if head is None:
            continue
        if head.startswith(b"\x7fELF"):
            report.native += 1
        elif head.startswith(b"#!"):
            first = head.split(b"\n", 1)[0].decode("utf-8", "surrogateescape")
            if first in hardened:
                report.launchers += 1
            elif first in plain:
                report.violation("launcher_unhardened", entry.path)
            else:
                report.violation("launcher_unknown", entry.path)
        elif entry.name not in ACTIVATION_FILES:
            report.violation("launcher_unknown", entry.path)
    if not found_cli:
        report.cannot_evaluate("venv/bin/brandsentinel is missing")


def _check_source(path: str, tag: str, report: Report) -> None:
    report.sources += 1
    directory, name = os.path.split(path)
    cache_dir = os.path.join(directory, "__pycache__")
    if os.path.islink(cache_dir):
        return  # reported by the walk, and never read through
    cached = os.path.join(cache_dir, f"{name[:-3]}.{tag}.pyc")
    try:
        info = os.lstat(cached)
    except FileNotFoundError:
        report.violation("missing", path)
        return
    except OSError:
        report.cannot_evaluate(f"cannot inspect: {cached}")
        return
    if not stat.S_ISREG(info.st_mode):
        report.violation("pyc_not_regular", cached)
        return
    data = _read(cached, report)
    source = _read(path, report)
    if data is None or source is None:
        return
    if len(data) < HEADER_SIZE:
        report.violation("bad_header", cached)
    elif data[:4] != importlib.util.MAGIC_NUMBER:
        report.violation("bad_magic", cached)
    elif int.from_bytes(data[4:8], "little") != CHECKED_HASH_FLAGS:
        report.violation("not_checked_hash", cached)
    elif data[8:16] != importlib.util.source_hash(source):
        report.violation("hash_mismatch", cached)
    else:
        _check_body(path, cached, source, data[HEADER_SIZE:], report)


def _check_body(path: str, cached: str, source: bytes, body: bytes, report: Report) -> None:
    try:
        stored = marshal.loads(body)  # noqa: S302 - loaded to compare, never executed
    except (EOFError, ValueError, TypeError):
        report.violation("bad_body", cached)
        return
    if not isinstance(stored, types.CodeType):
        report.violation("bad_body", cached)
        return
    try:
        expected = compile(source, path, "exec", dont_inherit=True, optimize=0)
    except (SyntaxError, ValueError):
        report.violation("source_invalid", path)
        return
    if stored != expected:
        report.violation("body_differs", cached)


def _is_regular(path: str) -> bool:
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


def _check_cached_file(directory: str, name: str, path: str, tag: str, report: Report) -> None:
    """Judge one .pyc inside a __pycache__ of a compiled tree."""
    parts = name[: -len(".pyc")].split(".")
    if parts[-1].startswith("opt-"):
        report.violation("optimized", path)
    elif len(parts) < 2 or os.path.basename(os.path.dirname(directory)) == "__pycache__":
        report.violation("orphan", path)
    elif parts[-1] != tag:
        report.violation("wrong_tag", path)
    elif not _is_regular(os.path.join(os.path.dirname(directory), ".".join(parts[:-1]) + ".py")):
        report.violation("orphan", path)


def _is_bytecode_name(name: str) -> bool:
    return name.endswith((".pyc", ".pyo")) or ".pyc." in name or ".pyo." in name


def _walk(root: str, trees: tuple[str, str], tag: str, report: Report) -> None:
    def on_error(error: OSError) -> None:
        report.cannot_evaluate(f"cannot list: {error.filename}")

    for directory, subdirs, files in os.walk(root, onerror=on_error):
        compiled = any(directory == tree or _inside(directory, tree) for tree in trees)
        for name in subdirs:
            path = os.path.join(directory, name)
            if name == "__pycache__" and os.path.islink(path):
                report.violation("pycache_symlink", path)
            elif compiled and os.path.islink(path):
                report.violation("dir_symlink", path)
        in_cache = os.path.basename(directory) == "__pycache__"
        for name in files:
            path = os.path.join(directory, name)
            if _is_bytecode_name(name):
                if not compiled:
                    report.violation("outside", path)
                elif not name.endswith((".pyc", ".pyo")):
                    report.violation("temporary", path)
                elif in_cache and name.endswith(".pyc"):
                    _check_cached_file(directory, name, path, tag, report)
                else:
                    report.violation("sourceless", path)
            elif compiled and not in_cache and name.endswith(".py"):
                try:
                    regular = stat.S_ISREG(os.lstat(path).st_mode)
                except OSError:
                    report.cannot_evaluate(f"cannot inspect: {path}")
                    continue
                if regular:
                    _check_source(path, tag, report)
                else:
                    report.violation("source_symlink", path)


def inspect_prefix(prefix: str) -> Report:
    root = os.path.realpath(prefix)
    report = Report(root)
    tag = sys.implementation.cache_tag
    if not os.path.isdir(root):
        report.cannot_evaluate("the prefix is not a directory")
        return report
    if not tag:
        report.cannot_evaluate("this interpreter has no cache tag")
        return report
    trees = _layout(root, report)
    if trees is None:
        return report
    _check_launchers(root, os.path.abspath(prefix), report)
    _walk(root, trees, tag, report)
    stdlib, site = trees
    if not os.path.isfile(os.path.join(stdlib, "os.py")):
        report.cannot_evaluate("the standard library has no os.py")
    if not os.path.isfile(os.path.join(site, "brandsentinel", "__init__.py")):
        report.cannot_evaluate("site-packages has no brandsentinel package")
    if report.sources == 0:
        report.cannot_evaluate("no source files were inspected")
    return report


def _interpreter_problem(prefix: str) -> str | None:
    if not sys.dont_write_bytecode:
        return "run with -B: the check must not write bytecode itself"
    expected = os.path.realpath(os.path.join(prefix, "venv", "bin", "python"))
    if os.path.realpath(sys.executable) != expected:
        return "run with the installation's own interpreter"
    return None


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: check_bytecode.py <prefix>")
        return 2
    try:
        problem = _interpreter_problem(argv[0])
        if problem:
            print(f"INCOMPLETE {problem}")
            print("bytecode check: INCOMPLETE")
            return 2
        report = inspect_prefix(argv[0])
        print(report.render())
        return report.exit_code
    except Exception as error:  # any failure to look must not read as a pass
        print(f"INCOMPLETE internal error: {type(error).__name__}")
        print("bytecode check: INCOMPLETE")
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

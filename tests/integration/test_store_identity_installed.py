"""Production-store enforcement on a realistic scratch installation (B3).

A copy of the running interpreter, a real `venv`, the package and its imported
dependencies under `<P>/venv/lib/pythonX.Y/site-packages`, and an `INSTALL` record, in a
world-readable directory under /tmp. Two kinds of test:

- **installed layout:** the real interpreter prefix, `sys.path` and package location,
  with the trusted owner patched to the test's UID (the files are the test's own);
- **user namespace, real ownership:** `unshare --map-root-user --map-auto` makes the
  test's files root-owned inside the namespace. `setpriv` then runs the CLI as a mapped
  non-zero account with the trusted UID left at 0 and `check_account` unpatched. Only
  the anchor's location is patched, because the host's /etc cannot be written. Where
  user namespaces with subordinate IDs are unavailable these skip, unless
  `REQUIRE_USERNS=1`, which makes a skip an acceptance failure.
"""

import os
import pwd
import shutil
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.installed_layout

REPO = Path(__file__).resolve().parents[2]
VER = f"python{sys.version_info[0]}.{sys.version_info[1]}"
ME = os.getuid()
MY_NAME = pwd.getpwuid(ME).pw_name
CLEAN_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C.UTF-8"}
STORE_REFUSAL = "refusing to open a store:"
ROOT_REFUSAL = "refusing to open a store as root"
NS = ["unshare", "--map-root-user", "--map-auto"]
OTHER_UID = 4321  # a mapped namespace UID that is not the account


def _run(argv, *, cwd: Path, env: dict | None = None, timeout: int = 120):
    return subprocess.run(  # noqa: S603 - fixed argv built by the test
        [str(a) for a in argv],
        cwd=cwd,
        env=CLEAN_ENV if env is None else env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _dependency_closure() -> list[str]:
    """Top-level names in this venv's site-packages that the CLI imports."""
    program = (
        "import sys, sysconfig\n"
        "sp = sysconfig.get_paths()['purelib']\n"
        "import importlib, pkgutil, brandsentinel\n"
        "for m in pkgutil.walk_packages(brandsentinel.__path__, 'brandsentinel.'):\n"
        "    if not m.name.endswith('_worker'):\n"
        "        importlib.import_module(m.name)\n"
        "tops = set()\n"
        "for m in list(sys.modules.values()):\n"
        "    f = getattr(m, '__file__', None) or ''\n"
        "    if f.startswith(sp + '/'):\n"
        "        tops.add(f[len(sp) + 1:].split('/')[0])\n"
        "print('\\n'.join(sorted(tops)))\n"
    )
    done = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, "-B", "-c", program], capture_output=True, text=True, check=True
    )
    return [t for t in done.stdout.split() if t and not t.startswith("_virtualenv")]


class Install:
    """The scratch installation and the files around it."""

    def __init__(self, base: Path) -> None:
        self.base = base
        self.prefix = base / "opt"
        source = Path(sys.base_prefix).resolve()
        home = self.prefix / "python" / source.name
        shutil.copytree(
            source, home, symlinks=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
        )
        made = _run(
            [home / "bin" / VER, "-m", "venv", "--without-pip", self.prefix / "venv"], cwd=base
        )
        assert made.returncode == 0, made.stderr
        self.python = self.prefix / "venv" / "bin" / "python"
        self.base_python = home / "bin" / VER
        self.site = self.prefix / "venv" / "lib" / VER / "site-packages"
        here = Path(sysconfig.get_paths()["purelib"])
        for top in _dependency_closure():
            src = here / top
            (shutil.copytree if src.is_dir() else shutil.copy2)(src, self.site / top)
        for info in here.glob("*.dist-info"):
            if not info.name.startswith("brandsentinel"):
                shutil.copytree(info, self.site / info.name)
        shutil.copytree(
            REPO / "src" / "brandsentinel",
            self.site / "brandsentinel",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        (self.prefix / "INSTALL").write_text("commit: scratch\n")
        # The approved configuration and the anchor chain.
        self.etc = self.prefix / "etc"
        self.etc.mkdir()
        self.config = self.etc / "service.yaml"
        self.root = base / "root"
        self.anchor = self.root / "etc" / "brandsentinel" / "production.yaml"
        self.anchor.parent.mkdir(parents=True)
        for d in (base, self.root, self.root / "etc", self.anchor.parent, self.etc):
            d.chmod(0o755)
        for p in [self.prefix, *self.prefix.rglob("*")]:
            if p.is_dir() and not p.is_symlink():
                p.chmod(p.stat().st_mode | 0o755)

    def configure(self, store: Path, *, account: str) -> None:
        data = {
            "data_dir": str(store),
            "registry_path": str(self.site / "x" / "brands.yaml"),
            "analysis": {
                "policy": "/nonexistent/policy.yaml",
                "payment_providers": "/nonexistent/p.yaml",
            },
            "discovery": {
                "certstream": {"enabled": False},
                "dnstwist": {"enabled": False, "dictionary": "/nonexistent/d.dict"},
            },
            "sandbox": {"enabled": False},
        }
        if self.config.exists():
            self.config.chmod(0o644)
        self.config.write_text(yaml.safe_dump(data), encoding="utf-8")
        self.config.chmod(0o444)
        if self.anchor.exists():
            self.anchor.chmod(0o644)
        self.anchor.write_text(
            f"account: {account}\nstore_path: {store}\nconfig_path: {self.config}\n"
            f"install_prefix: {self.prefix}\ncomplete: true\n"
        )
        self.anchor.chmod(0o644)

    def program(self, *, trusted_uid: int | None, clean_account: bool) -> str:
        lines = [
            "from pathlib import Path",
            "from brandsentinel.store import identity",
            f"identity.CHAIN_ROOT = Path({str(self.root)!r})",
            f"identity.ANCHOR_PATH = Path({str(self.anchor)!r})",
        ]
        if trusted_uid is not None:
            lines.append(f"identity.TRUSTED_UID = {trusted_uid}")
        if clean_account:
            lines += [
                "from brandsentinel.sandbox import preflight",
                "preflight.check_account = lambda *a, **k: preflight.Report()",
            ]
        lines += ["from brandsentinel.cli import app", "app()"]
        return "\n".join(lines)


def _tree(root: Path) -> list[tuple[str, int]]:
    out = []
    for p in sorted(root.rglob("*")):
        try:
            out.append((str(p.relative_to(root)), p.lstat().st_mtime_ns))
        except OSError:
            out.append((str(p.relative_to(root)), -1))
    return out


@pytest.fixture(scope="module")
def install():
    if not Path(sys.base_prefix).is_dir():
        pytest.skip("the running interpreter cannot be copied")
    base = Path(tempfile.mkdtemp(prefix="bs-b3-", dir="/tmp"))
    try:
        yield Install(base)
    finally:
        # The namespace tests leave files owned by a subordinate UID; remove them there.
        if _userns_works():
            _run([*NS, "rm", "-rf", "--one-file-system", base], cwd=Path("/"))
        shutil.rmtree(base, ignore_errors=True)


def _userns_works() -> bool:
    if shutil.which("unshare") is None or shutil.which("setpriv") is None:
        return False
    return _run([*NS, "true"], cwd=Path("/")).returncode == 0


# --- installed layout (simulated root ownership) ---------------------------------------


def _store(install: Install, name: str) -> Path:
    store = install.base / name / "data"
    store.mkdir(parents=True, exist_ok=True)
    return store


def test_installed_code_without_an_anchor_refuses(install):
    """R2 (M18): the record beside sys.prefix, with the real interpreter layout."""
    install.anchor.unlink(missing_ok=True)
    scratch = _store(install, "scratch-a")
    config = install.base / "scratch-a.yaml"
    config.write_text(yaml.safe_dump({"data_dir": str(scratch)}))
    program = install.program(trusted_uid=ME, clean_account=False)
    before = _tree(scratch)
    done = _run(
        [install.python, "-I", "-B", "-c", program, "-c", config, "store", "check"],
        cwd=install.base,
    )
    assert done.returncode == 2, done.stdout + done.stderr
    assert done.stderr.strip() == f"{STORE_REFUSAL} anchor_missing"
    assert _tree(scratch) == before


def test_another_interpreter_importing_the_installed_package_is_still_installed(install):
    """R2: the base interpreter's sys.prefix has no record; the package directory does."""
    install.anchor.unlink(missing_ok=True)
    scratch = _store(install, "scratch-b")
    config = install.base / "scratch-b.yaml"
    config.write_text(yaml.safe_dump({"data_dir": str(scratch)}))
    program = f"import sys; sys.path.insert(0, {str(install.site)!r})\n" + install.program(
        trusted_uid=ME, clean_account=False
    )
    done = _run(
        [install.base_python, "-I", "-B", "-c", program, "-c", config, "store", "check"],
        cwd=install.base,
    )
    assert done.returncode == 2, done.stdout + done.stderr
    assert done.stderr.strip() == f"{STORE_REFUSAL} anchor_missing"


def test_the_installed_layout_passes_the_policy(install):
    """sys.path, the package directory and the INSTALL record are the real ones."""
    store = _store(install, "live")
    install.configure(store, account=MY_NAME)
    program = install.program(trusted_uid=ME, clean_account=True)
    before = _tree(install.base / "live")
    done = _run(
        [install.python, "-I", "-B", "-c", program, "-c", install.config, "store", "check"],
        cwd=install.base,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert "store class: production (anchor path)" in done.stdout
    assert _tree(install.base / "live") == before


def test_a_working_directory_on_sys_path_is_refused(install):
    """`python -c`/`-m` without -I puts the working directory first (M10)."""
    store = _store(install, "live")
    install.configure(store, account=MY_NAME)
    program = install.program(trusted_uid=ME, clean_account=True)
    elsewhere = install.base / "elsewhere"
    elsewhere.mkdir(exist_ok=True)
    done = _run(
        [install.python, "-B", "-c", program, "-c", install.config, "store", "check"],
        cwd=elsewhere,
    )
    assert done.returncode == 2, done.stdout + done.stderr
    assert done.stderr.strip() == f"{STORE_REFUSAL} python_env_set"


def test_pythonpath_is_refused(install):
    store = _store(install, "live")
    install.configure(store, account=MY_NAME)
    program = install.program(trusted_uid=ME, clean_account=True)
    env = {**CLEAN_ENV, "PYTHONPATH": str(install.base / "elsewhere")}
    done = _run(
        [install.python, "-B", "-c", program, "-c", install.config, "store", "check"],
        cwd=install.prefix,
        env=env,
    )
    assert done.returncode == 2, done.stdout + done.stderr
    assert done.stderr.strip() == f"{STORE_REFUSAL} python_env_set"


def test_the_checkout_on_the_same_host_is_not_installed_code(install, tmp_path):
    """The developer's checkout with the installation present but no anchor: development."""
    install.anchor.unlink(missing_ok=True)
    config = tmp_path / "c.yaml"
    config.write_text(yaml.safe_dump({"data_dir": str(tmp_path / "s")}))
    program = install.program(trusted_uid=ME, clean_account=False)
    done = _run(
        [sys.executable, "-B", "-c", program, "-c", config, "store", "check"],
        cwd=tmp_path,
        env={**CLEAN_ENV},
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert "store class: development (none)" in done.stdout


# --- user namespace, real ownership ----------------------------------------------------


@pytest.fixture(scope="module")
def ns(install):
    """The account's store under a 0700 home owned by the mapped account UID."""
    if not _userns_works():
        if os.environ.get("REQUIRE_USERNS"):
            pytest.fail("user namespaces with subordinate IDs are unavailable")
        pytest.skip("user namespaces with subordinate IDs are unavailable")
    if ME == 0 or ME > 65536:
        pytest.skip("the account UID must be mappable inside the namespace")
    home = install.base / "ns-home"
    store = home / "data"
    store.mkdir(parents=True)
    install.configure(store, account=MY_NAME)
    owned = _run(
        [*NS, "sh", "-c", f'chown -R {ME}:{ME} "$1" && chmod 0700 "$1"', "sh", home],
        cwd=install.base,
    )
    assert owned.returncode == 0, owned.stderr
    return store


def _as(uid: int | None, install: Install, *cli: str):
    program = install.program(trusted_uid=None, clean_account=False)
    run = [install.python, "-I", "-B", "-c", program, "-c", install.config, *cli]
    if uid is not None:
        run = ["setpriv", f"--reuid={uid}", f"--regid={uid}", "--clear-groups", *run]
    return _run([*NS, *run], cwd=install.base)


def test_real_ownership_the_account_passes_store_check(install, ns):
    """Root-owned anchor, chain, prefix and configuration; unpatched trusted UID and
    account checks; the account itself (AE9 on a real ownership layout)."""
    done = _as(ME, install, "store", "check")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "store class: production (anchor path)" in done.stdout


def test_real_ownership_the_account_opens_the_store(install, ns):
    done = _as(ME, install, "status")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "store class: production (anchor path)" in done.stdout


def test_real_ownership_another_account_is_refused_by_the_path(install, ns):
    """AE1: the home is 0700; the refusal names the account and nothing else."""
    done = _as(OTHER_UID, install, "cases", "list")
    assert done.returncode == 2, done.stdout + done.stderr
    assert done.stderr.strip().startswith(f"{STORE_REFUSAL} wrong_account")
    assert "store_missing" not in done.stderr


def test_real_ownership_root_is_refused(install, ns):
    """A real effective and real UID of 0 (namespace root)."""
    done = _as(None, install, "status")
    assert done.returncode == 2, done.stdout + done.stderr
    assert done.stderr.startswith(ROOT_REFUSAL)


@pytest.mark.parametrize(
    "cli",
    [
        ["sandbox", "sweep"],
        ["sandbox", "check", "--no-network"],
        ["sandbox", "selftest", "media"],
        ["proxy", "--listen", "127.0.0.1:1"],
    ],
    ids=["sandbox-sweep", "sandbox-check", "sandbox-selftest", "proxy"],
)
def test_real_ownership_root_is_refused_for_daemon_commands(install, ns, cli):
    done = _as(None, install, *cli)
    assert done.returncode == 2, done.stdout + done.stderr
    assert done.stderr.startswith(ROOT_REFUSAL)

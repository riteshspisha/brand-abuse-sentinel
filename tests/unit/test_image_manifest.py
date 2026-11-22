"""The sandbox-image verifier (scripts/service-account/image_manifest.py; B7 PR-2).

A real virtual environment stands in for the image: the verifier's in-image script runs
for real under that environment's interpreter, and only the `docker` and `uv` calls are
faked. Every damage case starts from a world asserted to pass and must flip the
verdict, and a completeness test ties each rule to a case.
"""

import base64
import csv
import dis
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import marshal
import os
import py_compile
import shutil
import signal
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).parents[2]
SCRIPT = REPO / "scripts" / "service-account" / "image_manifest.py"


def _load():
    spec = importlib.util.spec_from_file_location("image_manifest", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["image_manifest"] = module
    spec.loader.exec_module(module)
    return module


im = _load()
REAL_RUN_COMMAND = im.run_command  # before any fixture replaces it

FILES = {
    "__init__.py": b'"""The package."""\n',
    # Two LOAD_CONSTs in a row (a superinstruction target) and a BINARY_OP.
    "cli.py": b"def app(x=0):\n    return min(100, 1) + x\n",
    "store/__init__.py": b"",
    # Code shapes the field-by-field comparison must cover: a closure, keyword-only
    # arguments, an exception table, an assert, tuple/-0.0/frozenset constants, and
    # interleaved local and cell slots.
    "store/ops.py": (
        b"def outer(a, /, b=0, *, key=1):\n"
        b"    total = (1, (2, 3))\n"
        b"    neg = -0.0\n"
        b"    def inner():\n"
        b"        return a + key\n"
        b"    try:\n"
        b"        assert a >= 0, 'negative'\n"
        b"        return inner() if a in {'x', 'y'} or a else (total, neg, b)\n"
        b"    except ZeroDivisionError:\n"
        b"        return None\n"
    ),
    "store/slots.py": (
        b"def f():\n    aa = 'safe'\n    bb = 'other'\n    cc = 'cell'\n"
        b"    gg = lambda: cc\n"
        b"    return sorted((k, type(v).__name__) for k, v in locals().items())\n"
    ),
    "store/migrations/0001.sql": b"create table t (x);\n",
    "report/page.html.j2": b"<p>{{ x }}</p>\n",
    "sandbox/chromium-seccomp.json": b'{"defaultAction": "SCMP_ACT_ERRNO"}\n',
    "sandbox/selftest/README.md": b"# fixtures\n",
    "sandbox/selftest/ocr-donate.png": b"\x89PNG\r\n\x1a\n" + bytes(range(64)),
}
SOURCES = sorted(rel for rel in FILES if rel.endswith(".py"))
DIST = "brandsentinel-0.2.1.dist-info"
WHEEL_META = {
    "METADATA": b"Metadata-Version: 2.4\nName: brandsentinel\nVersion: 0.2.1\n",
    "WHEEL": b"Wheel-Version: 1.0\nGenerator: hatchling 1.32.4\nRoot-Is-Purelib: true\n"
    b"Tag: py3-none-any\n",
    "entry_points.txt": b"[console_scripts]\nbrandsentinel = brandsentinel.cli:app\n",
}
PINS = (
    "dep-a==1.0\ndep-c==3.0 ; sys_platform == 'linux'\ncolorama==0.4.6 ; sys_platform == 'win32'\n"
)
IMAGE_ID = "sha256:" + "ab" * 32
TAG = sys.implementation.cache_tag


def record_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def write_record(path: Path, rows: dict[str, bytes]) -> None:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    for name, data in rows.items():
        writer.writerow([name, record_hash(data), len(data)])
    writer.writerow([path.parent.name + "/RECORD", "", ""])
    path.write_text(out.getvalue())


def dist(
    site: Path,
    name: str,
    version: str,
    dirname: str | None = None,
    module: bool = True,
    record: bool = True,
) -> Path:
    """A distribution as pip leaves it: dist-info with METADATA and a RECORD owning its
    files, and (by default) a top-level module of its import name."""
    d = site / (dirname or f"{name.replace('-', '_')}-{version}.dist-info")
    d.mkdir()
    meta = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n".encode()
    (d / "METADATA").write_bytes(meta)
    rows = {f"{d.name}/METADATA": meta}
    if module:
        mod = site / f"{name.replace('-', '_').lower()}.py"
        mod.write_text(f"VERSION = {version!r}\n")
        rows[mod.name] = mod.read_bytes()
    if record:
        write_record(d / "RECORD", rows)
    return d


VER = f"python{sys.version_info[0]}.{sys.version_info[1]}"


def fake_base(tmp: Path) -> Path:
    """A copy of the base interpreter whose standard library directory is writable, a
    stand-in for the image's /usr/lib/python3.x (entries symlinked to the real ones)."""
    real = Path(sys.base_prefix)
    base = tmp / "base"
    (base / "bin").mkdir(parents=True)
    shutil.copy2(real / "bin" / VER, base / "bin" / VER)
    lib = base / "lib" / VER
    lib.mkdir(parents=True)
    for entry in (real / "lib" / VER).iterdir():
        if entry.name != "site-packages":
            (lib / entry.name).symlink_to(entry)
    (lib / "site-packages").mkdir()
    return base


_UNSET = object()


class World:
    """A source tree, a release wheel, an image stand-in and an installation."""

    def __init__(self, tmp: Path, writable_base: bool = False) -> None:
        self.tmp = tmp
        interpreter = sys.executable
        self.base_lib: Path | None = None
        if writable_base:
            base = fake_base(tmp)
            interpreter = str(base / "bin" / VER)
            self.base_lib = base / "lib" / VER
        self.source = tmp / "source"
        pkg = self.source / "src" / "brandsentinel"
        for rel, data in FILES.items():
            (pkg / rel).parent.mkdir(parents=True, exist_ok=True)
            (pkg / rel).write_bytes(data)
        (self.source / "docker").mkdir()
        (self.source / "docker" / "Dockerfile.sandbox").write_text("FROM base@sha256:00\n")

        self.wheel = tmp / "brandsentinel-0.2.1-py3-none-any.whl"
        members = {f"brandsentinel/{rel}": data for rel, data in FILES.items()}
        members |= {f"{DIST}/{name}": data for name, data in WHEEL_META.items()}
        record = io.StringIO()
        writer = csv.writer(record, lineterminator="\n")
        for name, data in members.items():
            writer.writerow([name, record_hash(data), len(data)])
        writer.writerow([f"{DIST}/RECORD", "", ""])
        with zipfile.ZipFile(self.wheel, "w") as z:
            for name, data in members.items():
                z.writestr(name, data)
            z.writestr(f"{DIST}/RECORD", record.getvalue())
        self.wheel_sha = hashlib.sha256(self.wheel.read_bytes()).hexdigest()

        self.image = tmp / "image"
        venv = [interpreter, "-m", "venv", "--without-pip", str(self.image)]
        subprocess.run(venv, check=True)  # noqa: S603 - fixed argv
        self.python = self.image / "bin" / "python"
        purelib = "import sysconfig; print(sysconfig.get_paths()['purelib'])"
        self.site = Path(
            subprocess.run(  # noqa: S603 - fixed argv
                [self.python, "-I", "-c", purelib], check=True, capture_output=True, text=True
            ).stdout.strip()
        )
        self.pkg = self.site / "brandsentinel"
        self.install_package(self.site)
        for src in SOURCES:
            py_compile.compile(str(self.pkg / src), doraise=True)  # pip's default: timestamp
        dist(self.site, "dep-a", "1.0")
        dist(self.site, "dep-c", "3.0")
        dist(self.site, "pip", "24.0", module=False)
        self.home = tmp / "home"
        self.home.mkdir()
        self.config_env = ["PATH=/opt/brandsentinel/bin:/usr/bin", "PYTHONDONTWRITEBYTECODE=1"]

        self.prefix = tmp / "prefix"
        installed_site = self.prefix / "venv" / "lib" / "python3.12" / "site-packages"
        installed_site.mkdir(parents=True)
        self.install_package(installed_site, installer="uv")
        (self.prefix / "INSTALL").write_text(f"commit: x\nwheel_sha256: {self.wheel_sha}\n")
        self.docker_calls: list[list[str]] = []
        self.created = "2026-11-11T00:00:00Z"
        self.config_override = _UNSET  # replaces the whole image config when set
        self.run_error: BaseException | None = None  # raised by `docker run`
        self.rm_error: BaseException | None = None  # raised by `docker rm -f`
        self.interpreter_options: list[str] = []  # before the image's own flags

    def install_package(self, site: Path, installer: str = "pip") -> None:
        for rel, data in FILES.items():
            (site / "brandsentinel" / rel).parent.mkdir(parents=True, exist_ok=True)
            (site / "brandsentinel" / rel).write_bytes(data)
        info = site / DIST
        info.mkdir()
        for name, data in WHEEL_META.items():
            (info / name).write_bytes(data)
        (info / "INSTALLER").write_text(installer + "\n")
        if installer == "uv":  # what install.sh's `uv pip install` writes
            (info / "uv_cache.json").write_text('{"timestamp":{"secs_since_epoch":1}}')
        (info / "REQUESTED").write_text("")
        (info / "direct_url.json").write_text(
            '{"url": "file:///tmp/dist/x.whl", "archive_info": {}}'
        )
        rows = {f"brandsentinel/{rel}": data for rel, data in FILES.items()}
        rows |= {f"{DIST}/{name}": data for name, data in WHEEL_META.items()}
        write_record(info / "RECORD", rows)

    def enable_user_site(self) -> Path:
        """Make the stand-in a --system-site-packages environment, as the image is, and
        create the image user's user site directory, which then precedes it."""
        cfg = self.image / "pyvenv.cfg"
        cfg.write_text(
            cfg.read_text().replace(
                "include-system-site-packages = false", "include-system-site-packages = true"
            )
        )
        ver = f"python{sys.version_info[0]}.{sys.version_info[1]}"
        user = self.home / ".local" / "lib" / ver / "site-packages"
        user.mkdir(parents=True)
        return user

    def pyc(self, src: str) -> Path:
        path = self.pkg / src
        return path.parent / "__pycache__" / f"{path.stem}.{TAG}.pyc"

    def runner(self, argv, cwd=None, timeout=None, env=None):
        name = Path(argv[0]).name
        if name == "docker":
            self.docker_calls.append(argv)
            args = argv[3:]
            if args[:2] == ["image", "inspect"]:
                assert args[2:4] == ["--format", "{{json .}}"]
                config = {"Env": self.config_env, "User": "pwuser", "Entrypoint": None}
                if self.config_override is not _UNSET:
                    config = self.config_override
                return json.dumps({"Id": IMAGE_ID, "Created": self.created, "Config": config})
            if args[0] == "rm":
                if self.rm_error is not None:
                    raise self.rm_error
                return ""
            if args[0] == "run":
                assert IMAGE_ID in args, "the measurement must run the inspected ID"
                if self.run_error is not None:
                    raise self.run_error
                flags = args[args.index(IMAGE_ID) + 1 :]
                env = {"PATH": os.environ.get("PATH", ""), "HOME": str(self.home)}
                return subprocess.run(  # noqa: S603 - the verifier's own in-image script
                    [self.python, *self.interpreter_options, *flags],
                    check=True,
                    capture_output=True,
                    text=True,
                    env=env,
                ).stdout
        if name == "uv":
            assert {"--frozen", "--offline", "--no-dev", "--no-emit-project"} <= set(argv)
            assert argv[argv.index("--extra") + 1] == "sandbox"
            assert {"--no-config", "--no-cache"} <= set(argv)
            assert argv[argv.index("--project") + 1] == str(cwd) == str(self.source.resolve())
            assert env is not None and not [k for k in env if k.startswith("UV_")]
            return PINS
        raise AssertionError(argv)


@pytest.fixture
def world(tmp_path, monkeypatch):
    w = World(tmp_path)
    monkeypatch.setattr(im, "run_command", w.runner)
    monkeypatch.setattr(im.shutil, "which", lambda name: f"/fake/bin/{name}")
    return w


def verify(w: World, capsys, profile: str = "release", **options) -> tuple[int, dict]:
    argv = ["--profile", profile, "--docker-host", "unix:///fake.sock", "--source", str(w.source)]
    if profile == "release":
        argv += ["--wheel", str(w.wheel)]
        options.setdefault("expect_wheel_sha256", w.wheel_sha)
    else:
        argv += ["--installed", str(w.prefix)]
        options.setdefault("expect_id", IMAGE_ID)
    for key, value in options.items():
        argv += [f"--{key.replace('_', '-')}", value]
    code = im.main(argv)
    return code, json.loads(capsys.readouterr().out)


def rules(report: dict) -> set[str]:
    return {v["rule"] for v in report["violations"]}


# Clean behaviour ---------------------------------------------------------------------


def test_release_profile_passes_a_faithful_image(world, capsys):
    code, report = verify(world, capsys, expect_id=IMAGE_ID, expect_wheel_sha256=world.wheel_sha)
    assert (code, report["verdict"], report["violations"]) == (0, "ok", [])
    assert report["compared"] == {
        "payload_files": len(FILES),
        "bytecode_files": len(SOURCES),
        "dist_info_files": len(WHEEL_META),
        "dependencies": 2,  # dep-a, and dep-c whose marker is true in the image
    }
    assert report["id_matches"] is True
    assert report["references"]["wheel_sha256"] == world.wheel_sha
    excluded = {e["path"].split("/")[-1]: e["reason"] for e in report["excluded"]}
    assert set(excluded) >= {"INSTALLER", "REQUESTED", "direct_url.json", "RECORD"}
    assert "dependency pip==24.0" in excluded and "dependency colorama==0.4.6" in excluded
    # every non-Python asset is compared, not only .py/.sql/.j2
    assert report["compared"]["payload_files"] == len(FILES)


def test_an_unbound_release_result_says_it_approves_nothing(world, capsys):
    code, report = verify(world, capsys)
    assert (code, report["verdict"]) == (0, "ok")
    assert report["binding"]["image_id"].startswith("NOT BOUND")
    assert report["binding"]["wheel"] == "bound to --expect-wheel-sha256"
    assert report["binding"]["approval"].startswith("none")
    _, bound = verify(world, capsys, expect_id=IMAGE_ID)
    assert bound["binding"]["image_id"] == "bound to --expect-id"


@pytest.mark.parametrize(
    ("where", "rule"),
    [
        ("dist-info/sub/INSTALLER", "metadata_extra"),
        ("dist-info/installer", "metadata_extra"),
        ("package/INSTALLER", "payload_extra"),
        ("package/uv_cache.json", "payload_extra"),
    ],
)
def test_installer_exclusions_are_exact_names_in_the_dist_info_only(where, rule, world, capsys):
    base, rel = where.split("/", 1)
    path = (world.site / DIST if base == "dist-info" else world.pkg) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("planted\n")
    code, report = verify(world, capsys)
    assert code == 1 and rule in rules(report), report["violations"]


def test_the_measurement_runs_without_network_and_never_pulls(world, capsys):
    verify(world, capsys)
    (run,) = [c for c in world.docker_calls if "run" in c]
    assert run[run.index("--network") + 1] == "none"
    assert run[run.index("--pull") + 1] == "never"
    assert "--rm" in run


def test_the_manifest_digest_is_stable_and_ignores_the_creation_time(world, capsys):
    _, first = verify(world, capsys)

    world.created = "2027-01-01T00:00:00Z"
    code, second = verify(world, capsys, expect_manifest_sha256=first["manifest_sha256"])
    assert code == 0 and second["created"] != first["created"]
    assert second["manifest_sha256"] == first["manifest_sha256"]


@pytest.mark.parametrize("mode", ["CHECKED_HASH", "UNCHECKED_HASH"])
def test_hash_based_bytecode_is_accepted(mode, world, capsys):
    for src in SOURCES:
        py_compile.compile(
            str(world.pkg / src), doraise=True,
            invalidation_mode=py_compile.PycInvalidationMode[mode],
        )  # fmt: skip
    code, report = verify(world, capsys)
    assert (code, report["violations"]) == (0, [])


def test_the_measurement_runs_no_startup_hook_first(world, capsys):
    """A .pth that hides itself from directory listings would blind a measurement
    taken after site.main(); under -S it never runs, so it is still seen."""
    (world.site / "hide.pth").write_text(
        "import os; _l = os.listdir; "
        "os.listdir = lambda p='.': [n for n in _l(p) if not n.endswith('.pth')]\n"
    )
    code, report = verify(world, capsys)
    assert code == 1 and "startup_hook" in rules(report)
    (run,) = [c for c in world.docker_calls if "run" in c]
    assert run[run.index(IMAGE_ID) + 1 : run.index("-c")] == ["-I", "-S", "-B"]


def test_load_profile_passes_against_the_installation(world, capsys):
    code, report = verify(world, capsys, profile="load")
    assert (code, report["verdict"], report["violations"]) == (0, "ok", [])
    assert report["references"]["installed_wheel_sha256"] == world.wheel_sha
    info = next((world.prefix / "venv").rglob(DIST))
    assert (info / "uv_cache.json").is_file() and (info / "INSTALLER").read_text() == "uv\n"
    assert report["checks"]["dependencies"].startswith("bound by the expected image ID")
    assert "dependencies" not in report["compared"]


# Invocations that cannot satisfy the contract fail closed ----------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["--docker-host", "h", "--source", "s", "--expect-id", "sha256:x"],  # the legacy call
        ["--profile", "release", "--docker-host", "h", "--source", "s"],
        ["--profile", "release", "--docker-host", "h", "--source", "s", "--wheel", "w"],
        ["--profile", "release", "--docker-host", "h", "--source", "s", "--wheel", "w",
         "--expect-wheel-sha256", "ab12"],
        ["--profile", "load", "--docker-host", "h", "--source", "s", "--installed", "p",
         "--expect-id", "brandsentinel-sandbox:local"],
        ["--profile", "load", "--docker-host", "h", "--source", "s", "--installed", "p",
         "--expect-id", "sha256:" + "ab" * 32, "--expect-manifest-sha256", "x" * 64],
        ["--profile", "load", "--docker-host", "h", "--source", "s", "--installed", "p"],
        ["--profile", "load", "--docker-host", "h", "--source", "s", "--installed", "p",
         "--expect-id", IMAGE_ID, "--wheel", "w"],
        ["--profile", "load", "--docker-host", "h", "--source", "s", "--installed", "p",
         "--expect-id", IMAGE_ID, "--expect-wheel-sha256", "ab" * 32],
    ],
    ids=["legacy", "release-no-wheel", "release-unbound-wheel", "release-short-wheel-sha",
         "load-id-is-a-tag", "load-bad-manifest-sha", "load-no-id", "load-with-wheel",
         "load-wheel-sha"],
)  # fmt: skip
def test_incomplete_invocations_are_refused(argv):
    with pytest.raises(SystemExit) as exit_:
        im.parse(argv)
    assert exit_.value.code == 2


def test_load_image_uses_the_load_profile():
    text = (REPO / "scripts" / "service-account" / "load-image.sh").read_text()
    call = text[text.index('-I -B "$VERIFIER"') :]
    assert "--profile load" in call and '--installed "$PREFIX"' in call
    assert '--image "$EXPECTED" --expect-id "$EXPECTED"' in call


def _incomplete(code: int, report: dict, words: str) -> None:
    assert (code, report["verdict"]) == (2, "INCOMPLETE")
    assert words in report["incomplete"][0]


def _fail_runner(w: World, name: str, error: Exception | None = None, out: str | None = None):
    def runner(argv, cwd=None, timeout=None, env=None):
        if Path(argv[0]).name == name and (name != "docker" or "run" in argv):
            if error is not None:
                raise error
            return out
        return w.runner(argv, cwd, timeout, env)

    return runner


def _edit_installed(w: World, name: str, text: str) -> None:
    (next((w.prefix / "venv").rglob(DIST)) / name).write_text(text)


def _wheel_add(w: World, name: str, data: bytes = b"") -> None:
    with zipfile.ZipFile(w.wheel, "a") as z:
        z.writestr(name, data)


INCOMPLETE = {
    "docker-fails": (lambda w, m: m.setattr(im, "run_command", _fail_runner(
        w, "docker", subprocess.CalledProcessError(1, ["docker"], stderr="Error: No such image"))),
        "release", "No such image"),
    "docker-times-out": (lambda w, m: m.setattr(im, "run_command", _fail_runner(
        w, "docker", subprocess.TimeoutExpired(["docker"], 600))), "release", "timed out"),
    "inspect-not-json": (lambda w, m: m.setattr(im, "run_command",
        lambda argv, cwd=None, timeout=None: "[]"),
        "release", "did not return the image"),
    "measurement-not-json": (lambda w, m: m.setattr(im, "run_command", _fail_runner(
        w, "docker", out="Traceback")), "release", "did not return JSON"),
    "measurement-fatal": (lambda w, m: m.setattr(im, "run_command", _fail_runner(
        w, "docker", out='{"fatal": "OSError: x"}')), "release", "measurement failed"),
    "no-uv": (lambda w, m: m.setattr(im.shutil, "which",
        lambda n: None if n == "uv" else f"/fake/bin/{n}"), "release", "uv not found"),
    "uv-fails": (lambda w, m: m.setattr(im, "run_command", _fail_runner(
        w, "uv", subprocess.CalledProcessError(2, ["uv"], stderr="lock out of date"))),
        "release", "uv export failed"),
    "uv-unpinned": (lambda w, m: m.setattr(im, "run_command", _fail_runner(
        w, "uv", out="dep-a>=1.0\n")), "release", "not an exact pin"),
    "uv-no-pins": (lambda w, m: m.setattr(im, "run_command", _fail_runner(w, "uv", out="")),
        "release", "no pins"),
    "wheel-record-disagrees": (lambda w, m: _wheel_add(w, "brandsentinel/sneaky.py", b"x = 1\n"),
        "release", "RECORD does not match"),
    "wheel-member-outside": (lambda w, m: _wheel_add(w, "sitecustomize.py"),
        "release", "outside the package"),
    "wheel-duplicate-member": (lambda w, m: _wheel_add(w, "brandsentinel/cli.py", b"x"),
        "release", "duplicate members"),
    "wheel-unreadable": (lambda w, m: w.wheel.write_bytes(b"not a zip"), "release",
        "cannot be read"),
    "installed-editable": (lambda w, m: _edit_installed(
        w, "direct_url.json", '{"url": "file:///src", "dir_info": {"editable": true}}'),
        "load", "editable"),
    "installed-direct-url-garbage": (lambda w, m: _edit_installed(w, "direct_url.json", "{"),
        "load", "direct_url.json cannot be read"),
    "installed-two-dist-infos": (lambda w, m: dist(
        next((w.prefix / "venv").rglob("site-packages")), "brandsentinel", "0.2.0",
        module=False),
        "load", "not exactly one brandsentinel dist-info"),
    "installed-two-sites": (lambda w, m: (w.prefix / "venv" / "lib" / "python3.13"
        / "site-packages").mkdir(parents=True), "load", "not exactly one site-packages"),
    "image-without-package": (lambda w, m: shutil.rmtree(w.pkg), "release",
        "no package directory"),
    "source-symlink": (lambda w, m: (w.source / "src" / "brandsentinel" / "l.py").symlink_to(
        "cli.py"), "release", "not a regular file"),
    "internal-error": (lambda w, m: m.setattr(im, "compare_payload", lambda *a: 1 / 0),
        "release", "internal error: ZeroDivisionError"),
}  # fmt: skip


@pytest.mark.parametrize("case", sorted(INCOMPLETE))
@pytest.mark.filterwarnings("ignore:Duplicate name:UserWarning")
def test_an_inspection_that_cannot_complete_is_never_a_pass(case, world, capsys, monkeypatch):
    damage, profile, words = INCOMPLETE[case]
    damage(world, monkeypatch)
    _incomplete(*verify(world, capsys, profile=profile), words)


def test_an_unreadable_image_entry_is_incomplete(world, capsys):
    if os.geteuid() == 0:
        pytest.skip("root reads anything")
    locked = world.pkg / "store"
    locked.chmod(0)
    try:
        _incomplete(*verify(world, capsys), "cannot")
    finally:
        locked.chmod(0o755)


def test_unreadable_bytecode_is_incomplete_not_a_pass(world, capsys):
    if os.geteuid() == 0:
        pytest.skip("root reads anything")
    world.pyc("cli.py").chmod(0)
    _incomplete(*verify(world, capsys), "unreadable")


# Damage cases: each must flip a passing world ----------------------------------------


def _header_for(source: Path) -> bytes:
    st = source.stat()
    return (
        importlib.util.MAGIC_NUMBER
        + (0).to_bytes(4, "little")
        + (int(st.st_mtime) & 0xFFFFFFFF).to_bytes(4, "little")
        + (st.st_size & 0xFFFFFFFF).to_bytes(4, "little")
    )


def _patch_pyc(w: World, offset: int, data: bytes, src: str = "cli.py") -> None:
    pyc = w.pyc(src)
    raw = bytearray(pyc.read_bytes())
    raw[offset : offset + len(data)] = data
    pyc.write_bytes(bytes(raw))


def _rewrite_record(w: World, change) -> None:
    path = w.site / DIST / "RECORD"
    rows = list(csv.reader(io.StringIO(path.read_text())))
    out = io.StringIO()
    csv.writer(out, lineterminator="\n").writerows(change(rows))
    path.write_text(out.getvalue())


def _outside(w: World) -> dict:
    user = w.enable_user_site()
    shutil.move(w.site / "dep_a-1.0.dist-info", user / "dep_a-1.0.dist-info")
    return {}


def _invalid_source(w: World) -> dict:
    src = w.pkg / "cli.py"
    body = w.pyc("cli.py").read_bytes()[16:]
    src.write_bytes(b"def app(:\n")
    w.pyc("cli.py").write_bytes(_header_for(src) + body)
    return {}


def _body_differs(w: World) -> dict:
    src = w.pkg / "cli.py"
    other = compile(b"def app():\n    return 1\n", str(src), "exec", dont_inherit=True)
    w.pyc("cli.py").write_bytes(_header_for(src) + marshal.dumps(other))
    return {}


def _hash_mismatch(w: World) -> dict:
    py_compile.compile(
        str(w.pkg / "cli.py"), doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )  # fmt: skip
    _patch_pyc(w, 8, b"\x00" * 8)
    return {}


def _filename_differs(w: World) -> dict:
    src = w.pkg / "cli.py"
    py_compile.compile(
        str(src), cfile=str(w.pyc("cli.py")), dfile="/elsewhere/cli.py", doraise=True
    )
    return {}


def _bad_body(w: World) -> dict:
    src = w.pkg / "cli.py"
    w.pyc("cli.py").write_bytes(_header_for(src) + b"\xffnot marshal")
    return {}


def _pyc_symlink(w: World) -> dict:
    pyc = w.pyc("cli.py")
    real = w.tmp / "real.pyc"
    shutil.move(pyc, real)
    pyc.symlink_to(real)
    return {}


def _bump_version(w: World) -> dict:
    shutil.rmtree(w.site / "dep_a-1.0.dist-info")
    dist(w.site, "dep-a", "1.1")
    return {}


CASES = {
    "image_id_mismatch": lambda w: {"expect_id": "sha256:" + "cd" * 32},
    "wheel_sha256_mismatch": lambda w: {"expect_wheel_sha256": "0" * 64},
    "manifest_sha256_mismatch": lambda w: {"expect_manifest_sha256": "0" * 64},
    "reference_mismatch": lambda w: (
        w.source.joinpath("src/brandsentinel/sandbox/selftest/README.md").write_text("edited\n")
        and {}
    ),
    "payload_missing": lambda w: (w.pkg / "sandbox" / "chromium-seccomp.json").unlink() or {},
    "payload_extra": lambda w: (w.pkg / "sandbox" / "planted.so").write_bytes(b"\x7fELF") and {},
    "payload_modified": lambda w: (
        (w.pkg / "sandbox" / "selftest" / "ocr-donate.png").write_bytes(b"\x89PNG other") and {}
    ),
    "payload_not_regular": lambda w: (w.pkg / "link.json").symlink_to("/etc/hostname") or {},
    "unexpected_bytecode": lambda w: (
        shutil.copy(w.pyc("cli.py"), w.pyc("cli.py").with_name(f"cli.{TAG}.opt-1.pyc")) and {}
    ),
    "bytecode_missing": lambda w: w.pyc("cli.py").unlink() or {},
    "bytecode_not_regular": _pyc_symlink,
    "bytecode_bad_header": lambda w: w.pyc("cli.py").write_bytes(b"\x00" * 8) and {},
    "bytecode_bad_magic": lambda w: _patch_pyc(w, 0, b"\x00\x00") or {},
    "bytecode_bad_flags": lambda w: _patch_pyc(w, 4, (2).to_bytes(4, "little")) or {},
    "bytecode_stale_header": lambda w: _patch_pyc(w, 8, (12345).to_bytes(4, "little")) or {},
    "bytecode_hash_mismatch": _hash_mismatch,
    "bytecode_bad_body": _bad_body,
    "bytecode_source_invalid": _invalid_source,
    "bytecode_body_differs": _body_differs,
    "bytecode_filename_differs": _filename_differs,
    "dist_info_count": lambda w: dist(w.site, "brandsentinel", "0.2.0", module=False) and {},
    "metadata_missing": lambda w: (w.site / DIST / "entry_points.txt").unlink() or {},
    "metadata_modified": lambda w: (
        (w.site / DIST / "METADATA").write_text(
            "Metadata-Version: 2.4\nName: brandsentinel\nVersion: 0.2.2\n"
        )
        and {}
    ),
    "metadata_extra": lambda w: (w.site / DIST / "extra.txt").write_text("x") and {},
    "record_mismatch": lambda w: (
        _rewrite_record(w, lambda rows: [r for r in rows if r[0] != "brandsentinel/cli.py"]) or {}
    ),
    "site_not_regular": lambda w: (w.site / "linked").symlink_to(w.tmp) or {},
    "dependency_shadowed": lambda w: (
        (w.site / "dep_a").mkdir() or ((w.site / "dep_a" / "__init__.py").write_text("") and {})
    ),
    "startup_hook": lambda w: (w.site / "zzz.pth").write_text("/nonexistent\n") and {},
    "dependency_missing": lambda w: shutil.rmtree(w.site / "dep_a-1.0.dist-info") or {},
    "dependency_version": _bump_version,
    "dependency_outside_venv": _outside,
    "user_site": lambda w: w.enable_user_site() and {},
    "image_environment": lambda w: w.config_env.append("PYTHONPATH=/srv/override") or {},
    "image_loader_environment": lambda w: w.config_env.append("LD_PRELOAD=/x.so") or {},
    "site_unowned": lambda w: (w.site / "planted.py").write_text("x = 1\n") and {},
    "bytecode_trailing_data": lambda w: (
        w.pyc("cli.py").write_bytes(w.pyc("cli.py").read_bytes() + b"\x00PAYLOAD") and {}
    ),
    "dependency_unexpected": lambda w: dist(w.site, "dep-b", "2.0") and {},
    "dependency_duplicate": lambda w: dist(w.site, "dep-a", "1.0", "Dep_A-1.0.dist-info") and {},
}


@pytest.mark.parametrize("rule", sorted(CASES))
def test_each_damage_is_detected(rule, world, capsys):
    code, report = verify(world, capsys)
    assert (code, report["violations"]) == (0, []), "the world must pass before the damage"
    options = CASES[rule](world) or {}
    code, report = verify(world, capsys, **options)
    assert (code, report["verdict"]) == (1, "MISMATCH")
    assert rule in rules(report), report["violations"]


@pytest.mark.parametrize(
    "change",
    [
        lambda rows: [[r[0], "sha256=AAAA", r[2]] if r[0] == "brandsentinel/cli.py" else r
                      for r in rows],
        lambda rows: [*rows, ["brandsentinel/ghost.py", "sha256=AAAA", "1"]],
    ],
    ids=["wrong-hash", "extra-row"],
)  # fmt: skip
def test_record_disagreements_are_detected(change, world, capsys):
    _rewrite_record(world, change)
    code, report = verify(world, capsys)
    assert code == 1 and "record_mismatch" in rules(report)


@pytest.mark.parametrize(
    "rule", ["payload_extra", "payload_modified", "metadata_modified", "bytecode_body_differs"]
)
def test_the_load_profile_detects_damage_too(rule, world, capsys):
    CASES[rule](world)
    code, report = verify(world, capsys, profile="load")
    assert code == 1 and rule in rules(report)


def test_an_installation_that_differs_from_the_source_is_a_reference_mismatch(world, capsys):
    installed = next((world.prefix / "venv").rglob("brandsentinel/cli.py"))
    installed.write_bytes(b"def app():\n    return 2\n")
    code, report = verify(world, capsys, profile="load")
    assert code == 1 and {"reference_mismatch", "payload_modified"} <= rules(report)


# Rules whose damage needs a writable standard library, so a dedicated test covers it.
DEDICATED = {"package_shadowed": "test_a_stdlib_copy_of_the_package_is_shadowing"}


def test_every_rule_has_a_damage_case():
    assert set(CASES) | set(DEDICATED) == set(im.RULES)
    assert not set(CASES) & set(DEDICATED)
    for name in DEDICATED.values():
        assert callable(globals()[name])


# Round-2 review remediation (S1-S9, LD_*) ------------------------------------------


def _runs(w: World) -> list[list[str]]:
    return [c for c in w.docker_calls if c[3] == "run"]


@pytest.mark.parametrize("profile", ["release", "load"])
def test_an_unexpected_image_is_never_run(profile, world, capsys):
    """S1: the ID is compared before anything runs; a mismatch is reported, never run."""
    code, report = verify(world, capsys, profile=profile, expect_id="sha256:" + "cd" * 32)
    assert (code, report["verdict"], report["measured"]) == (1, "MISMATCH", False)
    assert rules(report) == {"image_id_mismatch"} and report["id_matches"] is False
    assert _runs(world) == []


@pytest.mark.parametrize("variable", ["LD_PRELOAD=/x.so", "LD_LIBRARY_PATH=/x", "LD_AUDIT=/x.so"])
def test_a_loader_variable_in_the_image_config_is_rejected_before_running(variable, world, capsys):
    world.config_env.append(variable)
    code, report = verify(world, capsys)
    assert code == 1 and rules(report) == {"image_loader_environment"}
    assert report["measured"] is False and _runs(world) == []
    assert variable.split("=")[0] in report["config"]["env_names"]


def test_other_image_variables_are_reported_not_judged(world, capsys):
    world.config_env += ["PLAYWRIGHT_BROWSERS_PATH=/ms-playwright", "LANG=C.UTF-8"]
    code, report = verify(world, capsys)
    assert (code, report["violations"]) == (0, [])
    assert {"PLAYWRIGHT_BROWSERS_PATH", "LANG"} <= set(report["config"]["env_names"])


def test_the_measurement_container_is_locked_down(world, capsys):
    """S1: the runner's lockdown, a unique name, the python3 entrypoint, -I -S -B."""
    verify(world, capsys)
    (run,) = _runs(world)
    args = run[3:]
    image_at = args.index(IMAGE_ID)
    flags = args[:image_at]
    expected = (
        "--rm", "--pull", "never", "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges=true", "--memory", "1g", "--memory-swap", "1g",
        "--cpus", "1", "--pids-limit", "64", "--ipc", "private", "--ulimit", "core=0",
        "--ulimit", "nofile=1024:1024", "--no-healthcheck", "--workdir", "/tmp",
        "--label", "brandsentinel.role=image-manifest",
    )  # fmt: skip
    n = len(expected)
    assert any(tuple(flags[j : j + n]) == expected for j in range(len(flags)))
    for flag, value in [
        ("--network", "none"),
        ("--pull", "never"),
        ("--cap-drop", "ALL"),
        ("--security-opt", "no-new-privileges=true"),
        ("--entrypoint", "python3"),
    ]:
        assert flags[flags.index(flag) + 1] == value
    assert "--read-only" in flags and "--pids-limit" in flags and "--memory" in flags
    assert flags[flags.index("--name") + 1].startswith("brandsentinel-image-manifest-")
    assert args[image_at + 1 : args.index("-c")] == ["-I", "-S", "-B"]  # fmt: skip


def _rm_calls(w: World) -> list[str]:
    return [c[-1] for c in w.docker_calls if c[3:5] == ["rm", "-f"]]


def test_a_timed_out_measurement_removes_its_container(world, capsys):
    world.run_error = subprocess.TimeoutExpired(["docker"], 600)
    code, report = verify(world, capsys)
    assert (code, report["verdict"]) == (2, "INCOMPLETE") and "timed out" in report["incomplete"][0]
    (run,) = _runs(world)
    assert _rm_calls(world) == [run[run.index("--name") + 1]]


def test_a_container_that_cannot_be_removed_is_reported(world, capsys):
    world.run_error = subprocess.TimeoutExpired(["docker"], 600)
    world.rm_error = subprocess.CalledProcessError(1, ["docker"], stderr="daemon unreachable")
    code, report = verify(world, capsys)
    (run,) = _runs(world)
    name = run[run.index("--name") + 1]
    assert code == 2 and name in report["incomplete"][0]
    assert "may still be running" in report["incomplete"][0]


def test_a_container_already_gone_counts_as_removed(world, capsys):
    world.run_error = subprocess.CalledProcessError(125, ["docker"], stderr="Error: No such image")
    world.rm_error = subprocess.CalledProcessError(
        1, ["docker"], stderr="Error: No such container: x"
    )
    code, report = verify(world, capsys)
    assert code == 2 and "No such image" in report["incomplete"][0]


def test_an_interrupted_measurement_removes_its_container(world, capsys):
    world.run_error = KeyboardInterrupt()
    argv = ["--profile", "release", "--docker-host", "unix:///fake.sock", "--source",
            str(world.source), "--wheel", str(world.wheel), "--expect-wheel-sha256",
            world.wheel_sha]  # fmt: skip
    with pytest.raises(KeyboardInterrupt):
        im.main(argv)
    assert len(_rm_calls(world)) == 1


@pytest.fixture
def base_world(tmp_path, monkeypatch):
    """The world on a copied base interpreter with a writable standard library."""
    w = World(tmp_path, writable_base=True)
    monkeypatch.setattr(im, "run_command", w.runner)
    monkeypatch.setattr(im.shutil, "which", lambda name: f"/fake/bin/{name}")
    return w


def test_a_stdlib_copy_of_the_package_is_shadowing(base_world, capsys):
    """S2: the standard library precedes site-packages at runtime."""
    code, report = verify(base_world, capsys)
    assert (code, report["violations"]) == (0, [])
    shadow = base_world.base_lib / "brandsentinel"
    shadow.mkdir()
    (shadow / "__init__.py").write_text("")
    code, report = verify(base_world, capsys)
    assert code == 1 and "package_shadowed" in rules(report)
    assert str(shadow) in {v["path"] for v in report["violations"]}.pop()


def test_hooks_outside_the_environment_are_inventoried_not_judged(base_world, capsys):
    """S5: base-image or later-layer hooks are hashed into the manifest and excluded with
    an accurate reason; venv hooks are violations."""
    base_world.enable_user_site()
    shutil.rmtree(base_world.home / ".local")  # the faithful image has no user site
    (base_world.base_lib / "sitecustomize.py").write_text("")
    (base_world.base_lib / "site-packages" / "zz.pth").write_text("")
    code, report = verify(base_world, capsys)
    assert (code, report["violations"]) == (0, [])
    reasons = {Path(e["path"]).name: e["reason"] for e in report["excluded"]}
    for name in ("sitecustomize.py", "zz.pth"):
        assert "bound only by the image ID" in reasons[name]
        assert "base image digest" not in reasons[name]
    _, again = verify(base_world, capsys)
    (base_world.base_lib / "site-packages" / "zz.pth").write_text("import os\n")
    _, changed = verify(base_world, capsys)
    assert again["manifest_sha256"] != changed["manifest_sha256"]


@pytest.mark.parametrize("name", ["sitecustomize.py", "usercustomize.py", "x.pth"])
def test_startup_hooks_in_the_environment_are_violations(name, world, capsys):
    (world.site / name).write_text("")
    code, report = verify(world, capsys)
    assert code == 1 and "startup_hook" in rules(report)


@pytest.mark.parametrize(
    "plant",
    [
        lambda s: (s / "dep_a").mkdir() or (s / "dep_a" / "__init__.py").write_text(""),
        lambda s: (s / "loose.py").write_text(""),
        lambda s: (s / "dep_a.cpython-312-x86_64-linux-gnu.so").write_bytes(b"\x7fELF"),
        lambda s: (s / "sourceless.pyc").write_bytes(b"\x00" * 16),
        lambda s: dist(s, "norecord", "1.0", record=False),
    ],
    ids=["package-shadows-module", "module", "extension", "sourceless-pyc", "no-record"],
)
def test_unowned_site_entries_are_violations(plant, world, capsys):
    """S3: only what a distribution's RECORD owns may sit at the top of site-packages."""
    plant(world.site)
    code, report = verify(world, capsys)
    assert code == 1 and "site_unowned" in rules(report), report["violations"]


def test_owned_layouts_pass(world, capsys):
    """S3 compatibility: namespace packages shared by two distributions, a single-module
    distribution with its top-level __pycache__, and an extension module, all owned."""
    site = world.site
    for name, sub in (("ns-one", "one"), ("ns-two", "two")):
        d = dist(site, name, "1.0", module=False)
        (site / "nsp" / sub).mkdir(parents=True)
        (site / "nsp" / sub / "__init__.py").write_text("")
        write_record(d / "RECORD", {f"{d.name}/METADATA": (d / "METADATA").read_bytes(),
                                    f"nsp/{sub}/__init__.py": b""})  # fmt: skip
    d = dist(site, "single", "1.0")
    (site / "__pycache__").mkdir()
    (site / "__pycache__" / f"single.{TAG}.pyc").write_bytes(b"")
    (site / "fast.cpython-312-x86_64-linux-gnu.so").write_bytes(b"\x7fELF")
    write_record(d / "RECORD", {f"{d.name}/METADATA": (d / "METADATA").read_bytes(),
                                "single.py": (site / "single.py").read_bytes(),
                                f"__pycache__/single.{TAG}.pyc": b"",
                                "fast.cpython-312-x86_64-linux-gnu.so": b"\x7fELF"})  # fmt: skip
    pins = PINS + "ns-one==1.0\nns-two==1.0\nsingle==1.0\n"
    original = world.runner
    world_runner = lambda argv, cwd=None, timeout=None, env=None: (  # noqa: E731
        pins if Path(argv[0]).name == "uv" else original(argv, cwd, timeout, env)
    )
    im.run_command = world_runner
    code, report = verify(world, capsys)
    assert (code, report["violations"]) == (0, [])


# The image's interpreter: Ubuntu's 3.12 ------------------------------------------------

# A stand-in for Ubuntu 3.12.3's sysconfig (the M8 image's; Debian-patched and older than
# GH-126789), reduced to what the in-image script calls. Two values are fixed when the
# module is imported, before site.venv() has run: the default scheme (`get_paths`'s
# default argument, Debian's `posix_local` outside an environment) and the prefix. A
# script that imports sysconfig first and reads the defaults gets the system's
# /usr/local/lib/python3.12/dist-packages, not the environment's site-packages (U15
# Part B). Explicit `vars` take precedence over the config variables, as upstream.
UBUNTU_SYSCONFIG = """
import os, sys
_PREFIX = os.path.normpath(sys.prefix)
_EXEC_PREFIX = os.path.normpath(sys.exec_prefix)
_BASE_PREFIX = os.path.normpath(sys.base_prefix)
_SCHEMES = {
    "posix_local": {
        "purelib": "{base}/local/lib/python{py_version_short}/dist-packages",
        "platlib": "{platbase}/local/lib/python{py_version_short}/dist-packages",
    },
    "posix_prefix": {
        "purelib": "{base}/lib/python{py_version_short}/site-packages",
        "platlib": "{platbase}/lib/python{py_version_short}/site-packages",
    },
    "venv": {
        "purelib": %(venv_purelib)r,
        "platlib": "{platbase}/lib/python{py_version_short}/site-packages",
    },
}

def get_default_scheme():
    return "venv" if sys.prefix != sys.base_prefix else "posix_local"

def get_config_vars():
    return {"base": _PREFIX, "platbase": _EXEC_PREFIX, "installed_base": _BASE_PREFIX,
            "installed_platbase": _BASE_PREFIX,
            "py_version_short": "%%d.%%d" %% sys.version_info[:2]}

def get_paths(scheme=get_default_scheme(), vars=None, expand=True):
    values = get_config_vars()
    values.update(vars or {})
    return {k: os.path.normpath(v.format(**values)) for k, v in _SCHEMES[scheme].items()}
"""
VENV_PURELIB = "{base}/lib/python{py_version_short}/site-packages"

# This interpreter's site.py with Ubuntu 3.12.3's (Debian's) getsitepackages: in an
# environment, each prefix lists its lib/python3.x/site-packages, then Debian's three
# dist-packages directories, so the system's /usr/local/lib/python3.x/dist-packages is on
# the path after the environment's directories. `extra` runs after it, to bend it.
UBUNTU_SITE = """
exec(compile(open(%(real)r).read(), %(real)r, "exec"))

def getsitepackages(prefixes=None):
    sitepackages, seen = [], set()
    ver = "python%%d.%%d" %% sys.version_info[:2]
    for prefix in PREFIXES if prefixes is None else prefixes:
        if not prefix or prefix in seen:
            continue
        seen.add(prefix)
        if sys.base_prefix != sys.prefix:
            sitepackages.append(os.path.join(prefix, "lib", ver, "site-packages"))
        sitepackages.append(os.path.join(prefix, "local/lib", ver, "dist-packages"))
        sitepackages.append(os.path.join(prefix, "lib", "python3", "dist-packages"))
        sitepackages.append(os.path.join(prefix, "lib", ver, "dist-packages"))
    return sitepackages
%(extra)s
"""


def ubuntu_like(w: World, venv_purelib: str = VENV_PURELIB, site_extra: str = "") -> Path:
    """Give the world's base interpreter Ubuntu's sysconfig and site behaviour and the
    image's layout: a --system-site-packages environment, and a system dist-packages
    directory (holding pip in the image) where the import-time defaults point. Returns
    that directory."""
    assert w.base_lib is not None, "needs the writable base"
    (w.base_lib / "sysconfig.py").unlink()  # a symlink to the real one
    (w.base_lib / "sysconfig.py").write_text(UBUNTU_SYSCONFIG % {"venv_purelib": venv_purelib})
    # site is a frozen module in 3.12 (Ubuntu freezes its own patched copy): the
    # stand-in's interpreter must load it from the file instead.
    w.interpreter_options = ["-X", "frozen_modules=off"]
    real_site = os.path.realpath(w.base_lib / "site.py")
    (w.base_lib / "site.py").unlink()
    (w.base_lib / "site.py").write_text(UBUNTU_SITE % {"real": real_site, "extra": site_extra})
    local = w.base_lib.parents[1] / "local" / "lib" / VER / "dist-packages"
    local.mkdir(parents=True)
    dist(local, "pip", "26.0", module=False)
    cfg = w.image / "pyvenv.cfg"
    cfg.write_text(
        cfg.read_text().replace(
            "include-system-site-packages = false", "include-system-site-packages = true"
        )
    )
    return local


@pytest.fixture(params=["upstream", "ubuntu"])
def either_world(request, base_world):
    """The base world on the pinned interpreter as it is, and with Ubuntu's sysconfig."""
    if request.param == "ubuntu":
        ubuntu_like(base_world)
    return base_world


def test_the_environments_site_packages_is_measured_on_either_interpreter(either_world, capsys):
    """U15 Part B: on Ubuntu's interpreter the verifier measured the system's
    dist-packages and could not find the package (INCOMPLETE)."""
    code, report = verify(either_world, capsys)
    assert (code, report["verdict"], report["violations"]) == (0, "ok", [])
    assert report["site"] == str(either_world.site)
    assert report["compared"]["payload_files"] == len(FILES)
    code, report = verify(either_world, capsys, profile="load")
    assert (code, report["verdict"], report["violations"]) == (0, "ok", [])


@pytest.mark.parametrize(
    "purelib, words",
    [
        ("{base}/lib/python{py_version_short}/other-packages", "site.py puts it"),
        ("{installed_base}/lib/python{py_version_short}/site-packages", "outside the environment"),
    ],
    ids=["calculations-disagree", "outside-the-environment"],
)
def test_a_site_directory_the_environment_does_not_use_is_incomplete(
    purelib, words, base_world, capsys
):
    """The environment's own scheme must name a directory inside it that site.py adds
    for it, even holding a faithful copy of the package."""
    ubuntu_like(base_world, venv_purelib=purelib)
    values = {"base": str(base_world.image), "installed_base": str(base_world.base_lib.parents[1]),
              "py_version_short": VER.removeprefix("python")}  # fmt: skip
    elsewhere = Path(purelib.format(**values))
    elsewhere.mkdir(parents=True, exist_ok=True)
    shutil.copytree(base_world.pkg, elsewhere / "brandsentinel")
    shutil.copytree(base_world.site / DIST, elsewhere / DIST)
    _incomplete(*verify(base_world, capsys), words)


# site.venv() sets both prefixes; an interpreter that leaves exec_prefix elsewhere is not
# the environment the measurement assumes.
SPLIT_EXEC_PREFIX = """
_venv = venv
def venv(known_paths):
    known_paths = _venv(known_paths)
    sys.exec_prefix = sys.base_exec_prefix
    return known_paths
"""


def _venv_site_out(w: World) -> None:
    outside = w.tmp / "outside-dist-packages"
    outside.mkdir()
    (w.image / "lib" / "python3").mkdir()
    (w.image / "lib" / "python3" / "dist-packages").symlink_to(outside)


def _system_site_in(w: World, local: Path) -> None:
    shutil.rmtree(local)
    local.symlink_to(w.site)


@pytest.mark.parametrize(
    "purelib, extra, damage, words",
    [
        (VENV_PURELIB, SPLIT_EXEC_PREFIX, None, "prefix and exec_prefix differ"),
        ("{base}/local/lib/python{py_version_short}/dist-packages", "", None, "is missing"),
        ("{base}", "", None, "outside the environment"),
        (VENV_PURELIB, "", lambda w, local: _venv_site_out(w), "resolves outside it"),
        (VENV_PURELIB, "", _system_site_in, "resolves into the environment"),
    ],
    ids=["exec-prefix-elsewhere", "site-missing", "site-is-the-prefix",
         "environment-site-resolves-out", "system-site-resolves-in"],
)  # fmt: skip
def test_an_environment_the_measurement_cannot_place_is_incomplete(
    purelib, extra, damage, words, base_world, capsys
):
    local = ubuntu_like(base_world, venv_purelib=purelib, site_extra=extra)
    if damage is not None:
        damage(base_world, local)
    _incomplete(*verify(base_world, capsys), words)


def test_an_alias_of_the_environments_site_is_listed_once(base_world, capsys):
    """Debian's list names lib/python3.x/dist-packages too; a symlink to site-packages
    there is the same directory, not a second copy of every distribution."""
    ubuntu_like(base_world)
    (base_world.image / "lib" / VER / "dist-packages").symlink_to(base_world.site)
    code, report = verify(base_world, capsys)
    assert (code, report["verdict"], report["violations"]) == (0, "ok", [])


def _symlinked_lib(w: World) -> None:
    real = w.image / "lib.real"
    (w.image / "lib").rename(real)
    (w.image / "lib").symlink_to(real)


def _site_elsewhere(w: World) -> None:
    moved = w.tmp / "elsewhere-site"
    shutil.move(w.site, moved)
    w.site.symlink_to(moved)


@pytest.mark.parametrize(
    "damage, words",
    [
        (_symlinked_lib, "through a symlink"),
        (_site_elsewhere, "through a symlink"),
        (
            lambda w: shutil.move(w.pkg, w.tmp / "pkg") or w.pkg.symlink_to(w.tmp / "pkg"),
            "no package directory",
        ),
    ],
    ids=["symlink-inside-the-environment", "site-symlinked-out", "package-symlinked-out"],
)
def test_a_site_or_package_reached_through_a_symlink_is_incomplete(
    damage, words, either_world, capsys
):
    damage(either_world)
    _incomplete(*verify(either_world, capsys), words)


@pytest.mark.parametrize(
    "change, words",
    [
        (lambda m: m.update(site="/usr/local/lib/python3.12/dist-packages"), "site"),
        (lambda m: m.update(site=m["interpreter"]["prefix"]), "site"),
        (lambda m: m.update(site=m["site"] + "/../site-packages"), "site"),
        (lambda m: m["interpreter"].update(prefix="/usr"), "prefix"),
        (lambda m: m["interpreter"].update(prefix="/"), "prefix"),
        (lambda m: m["interpreter"].update(executable="/usr/bin/python3"), "prefix"),
        (lambda m: m.update(site=None), "site"),
        (lambda m: m.update(site=m["interpreter"]["prefix"] + "-other/site-packages"), "site"),
        (lambda m: m.update(interpreter=None), "no interpreter"),
        (lambda m: m["interpreter"].update(prefix=m["interpreter"]["prefix"].lstrip("/")),
         "prefix"),
        (lambda m: m["interpreter"].update(prefix=m["interpreter"]["prefix"] + "/"), "prefix"),
        (lambda m: m["interpreter"].update(
            executable=m["interpreter"]["prefix"] + "/bin/../bin/python"), "prefix"),
    ],
    ids=["site-outside", "site-is-prefix", "site-not-normal", "prefix-elsewhere",
         "prefix-root", "executable-elsewhere", "site-not-text", "site-in-a-sibling",
         "no-interpreter", "prefix-relative", "prefix-not-normal", "executable-not-normal"],
)  # fmt: skip
def test_the_host_checks_the_reported_site_against_the_interpreter(
    change, words, world, capsys, monkeypatch
):
    """The host does not take the image's word for where its environment is."""

    def runner(argv, cwd=None, timeout=None, env=None):
        out = world.runner(argv, cwd, timeout, env)
        if Path(argv[0]).name == "docker" and "run" in argv:
            measured = json.loads(out)
            change(measured)
            out = json.dumps(measured)
        return out

    monkeypatch.setattr(im, "run_command", runner)
    _incomplete(*verify(world, capsys), words)


def test_system_site_distributions_are_not_the_environments(base_world, capsys):
    """With include-system-site-packages = true, the system's copies of a dependency
    and of pip follow the environment's at runtime: never counted as in it."""
    local = ubuntu_like(base_world)
    system = base_world.base_lib / "site-packages"
    for site in (local, system):
        dist(site, "dep-a", "0.9")
        dist(site, "dep-b", "2.0")
    code, report = verify(base_world, capsys)
    assert (code, report["verdict"], report["violations"]) == (0, "ok", [])


def test_a_counterfeit_package_in_a_system_directory_is_never_measured(base_world, capsys):
    """A faithful copy where Ubuntu's import-time defaults point, and none in the
    environment: the environment's package is missing, whatever the system holds."""
    local = ubuntu_like(base_world)
    for site in (local, base_world.base_lib / "site-packages"):
        shutil.copytree(base_world.pkg, site / "brandsentinel")
        shutil.copytree(base_world.site / DIST, site / DIST)
    shutil.rmtree(base_world.pkg)
    shutil.rmtree(base_world.site / DIST)
    _incomplete(*verify(base_world, capsys), "no package directory")


def test_a_stdlib_copy_of_the_package_shadows_on_ubuntu_too(base_world, capsys):
    ubuntu_like(base_world)
    shadow = base_world.base_lib / "brandsentinel"
    shadow.mkdir()
    (shadow / "__init__.py").write_text("")
    code, report = verify(base_world, capsys)
    assert code == 1 and "package_shadowed" in rules(report)


def _code_tree_change(w: World, change) -> None:
    raw = w.pyc("cli.py").read_bytes()
    stored = marshal.loads(raw[16:])  # noqa: S302 - a test-built file
    w.pyc("cli.py").write_bytes(raw[:16] + marshal.dumps(change(stored)))


def _nested(code, **fields):
    consts = tuple(c.replace(**fields) if hasattr(c, "co_code") else c for c in code.co_consts)
    return code.replace(co_consts=consts)


@pytest.mark.parametrize(
    ("change", "rule"),
    [
        (lambda c: _nested(c, co_qualname="evil"), "bytecode_body_differs"),
        (lambda c: _nested(c, co_stacksize=99), "bytecode_body_differs"),
        (lambda c: _nested(c, co_filename="/elsewhere/cli.py"), "bytecode_filename_differs"),
    ],
    ids=["nested-qualname", "nested-stacksize", "nested-filename-only"],
)
def test_bytecode_fields_that_code_equality_ignores_are_checked(change, rule, world, capsys):
    """S4 (and S8: the nested co_filename walk): the top-level code object is untouched."""
    _code_tree_change(world, change)
    stored = marshal.loads(world.pyc("cli.py").read_bytes()[16:])  # noqa: S302 - test-built
    assert stored.co_filename == str(world.pkg / "cli.py")
    code, report = verify(world, capsys)
    assert code == 1 and rule in rules(report), report["violations"]


@pytest.mark.parametrize(
    "rel",
    ["__pycache__/evil.so", "__pycache__/notes.txt", "__pycache__/__pycache__/x.pyc",
     f"store/__pycache__/ghost.{TAG}.pyc"],
)  # fmt: skip
def test_anything_unexpected_under_pycache_is_a_violation(rel, world, capsys):
    path = world.pkg / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x")
    code, report = verify(world, capsys)
    assert code == 1 and "unexpected_bytecode" in rules(report)


def test_the_manifest_digest_covers_the_whole_inventory():
    """S8: every measured section changes manifest_sha256; volatile fields do not."""
    measured = {
        "python": {"version": "3.12.3"}, "site": "/s", "package": {"a": 1}, "bytecode": {"a": 1},
        "dist_info": {"d": 1}, "startup_hooks": [], "user_site": None, "origin": "/s/b",
        "unowned": [], "distributions": [], "marker_environment": {"k": 1}, "record": "r",
        "errors": [], "located": ["/s/b"], "shadowed": [], "ld_so_preload": None,
        "irregular": [],
        "interpreter": {"prefix": "/p"},
    }  # fmt: skip
    digest = im.manifest_digest(measured)
    covered = {"python", "site", "package", "bytecode", "dist_info", "startup_hooks",
               "user_site", "origin", "unowned", "distributions", "shadowed", "irregular",
               "ld_so_preload", "interpreter"}  # fmt: skip
    for key in measured:
        changed = dict(measured, **{key: {"changed": True}})
        assert (im.manifest_digest(changed) != digest) == (key in covered), key


def test_unreadable_distribution_metadata_is_incomplete(world, capsys):
    """S9: metadata that cannot be read is not a proven mismatch."""
    d = world.site / "broken-1.0.dist-info"
    d.mkdir()
    (d / "METADATA").write_text("Metadata-Version: 2.1\n")  # no Name, no Version
    code, report = verify(world, capsys)
    assert (code, report["verdict"]) == (2, "INCOMPLETE")
    assert "unreadable distribution metadata" in report["incomplete"][0]


def test_image_controlled_text_is_bounded_and_escaped(world, capsys, monkeypatch):
    """S9: an image cannot flood or control the terminal through the report."""
    noisy = "\x1b[31m" + "A" * 10000
    monkeypatch.setattr(im, "run_command", _fail_runner(world, "docker", out=json.dumps(
        {"fatal": noisy})))  # fmt: skip
    code, report = verify(world, capsys)
    message = report["incomplete"][0]
    assert code == 2 and len(message) < 400 and "\x1b" not in message and "\\x1b" in message
    report_ = im.Report()
    for i in range(im.MAX_LISTED + 5):
        report_.violation("payload_extra", "\x1b" + "p" * 1000 + str(i))
    assert len(report_.violations) == im.MAX_LISTED
    assert report_.totals["violations"] == im.MAX_LISTED + 5
    assert all(len(v["path"]) < 330 and "\x1b" not in v["path"] for v in report_.violations)


# load-image.sh ------------------------------------------------------------------------

STUB_DOCKER = r"""#!/bin/sh
echo "$*" >> "$STUB_LOG"
shift 2  # --host <sock>
case "$1" in
  info) echo "$STUB_ROOT" ;;
  load) cat >/dev/null; printf '%b' "$STUB_LOAD_OUT"; exit "${STUB_LOAD_RC:-0}" ;;
  image) [ "${STUB_INSPECT_RC:-0}" -eq 0 ] || exit "$STUB_INSPECT_RC"
         eval "echo \$STUB_ID_$(echo "$5" | tr -c 'a-zA-Z0-9\n' _)" ;;
esac
"""
STUB_PYTHON = r"""#!/bin/sh
echo "python $*" >> "$STUB_LOG"
for arg in "$@"; do printf '%s\0' "$arg"; done > "$STUB_ARGV"
exit "$STUB_RC"
"""


def _load_image(tmp: Path, expected: str, rc: int = 0, loaded_id: str | None = None,
                local_id: str = "", load_out: str | None = None, load_rc: int = 0,
                inspect_rc: int = 0, drop_verifier: bool = False,
                ) -> tuple[subprocess.CompletedProcess, list[str]]:  # fmt: skip
    prefix = tmp / "prefix"
    (prefix / "venv" / "bin").mkdir(parents=True)
    (prefix / "src" / "scripts" / "service-account").mkdir(parents=True, exist_ok=True)
    if not drop_verifier:
        (prefix / "src" / "scripts" / "service-account" / "image_manifest.py").write_text("")
    python = prefix / "venv" / "bin" / "python"
    python.write_text(STUB_PYTHON)
    python.chmod(0o755)
    bindir = tmp / "bin"
    bindir.mkdir()
    (bindir / "docker").write_text(STUB_DOCKER)
    (bindir / "docker").chmod(0o755)
    log = tmp / "log"
    log.write_text("")
    ref = "brandsentinel-sandbox:b7"

    def key(r: str) -> str:
        return "STUB_ID_" + "".join(c if c.isalnum() else "_" for c in r)

    env = {
        "PATH": f"{bindir}:/usr/bin:/bin", "PREFIX": str(prefix), "MIN_FREE_GIB": "0",
        "XDG_RUNTIME_DIR": str(tmp), "STUB_LOG": str(log), "STUB_ROOT": str(tmp),
        "STUB_RC": str(rc), key(ref): loaded_id or expected,
        "STUB_LOAD_OUT": f"Loaded image: {ref}\\n" if load_out is None else load_out,
        "STUB_LOAD_RC": str(load_rc), "STUB_INSPECT_RC": str(inspect_rc),
        "STUB_ARGV": str(tmp / "argv"),
        key("brandsentinel-sandbox:local"): local_id,
    }  # fmt: skip
    done = subprocess.run(  # noqa: S603 - fixed argv, test-built stubs
        ["/bin/sh", str(REPO / "scripts" / "service-account" / "load-image.sh"), expected],
        capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL,
    )  # fmt: skip
    return done, log.read_text().splitlines()


@pytest.mark.parametrize(
    "expected",
    ["brandsentinel-sandbox:local", "sha256:" + "ab" * 31, "sha256:" + "ab" * 33,
     "sha256:" + "AB" * 32, "sha256:" + "ab" * 32 + "\nsha256:x", "x" + IMAGE_ID,
     IMAGE_ID + " ", "sha256:" + "ab" * 31 + "zz"],
    ids=["tag", "short", "long", "upper", "multi-line", "prefixed", "trailing", "non-hex"],
)  # fmt: skip
def test_load_image_refuses_a_malformed_id_before_loading(expected, tmp_path):
    done, log = _load_image(tmp_path, expected)
    assert done.returncode == 1 and "sha256:<64 hex digits>" in done.stderr
    assert not any(" load" in line for line in log)


@pytest.mark.parametrize(
    ("load_out", "load_rc", "message"),
    [
        ("Loaded image ID: sha256:" + "cd" * 32 + "\\n", 0, "now names an unverified image"),
        ("Loaded image: brandsentinel-sandbox:b7\\nLoaded image: other:tag\\n", 0,
         "other:tag now names an unverified image"),
        ("", 0, "reported no loaded image"),
        ("partial\\n", 1, "docker load failed"),
    ],
    ids=["id-line-other-image", "second-ref-unknown", "nothing-loaded", "load-fails"],
)  # fmt: skip
def test_load_image_refuses_a_stream_it_cannot_tie_to_the_expected_image(
    load_out, load_rc, message, tmp_path
):
    done, log = _load_image(tmp_path, IMAGE_ID, load_out=load_out, load_rc=load_rc)
    assert done.returncode == 1 and message in done.stderr, done.stderr
    assert not any(line.startswith("python") for line in log)


def test_load_image_does_not_warn_when_local_names_another_image(tmp_path):
    done, _ = _load_image(tmp_path, IMAGE_ID, rc=1, local_id="sha256:" + "cd" * 32)
    assert done.returncode == 1 and "WARNING" not in done.stderr


def test_load_image_refuses_a_stream_that_loaded_another_image(tmp_path):
    done, log = _load_image(tmp_path, IMAGE_ID, loaded_id="sha256:" + "cd" * 32)
    assert done.returncode == 1 and "now names an unverified image" in done.stderr
    assert not any(line.startswith("python") for line in log)


def test_load_image_runs_the_verifier_isolated_and_by_id(tmp_path):
    done, log = _load_image(tmp_path, IMAGE_ID)
    assert done.returncode == 0, done.stderr
    (call,) = [line for line in log if line.startswith("python")]
    assert call.startswith("python -I -B ")
    assert f"--image {IMAGE_ID} --expect-id {IMAGE_ID}" in call


@pytest.mark.parametrize("rc", [1, 2])
def test_load_image_propagates_a_failed_check_and_warns_about_local(rc, tmp_path):
    done, _ = _load_image(tmp_path, IMAGE_ID, rc=rc, local_id=IMAGE_ID)
    assert done.returncode == rc
    assert "brandsentinel-sandbox:local now names this unverified image" in done.stderr
    assert f"exited {rc}; the image stays loaded" in done.stderr


# Round-3 review remediation ------------------------------------------------------------


def _app_code(w: World):
    raw = w.pyc("cli.py").read_bytes()
    module = marshal.loads(raw[16:])  # noqa: S302 - a test-built file
    (app,) = [c for c in module.co_consts if hasattr(c, "co_code")]
    return raw, module, app


def test_a_specialized_opcode_hidden_from_co_code_is_detected(world, capsys):
    """co_code de-optimizes on read. A superinstruction placed over two LOAD_CONSTs
    changes what the function does, yet compares equal there: the raw instruction
    stream (_co_code_adaptive) is compared too. (Over a real LOAD_CONST, LOAD_FAST pair
    the interpreter inserts the same superinstruction itself, so that is not an attack.)"""
    opmaps = (getattr(dis, "_all_opmap", None), getattr(dis, "_specialized_opmap", None))
    specialized = next((m["LOAD_CONST__LOAD_FAST"] for m in opmaps
                        if m and "LOAD_CONST__LOAD_FAST" in m), None)  # fmt: skip
    if specialized is None:
        pytest.skip("this interpreter has no LOAD_CONST__LOAD_FAST")
    raw, module, app = _app_code(world)
    code = app.co_code
    const = dis.opmap["LOAD_CONST"]
    at = next(k for k in range(0, len(code) - 2, 2) if code[k] == const == code[k + 2])
    data = bytearray(raw)
    start = bytes(raw).find(code)
    assert start > 0 and bytes(raw).count(code) == 1
    data[start + at] = specialized
    world.pyc("cli.py").write_bytes(bytes(data))
    tampered = marshal.loads(bytes(data[16:]))  # noqa: S302 - a test-built file
    assert next(c for c in tampered.co_consts if hasattr(c, "co_code")).co_code == code
    genuine, planted = {}, {}
    exec(module, genuine)  # noqa: S102 - the test's own fixture code
    exec(tampered, planted)  # noqa: S102

    def outcome(ns):
        try:
            return ns["app"]()
        except Exception as error:  # any failure is a different outcome
            return type(error)

    assert outcome(genuine) != outcome(planted)  # the tampering changes behaviour
    code_, report = verify(world, capsys)
    assert code_ == 1 and "bytecode_body_differs" in rules(report)


@pytest.mark.parametrize(
    "fields",
    [
        {"co_code": None},  # a swapped base opcode
        {"co_names": ("evil",)},
        {"co_varnames": ("y",)},
        {"co_flags": "flip"},
        {"co_firstlineno": 99},
        {"co_argcount": 0},
        {"co_linetable": b""},
        {"co_name": "evil"},
    ],
    ids=lambda f: next(iter(f)),
)
def test_every_compared_code_field_is_checked(fields, world, capsys):
    raw, module, app = _app_code(world)
    if "co_code" in fields:
        code = bytearray(app.co_code)
        k = code.index(dis.opmap["BINARY_OP"])
        code[k + 1] = 10  # + becomes -
        fields = {"co_code": bytes(code)}
    if fields.get("co_flags") == "flip":
        fields = {"co_flags": app.co_flags ^ 0x20}  # CO_GENERATOR
    changed = app.replace(**fields)
    consts = tuple(changed if c is app else c for c in module.co_consts)
    world.pyc("cli.py").write_bytes(raw[:16] + marshal.dumps(module.replace(co_consts=consts)))
    code_, report = verify(world, capsys)
    assert code_ == 1 and "bytecode_body_differs" in rules(report), report["violations"]


@pytest.mark.parametrize("swap", [(1, True), (1, 1.0)], ids=["int-bool", "int-float"])
def test_a_constant_of_another_type_is_detected(swap, world, capsys):
    raw, module, app = _app_code(world)
    old, new = swap
    assert old in app.co_consts
    changed = app.replace(co_consts=tuple(new if c == old and type(c) is type(old) else c
                                          for c in app.co_consts))  # fmt: skip
    consts = tuple(changed if c is app else c for c in module.co_consts)
    world.pyc("cli.py").write_bytes(raw[:16] + marshal.dumps(module.replace(co_consts=consts)))
    code, report = verify(world, capsys)
    assert code == 1 and "bytecode_body_differs" in rules(report)


def test_a_stdlib_module_shadowing_a_dependency_is_detected(base_world, capsys):
    (base_world.base_lib / "dep_a.py").write_text("WHO = 'planted'\n")
    code, report = verify(base_world, capsys)
    assert code == 1 and "dependency_shadowed" in rules(report)


@pytest.mark.parametrize(
    "plant",
    [
        lambda s: (s / "dep_a").mkdir() or (s / "dep_a" / "__init__.py").write_text(""),
        lambda s: (s / "dep_a.cpython-312-x86_64-linux-gnu.so").write_bytes(b"\x7fELF"),
    ],
    ids=["package-beside-module", "extension-beside-module"],
)
def test_an_owned_entry_colliding_with_a_dependency_is_detected(plant, world, capsys):
    """Ownership is the image's own claim: a RECORD row could launder a planted entry,
    so colliding import names are reported whoever owns them."""
    plant(world.site)
    d = world.site / "dep_a-1.0.dist-info"
    rows = {r[0]: b"" for r in csv.reader(io.StringIO((d / "RECORD").read_text())) if r}
    rows |= {n: b"" for n in os.listdir(world.site) if n.startswith("dep_a")}
    write_record(d / "RECORD", {k: v for k, v in rows.items() if not k.endswith("RECORD")})
    code, report = verify(world, capsys)
    assert code == 1 and "dependency_shadowed" in rules(report), report["violations"]
    assert "site_unowned" not in rules(report)


@pytest.mark.parametrize(
    "row",
    [["planted.py", "", ""], ["other-1.0.dist-info/METADATA", "", ""]],
    ids=["module", "foreign-dist-info"],
)
def test_the_package_record_cannot_claim_foreign_entries(row, world, capsys):
    _rewrite_record(world, lambda rows: [*rows, row])
    code, report = verify(world, capsys)
    assert code == 1 and "record_mismatch" in rules(report)


def test_a_missing_package_record_is_a_mismatch(world, capsys):
    (world.site / DIST / "RECORD").unlink()
    code, report = verify(world, capsys)
    assert code == 1 and "record_mismatch" in rules(report)


def test_a_record_row_climbing_out_does_not_grant_ownership(world, capsys):
    (world.site / "planted.py").write_text("")
    d = world.site / "dep_a-1.0.dist-info"
    with open(d / "RECORD", "a") as record:
        record.write("planted.py/../x,,\n")
    code, report = verify(world, capsys)
    assert code == 1 and "site_unowned" in rules(report)


def test_path_interpreter_and_config_are_reported_and_bounded(world, capsys):
    world.config_env = ["PATH=/opt/decoy/bin:" + "x" * 5000, "PYTHONDONTWRITEBYTECODE=1"]
    original = world.runner

    def runner(argv, cwd=None, timeout=None, env=None):
        out = original(argv, cwd, timeout, env)
        if argv[3:5] == ["image", "inspect"]:
            data = json.loads(out)
            data["Config"]["Cmd"] = ["\x1b[2J" + "c" * 100000]
            data["Created"] = "C" * 1000
            return json.dumps(data)
        return out

    im.run_command = runner
    code, report = verify(world, capsys)
    assert code == 0, report["violations"]
    assert report["config"]["path"].startswith("/opt/decoy/bin:")
    assert len(report["config"]["path"]) < 600 and len(report["config"]["Cmd"]) < 600
    assert "\x1b" not in json.loads(json.dumps(report))["config"]["Cmd"]
    assert len(report["created"]) < 100
    assert report["interpreter"]["prefix"] == str(world.image)
    assert report["site"] == str(world.site)


def test_an_ld_so_preload_file_is_rejected(world, capsys, tmp_path, monkeypatch):
    preload = tmp_path / "ld.so.preload"
    preload.write_text("/x.so\n")
    monkeypatch.setattr(im, "INSIDE", im.INSIDE.replace("/etc/ld.so.preload", str(preload)))
    code, report = verify(world, capsys)
    assert code == 1 and "image_loader_environment" in rules(report)


class _Unhandled(BaseException):
    """Raised by a stand-in handler: SIGTERM reached a process that installed none."""


def _unhandled(signum, frame):
    raise _Unhandled(signum)


def test_sigterm_during_the_measurement_removes_its_container(world, capsys):
    before = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGHUP)}
    for sig in before:  # main() must replace these with its own
        signal.signal(sig, _unhandled)
    original = world.runner

    def runner(argv, cwd=None, timeout=None, env=None):
        if argv[3] == "run":
            os.kill(os.getpid(), signal.SIGTERM)
        return original(argv, cwd, timeout, env)

    im.run_command = runner
    argv = ["--profile", "release", "--docker-host", "unix:///fake.sock", "--source",
            str(world.source), "--wheel", str(world.wheel), "--expect-wheel-sha256",
            world.wheel_sha]  # fmt: skip
    try:
        with pytest.raises(SystemExit) as exit_:
            im.main(argv)
    finally:
        for sig, handler in before.items():
            signal.signal(sig, handler)
    assert exit_.value.code == 128 + signal.SIGTERM
    assert len(_rm_calls(world)) == 1


# Round-4 review remediation (R4-1 to R4-6) ---------------------------------------------


def _padded(position: int, variable: str) -> list[str]:
    env = [f"PAD_{i}=x" for i in range(max(position, 1) + 50)]
    env.insert(position, variable)
    return env


@pytest.mark.parametrize("profile", ["release", "load"])
@pytest.mark.parametrize("position", [0, 199, 200, 250])
def test_a_loader_variable_anywhere_in_the_environment_stops_the_run(
    position, profile, world, capsys
):
    """R4-1: every entry is judged; only the report is cut at ENV_REPORTED."""
    world.config_env = _padded(position, "LD_PRELOAD=/usr/lib/evil.so")
    code, report = verify(world, capsys, profile=profile)
    assert code == 1 and "image_loader_environment" in rules(report)
    assert report["measured"] is False and _runs(world) == []
    assert report["config"]["env_total"] == len(world.config_env)
    assert report["config"]["env_truncated"] is (len(world.config_env) > im.ENV_REPORTED)
    assert len(report["config"]["env_names"]) == min(len(world.config_env), im.ENV_REPORTED)


@pytest.mark.parametrize("profile", ["release", "load"])
@pytest.mark.parametrize("position", [0, 199, 200, 250])
def test_a_python_variable_anywhere_in_the_environment_is_a_mismatch(
    position, profile, world, capsys
):
    world.config_env = _padded(position, "PYTHONPATH=/srv/override")
    code, report = verify(world, capsys, profile=profile)
    assert code == 1 and rules(report) == {"image_environment"}
    assert any(v["path"] == "PYTHONPATH" for v in report["violations"])


def test_a_variable_set_twice_is_a_mismatch(world, capsys):
    world.config_env += ["PATH=/opt/decoy/bin"]
    code, report = verify(world, capsys)
    assert (
        code == 1
        and {"path": "PATH (set more than once)", "rule": "image_environment"}
        in (report["violations"])
    )
    assert report["config"]["path"] == "/opt/decoy/bin"  # the effective (last) value


@pytest.mark.parametrize(
    "env",
    [
        ["NOEQUALS"],
        ["=value"],
        [42],
        [None],
        "PATH=/usr/bin",
        {"PATH": "/usr/bin"},
        {},
        "",
        0,
        False,
    ],
    ids=[
        "no-equals",
        "empty-name",
        "not-a-string",
        "none-entry",
        "env-is-a-string",
        "env-is-a-dict",
        "empty-dict",
        "empty-string",
        "zero",
        "false",
    ],
)
def test_a_malformed_environment_is_incomplete_never_a_pass(env, world, capsys):
    world.config_env = env
    code, report = verify(world, capsys)
    assert (code, report["verdict"]) == (2, "INCOMPLETE") and _runs(world) == []


@pytest.mark.parametrize(
    "image_id",
    ["sha256:" + "AB" * 32, "sha256:" + "ab" * 31, "ab" * 32, "sha256:" + "ab" * 32 + "\n"],
    ids=["upper", "short", "unprefixed", "newline"],
)
def test_a_malformed_daemon_image_id_is_incomplete(image_id, world, capsys, monkeypatch):
    """R4-6: the inspected ID is format-checked before it is used, bound or not."""
    original = world.runner

    def runner(argv, cwd=None, timeout=None, env=None):
        out = original(argv, cwd, timeout, env)
        if argv[3:5] == ["image", "inspect"]:
            return json.dumps(dict(json.loads(out), Id=image_id))
        return out

    monkeypatch.setattr(im, "run_command", runner)
    code, report = verify(world, capsys)
    assert (code, report["verdict"]) == (2, "INCOMPLETE") and _runs(world) == []
    assert "malformed image ID" in report["incomplete"][0]


@pytest.mark.parametrize(
    "expected",
    [IMAGE_ID[:-1] + "c", "sha256:" + "ba" + "ab" * 31],
    ids=["last-nibble", "first-byte"],
)
def test_a_near_miss_expected_id_never_runs(expected, world, capsys):
    code, report = verify(world, capsys, profile="load", expect_id=expected)
    assert code == 1 and rules(report) == {"image_id_mismatch"} and _runs(world) == []


@pytest.mark.parametrize(
    "value",
    [IMAGE_ID.upper().replace("SHA256", "sha256"), IMAGE_ID[7:], IMAGE_ID + "0",
     IMAGE_ID + "\n", " " + IMAGE_ID],
    ids=["upper", "unprefixed", "long", "newline", "leading-space"],
)  # fmt: skip
def test_a_malformed_expected_id_is_refused(value):
    argv = ["--profile", "load", "--docker-host", "h", "--source", "s", "--installed", "p",
            "--expect-id", value]  # fmt: skip
    with pytest.raises(SystemExit) as exit_:
        im.parse(argv)
    assert exit_.value.code == 2


def test_a_symlinked_dependency_package_shadowed_from_the_stdlib(base_world, capsys):
    """R4-2: the round-4 reproduction. A symlinked top-level package is refused, and its
    name is still resolution-checked (the finder follows the symlink)."""
    w = base_world
    real = w.tmp / "elsewhere" / "dep_a"
    real.mkdir(parents=True)
    (real / "__init__.py").write_text("VERSION = '1.0'\n")
    (w.site / "dep_a.py").unlink()
    (w.site / "dep_a").symlink_to(real, target_is_directory=True)
    d = w.site / "dep_a-1.0.dist-info"
    write_record(d / "RECORD", {f"{d.name}/METADATA": (d / "METADATA").read_bytes(),
                                "dep_a/__init__.py": b"VERSION = '1.0'\n"})  # fmt: skip
    (w.base_lib / "dep_a.py").write_text("WHO = 'planted'\n")
    code, report = verify(w, capsys)
    assert code == 1
    assert {"site_not_regular", "dependency_shadowed"} <= rules(report), report["violations"]


@pytest.mark.parametrize("kind", ["file-symlink", "dangling-symlink", "fifo"])
def test_top_level_special_entries_are_refused(kind, world, capsys):
    target = world.site / "dep_a.py"
    entry = world.site / "special.py"
    if kind == "file-symlink":
        entry.symlink_to(target)
    elif kind == "dangling-symlink":
        entry.symlink_to(world.tmp / "nowhere.py")
    else:
        os.mkfifo(entry)
    code, report = verify(world, capsys)
    assert code == 1 and "site_not_regular" in rules(report)


def test_a_non_identifier_module_name_is_resolution_checked(base_world, capsys):
    """R4-4: importlib loads `odd-name` from odd-name.py; it is checked like any name."""
    w = base_world
    d = dist(w.site, "odd-name", "1.0", module=False)
    (w.site / "odd-name.py").write_text("OK = True\n")
    (w.site / "1abc__mypyc.cpython-312-x86_64-linux-gnu.so").write_bytes(b"\x7fELF")  # owned
    mypyc = "1abc__mypyc.cpython-312-x86_64-linux-gnu.so"
    write_record(d / "RECORD", {f"{d.name}/METADATA": (d / "METADATA").read_bytes(),
                                "odd-name.py": b"OK = True\n", mypyc: b"\x7fELF"})  # fmt: skip
    pins = PINS + "odd-name==1.0\n"
    original = w.runner
    im.run_command = lambda argv, cwd=None, timeout=None, env=None: (
        pins if Path(argv[0]).name == "uv" else original(argv, cwd, timeout, env)
    )
    code, report = verify(w, capsys)
    assert (code, report["violations"]) == (0, [])  # a faithful odd name passes
    (w.base_lib / "odd-name.py").write_text("OK = False\n")
    code, report = verify(w, capsys)
    assert code == 1 and "dependency_shadowed" in rules(report)


def _rewrite_code(w: World, rel: str, change) -> tuple:
    """Rewrite the .pyc of `rel` with `change(module_code)`; return (genuine, tampered)."""
    path = w.pkg / rel
    pyc = path.parent / "__pycache__" / f"{path.stem}.{TAG}.pyc"
    raw = pyc.read_bytes()
    module = marshal.loads(raw[16:])  # noqa: S302 - a test-built file
    tampered = change(module)
    pyc.write_bytes(raw[:16] + marshal.dumps(tampered))
    return module, tampered


def _function(module, name):
    return next(c for c in module.co_consts if hasattr(c, "co_code") and c.co_name == name)


def _replace_function(module, name, **fields):
    target = _function(module, name)
    consts = tuple(c.replace(**fields) if c is target else c for c in module.co_consts)
    return module.replace(co_consts=consts)


def _outer_change(field):
    def change(module):
        outer = _function(module, "outer")
        value = {
            "co_exceptiontable": b"",
            "co_posonlyargcount": 0,
            "co_kwonlyargcount": 0,
            "co_argcount": outer.co_argcount - 1,
            "co_cellvars": (*reversed(outer.co_cellvars), "extra"),
            "co_names": (*outer.co_names, "extra"),
            "co_firstlineno": outer.co_firstlineno + 1,
            "co_flags": outer.co_flags ^ 0x20,
        }[field]
        return _replace_function(module, "outer", **{field: value})

    return change


@pytest.mark.parametrize(
    "field",
    # co_nlocals is not here: the interpreter derives it from co_varnames and refuses a
    # code object where they disagree, so it cannot be forged on its own.
    ["co_exceptiontable", "co_posonlyargcount", "co_kwonlyargcount", "co_argcount",
     "co_cellvars", "co_names", "co_firstlineno", "co_flags"],
)  # fmt: skip
def test_behaviourally_significant_code_fields_are_compared(field, world, capsys):
    try:
        _rewrite_code(world, "store/ops.py", _outer_change(field))
    except ValueError as error:  # the interpreter refuses that combination outright
        pytest.fail(f"cannot build the damaged code for {field}: {error}")
    code, report = verify(world, capsys)
    assert code == 1 and "bytecode_body_differs" in rules(report), report["violations"]


def test_a_free_variable_change_in_a_nested_closure_is_compared(world, capsys):
    def change(module):
        outer = _function(module, "outer")
        inner = next(c for c in outer.co_consts if hasattr(c, "co_code"))
        consts = tuple(inner.replace(co_freevars=tuple(reversed(inner.co_freevars)))
                       if c is inner else c for c in outer.co_consts)  # fmt: skip
        return _replace_function(module, "outer", co_consts=consts)

    _rewrite_code(world, "store/ops.py", change)
    code, report = verify(world, capsys)
    assert code == 1 and "bytecode_body_differs" in rules(report)


@pytest.mark.parametrize(
    ("old", "new"),
    [((1, (2, 3)), (1, (2,))), (-0.0, 0.0), (frozenset({"x", "y"}), frozenset({"x"}))],
    ids=["tuple-length", "negative-zero", "frozenset"],
)
def test_constant_rules_are_compared(old, new, world, capsys):
    def change(module):
        outer = _function(module, "outer")
        assert any(type(c) is type(old) and repr(c) == repr(old) for c in outer.co_consts)
        consts = tuple(new if type(c) is type(old) and repr(c) == repr(old) else c
                       for c in outer.co_consts)  # fmt: skip
        return _replace_function(module, "outer", co_consts=consts)

    _rewrite_code(world, "store/ops.py", change)
    code, report = verify(world, capsys)
    assert code == 1 and "bytecode_body_differs" in rules(report)


def test_bytecode_compiled_with_optimization_is_refused(world, capsys):
    """An optimized compile drops the assert: the code differs from optimize=0."""
    src = world.pkg / "store" / "ops.py"
    py_compile.compile(str(src), cfile=str(src.parent / "__pycache__" / f"ops.{TAG}.pyc"),
                       optimize=1, doraise=True)  # fmt: skip
    code, report = verify(world, capsys)
    assert code == 1 and "bytecode_body_differs" in rules(report)


def test_reordered_local_and_cell_slots_are_detected(world, capsys):
    """R4-3: a forged slot layout changes locals() yet keeps every exposed field."""
    path = world.pkg / "store" / "slots.py"
    pyc = path.parent / "__pycache__" / f"slots.{TAG}.pyc"
    data = pyc.read_bytes()
    blob = marshal.dumps(marshal.loads(data[16:]), 2)  # noqa: S302 - a test-built file
    names = marshal.dumps(("aa", "bb", "gg", "cc"), 2)
    kinds = marshal.dumps(bytes([0x20, 0x20, 0x20, 0x40]), 2)
    assert blob.count(names) == 1 and blob.count(kinds) == 1
    forged = blob.replace(names, marshal.dumps(("aa", "bb", "cc", "gg"), 2)).replace(
        kinds, marshal.dumps(bytes([0x20, 0x20, 0x40, 0x20]), 2)
    )
    genuine, tampered = {}, {}
    exec(marshal.loads(data[16:]), genuine)  # noqa: S102, S302 - the test's own fixture
    exec(marshal.loads(forged), tampered)  # noqa: S102, S302
    assert genuine["f"]() != tampered["f"]()  # behaviour changes
    pyc.write_bytes(data[:16] + forged)
    code, report = verify(world, capsys)
    assert code == 1 and "bytecode_body_differs" in rules(report)


def test_valid_closure_and_exception_bytecode_passes(world, capsys):
    """R4-3 positive: genuine py_compile output for every fixture shape is accepted,
    in timestamp and hash modes."""
    for mode in (py_compile.PycInvalidationMode.TIMESTAMP,
                 py_compile.PycInvalidationMode.CHECKED_HASH):  # fmt: skip
        for rel in ("store/ops.py", "store/slots.py"):
            py_compile.compile(str(world.pkg / rel), doraise=True, invalidation_mode=mode)
        code, report = verify(world, capsys)
        assert (code, report["violations"]) == (0, [])


# The real command runner, the subprocess boundary and signals ------------------------


def _stub(tmp: Path, name: str, body: str) -> Path:
    path = tmp / "bin" / name
    path.parent.mkdir(exist_ok=True)
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)
    return path


def test_the_real_runner_enforces_its_timeout(tmp_path):
    slow = _stub(tmp_path, "slow", "sleep 5\n")
    with pytest.raises(subprocess.TimeoutExpired):
        im.run_command([str(slow)], timeout=1)


def test_the_real_runner_raises_on_a_failing_command(tmp_path):
    bad = _stub(tmp_path, "bad", "echo boom >&2; exit 3\n")
    with pytest.raises(subprocess.CalledProcessError) as error:
        im.run_command([str(bad)])
    assert error.value.returncode == 3 and "boom" in error.value.stderr


def test_a_failing_real_docker_is_incomplete(tmp_path, monkeypatch):
    docker = _stub(tmp_path, "docker", 'echo "Error: daemon unreachable" >&2; exit 1\n')
    monkeypatch.setattr(im, "docker_binary", lambda: str(docker))
    with pytest.raises(im.Incomplete, match="daemon unreachable"):
        im.docker("unix:///x.sock", "image", "inspect", "x")


@pytest.mark.parametrize(
    ("body", "result"),
    [("exit 0\n", None), ('echo "Error: No such container: c" >&2; exit 1\n', None),
     ('echo "Error: daemon unreachable" >&2; exit 1\n', "daemon unreachable"),
     ("sleep 5\n", "timed out")],
    ids=["removed", "already-gone", "daemon-down", "hangs"],
)  # fmt: skip
def test_real_container_removal_reports_failures(body, result, tmp_path, monkeypatch):
    docker = _stub(tmp_path, "docker", body)
    monkeypatch.setattr(im, "docker_binary", lambda: str(docker))
    monkeypatch.setattr(im, "CLEANUP_TIMEOUT_SECONDS", 1)
    problem = im.remove_container("unix:///x.sock", "c")
    assert problem is None if result is None else result in problem


def test_a_hung_real_measurement_times_out_and_removes_its_container(tmp_path, monkeypatch):
    log = tmp_path / "docker.log"
    docker = _stub(tmp_path, "docker", f'echo "$*" >> {log}\ncase "$3" in run) sleep 5;; esac\n')
    monkeypatch.setattr(im, "docker_binary", lambda: str(docker))
    monkeypatch.setattr(im, "TIMEOUT_SECONDS", 1)
    with pytest.raises(im.Incomplete, match="timed out"):
        im.measure("unix:///x.sock", IMAGE_ID)
    calls = log.read_text().splitlines()
    name = calls[0].split("--name ")[1].split()[0]
    assert calls[-1].endswith(f"rm -f {name}")


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGHUP], ids=["SIGTERM", "SIGHUP"])
@pytest.mark.parametrize("cleanup_fails", [False, True], ids=["removed", "removal-fails"])
def test_a_signal_during_the_measurement_removes_or_reports_its_container(
    signum, cleanup_fails, world, capsys
):
    before = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGHUP)}
    for sig in before:
        signal.signal(sig, _unhandled)
    if cleanup_fails:
        world.rm_error = subprocess.CalledProcessError(1, ["docker"], stderr="daemon unreachable")
    original = world.runner

    def runner(argv, cwd=None, timeout=None, env=None):
        if argv[3] == "run":
            os.kill(os.getpid(), signum)
        return original(argv, cwd, timeout, env)

    im.run_command = runner
    argv = ["--profile", "release", "--docker-host", "unix:///fake.sock", "--source",
            str(world.source), "--wheel", str(world.wheel), "--expect-wheel-sha256",
            world.wheel_sha]  # fmt: skip
    try:
        with pytest.raises(SystemExit) as exit_:
            im.main(argv)
    finally:
        for sig, handler in before.items():
            signal.signal(sig, handler)
    assert exit_.value.code == 128 + signum and len(_rm_calls(world)) == 1
    captured = capsys.readouterr()
    assert ("may still be running" in captured.err) is cleanup_fails
    assert '"verdict"' not in captured.out  # no report on a signal


def test_a_report_that_cannot_be_written_is_never_a_pass(world, capsys, monkeypatch):
    def broken(*args, **kwargs):
        raise BrokenPipeError

    monkeypatch.setattr("builtins.print", broken)
    argv = ["--profile", "release", "--docker-host", "unix:///fake.sock", "--source",
            str(world.source), "--wheel", str(world.wheel), "--expect-wheel-sha256",
            world.wheel_sha]  # fmt: skip
    assert im.main(argv) == 2


# load-image.sh: inspection failure and argument forwarding ---------------------------


def test_load_image_refuses_when_inspection_fails(tmp_path):
    done, log = _load_image(tmp_path, IMAGE_ID, inspect_rc=1)
    assert done.returncode == 1 and "cannot inspect brandsentinel-sandbox:b7" in done.stderr
    assert not any(line.startswith("python") for line in log)


def test_load_image_forwards_exactly_the_verified_arguments(tmp_path):
    done, _ = _load_image(tmp_path, IMAGE_ID)
    assert done.returncode == 0, done.stderr
    argv = (tmp_path / "argv").read_bytes().split(b"\0")[:-1]
    argv = [a.decode() for a in argv]
    prefix = tmp_path / "prefix"
    assert argv[:3] == ["-I", "-B", str(prefix / "src/scripts/service-account/image_manifest.py")]
    a = im.parse(argv[3:])
    assert (a.profile, a.image, a.expect_id) == ("load", IMAGE_ID, IMAGE_ID)
    assert (a.source, a.installed) == (prefix / "src", prefix)
    assert a.docker_host == f"unix://{tmp_path}/docker.sock"


# Round-5 follow-ups --------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE", "PYTHONINSPECT", "PYTHONSAFEPATH",
     "PYTHONNOUSERSITE", "PYTHONPATH", "PYTHON"],
)  # fmt: skip
def test_every_unreviewed_python_variable_is_a_mismatch(name, world, capsys):
    world.config_env.append(f"{name}=1")
    code, report = verify(world, capsys)
    assert code == 1 and {"rule": "image_environment", "path": name} in report["violations"]


def test_a_loader_variable_set_twice_is_both_rejected_and_never_run(world, capsys):
    world.config_env += ["LD_PRELOAD=", "LD_PRELOAD=/x.so=y"]
    code, report = verify(world, capsys)
    assert code == 1 and report["measured"] is False and _runs(world) == []
    assert {"image_loader_environment", "image_environment"} <= rules(report)


@pytest.mark.parametrize("config", [[], False, "x"], ids=["list", "false", "string"])
def test_an_image_config_that_is_not_an_object_is_incomplete(config, world, capsys):
    world.config_override = config
    code, report = verify(world, capsys)
    assert (code, report["verdict"]) == (2, "INCOMPLETE") and _runs(world) == []


def test_a_missing_image_config_is_an_empty_one(world, capsys):
    world.config_override = None
    code, report = verify(world, capsys)
    assert (code, report["violations"]) == (0, [])
    assert report["config"]["env_total"] == 0


@pytest.mark.parametrize(
    ("name", "expected"),
    [("owned.dist-info", 2), ("owned.pth", 2), ("__pycache__", 1)],
)
def test_symlinked_skipped_kinds_are_never_a_pass(name, expected, world, capsys):
    """The lstat check runs before the dist-info/.pth/__pycache__ skip. A symlinked
    dist-info is also read as a distribution with no metadata, and a .pth symlinked to a
    directory cannot be hashed: both make the inspection incomplete instead."""
    (world.site / name).symlink_to(world.tmp)
    code, report = verify(world, capsys)
    assert code == expected and report["verdict"] != "ok"
    if code == 1:
        assert "site_not_regular" in rules(report)


EXT = importlib.machinery.EXTENSION_SUFFIXES[0]


def _owned_module(w: World, name: str, files: dict[str, bytes]) -> None:
    d = dist(w.site, name, "1.0", module=False)
    for rel, data in files.items():
        (w.site / rel).parent.mkdir(parents=True, exist_ok=True)
        (w.site / rel).write_bytes(data)
    write_record(d / "RECORD", {f"{d.name}/METADATA": (d / "METADATA").read_bytes(), **files})
    original = w.runner
    pins = PINS + f"{name}==1.0\n"
    im.run_command = lambda argv, cwd=None, timeout=None, env=None: (
        pins if Path(argv[0]).name == "uv" else original(argv, cwd, timeout, env)
    )


def test_an_extension_module_shadowed_from_the_stdlib_is_detected(base_world, capsys):
    _owned_module(base_world, "fastmod", {f"fastmod{EXT}": b"\x7fELF"})
    code, report = verify(base_world, capsys)
    assert (code, report["violations"]) == (0, [])  # control: the owned extension passes
    (base_world.base_lib / "fastmod.py").write_text("")
    code, report = verify(base_world, capsys)
    assert code == 1 and "dependency_shadowed" in rules(report)


@pytest.mark.parametrize(
    "files",
    [{"dupmod.py": b"", f"dupmod{EXT}": b"\x7fELF"},
     {"dupmod.py": b"", "dupmod/mod.py": b""}],
    ids=["module-and-extension", "module-and-namespace-dir"],
)  # fmt: skip
def test_two_owned_entries_with_one_import_name_are_detected(files, world, capsys):
    _owned_module(world, "dupmod", files)
    code, report = verify(world, capsys)
    assert code == 1 and "dependency_shadowed" in rules(report), report["violations"]


def test_the_lock_export_runs_in_the_source_tree(world, tmp_path, monkeypatch):
    """The real runner, with a stub uv that only answers from the source directory."""
    uv = _stub(tmp_path, "uv", f'[ "$(pwd)" = "{world.source.resolve()}" ] && echo "dep-a==9.9"\n')
    monkeypatch.setattr(im, "run_command", REAL_RUN_COMMAND)
    monkeypatch.setattr(im.shutil, "which", lambda name: str(uv) if name == "uv" else None)
    assert im.expected_pins(world.source) == [("dep-a", "9.9", None)]


def test_long_and_hostile_environment_names_are_bounded(world, capsys):
    world.config_env = ["X" * 10000 + "\x1b=1"]
    code, report = verify(world, capsys)
    (name,) = report["config"]["env_names"]
    assert code == 0 and len(name) < 130 and "\x1b" not in name


def _script_main(tmp: Path, world_source: Path) -> str:
    """A process running the verifier's main() whose inspection is INCOMPLETE."""
    return (
        "import importlib.util, subprocess, sys\n"
        f"spec = importlib.util.spec_from_file_location('m', {str(SCRIPT)!r})\n"
        "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
        "def fail(argv, cwd=None, timeout=None):\n"
        "    raise subprocess.CalledProcessError(1, argv, stderr='no daemon')\n"
        "m.run_command = fail\n"
        f"sys.exit(m.main(['--profile', 'release', '--docker-host', 'h', '--source', "
        f"{str(world_source)!r}, '--wheel', 'w', '--expect-wheel-sha256', {'ab' * 32!r}]))\n"
    )


@pytest.mark.parametrize("stdout", ["closed", "full"])
def test_a_report_nobody_receives_exits_2_in_a_real_process(stdout, world, tmp_path):
    script = tmp_path / "run.py"
    script.write_text(_script_main(tmp_path, world.source))
    redirect = ">&-" if stdout == "closed" else ">/dev/full"
    done = subprocess.run(  # noqa: S603 - fixed argv, test-built script
        ["/bin/sh", "-c", f'"{sys.executable}" "{script}" {redirect}'],
        capture_output=False, stderr=subprocess.DEVNULL, check=False,
    )  # fmt: skip
    assert done.returncode == 2


def test_load_image_refuses_before_any_docker_call(tmp_path):
    done, log = _load_image(tmp_path, "ab" * 32)  # unprefixed
    assert done.returncode == 1 and log == []


def test_load_image_refuses_without_a_verifier_before_any_docker_call(tmp_path):
    done, log = _load_image(tmp_path, IMAGE_ID, drop_verifier=True)
    assert done.returncode == 1 and "no verifier" in done.stderr and log == []


def test_every_load_image_docker_call_names_the_account_daemon(tmp_path):
    done, log = _load_image(tmp_path, IMAGE_ID)
    assert done.returncode == 0
    docker_calls = [line for line in log if not line.startswith("python")]
    assert docker_calls and all(
        line.startswith(f"--host unix://{tmp_path}/docker.sock ") for line in docker_calls
    )

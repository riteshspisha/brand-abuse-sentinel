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

FILES = {
    "__init__.py": b'"""The package."""\n',
    # Two LOAD_CONSTs in a row (a superinstruction target) and a BINARY_OP.
    "cli.py": b"def app(x=0):\n    return min(100, 1) + x\n",
    "store/__init__.py": b"",
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
        self.run_error: BaseException | None = None  # raised by `docker run`
        self.rm_error: BaseException | None = None  # raised by `docker rm -f`

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

    def runner(self, argv, cwd=None, timeout=None):
        name = Path(argv[0]).name
        if name == "docker":
            self.docker_calls.append(argv)
            args = argv[3:]
            if args[:2] == ["image", "inspect"]:
                assert args[2:4] == ["--format", "{{json .}}"]
                config = {"Env": self.config_env, "User": "pwuser", "Entrypoint": None}
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
                    [self.python, *flags], check=True, capture_output=True, text=True, env=env
                ).stdout
        if name == "uv":
            assert {"--frozen", "--offline", "--no-dev", "--no-emit-project"} <= set(argv)
            assert argv[argv.index("--extra") + 1] == "sandbox"
            assert cwd == self.source
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
    def runner(argv, cwd=None, timeout=None):
        if Path(argv[0]).name == name and (name != "docker" or "run" in argv):
            if error is not None:
                raise error
            return out
        return w.runner(argv, cwd, timeout)

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
    world_runner = lambda argv, cwd=None, timeout=None: (  # noqa: E731
        pins if Path(argv[0]).name == "uv" else original(argv, cwd, timeout)
    )
    im.run_command = world_runner
    code, report = verify(world, capsys)
    assert (code, report["violations"]) == (0, [])


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
        "interpreter": {"prefix": "/p"},
    }  # fmt: skip
    digest = im.manifest_digest(measured)
    covered = {"python", "site", "package", "bytecode", "dist_info", "startup_hooks",
               "user_site", "origin", "unowned", "distributions", "shadowed",
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
  image) eval "echo \$STUB_ID_$(echo "$5" | tr -c 'a-zA-Z0-9\n' _)" ;;
esac
"""
STUB_PYTHON = r"""#!/bin/sh
echo "python $*" >> "$STUB_LOG"
exit "$STUB_RC"
"""


def _load_image(tmp: Path, expected: str, rc: int = 0, loaded_id: str | None = None,
                local_id: str = "", load_out: str | None = None, load_rc: int = 0,
                ) -> tuple[subprocess.CompletedProcess, list[str]]:  # fmt: skip
    prefix = tmp / "prefix"
    (prefix / "venv" / "bin").mkdir(parents=True)
    (prefix / "src" / "scripts" / "service-account").mkdir(parents=True)
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
        "STUB_LOAD_RC": str(load_rc),
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

    def runner(argv, cwd=None, timeout=None):
        out = original(argv, cwd, timeout)
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

    def runner(argv, cwd=None, timeout=None):
        if argv[3] == "run":
            os.kill(os.getpid(), signal.SIGTERM)
        return original(argv, cwd, timeout)

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

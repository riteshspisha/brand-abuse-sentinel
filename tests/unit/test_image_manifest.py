"""The sandbox-image verifier (scripts/service-account/image_manifest.py; B7 PR-2).

A real virtual environment stands in for the image: the verifier's in-image script runs
for real under that environment's interpreter, and only the `docker` and `uv` calls are
faked. Every damage case starts from a world asserted to pass and must flip the
verdict, and a completeness test ties each rule to a case.
"""

import base64
import csv
import hashlib
import importlib.util
import io
import json
import marshal
import os
import py_compile
import shutil
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
    "cli.py": b"def app():\n    return 0\n",
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


def dist(site: Path, name: str, version: str, dirname: str | None = None) -> Path:
    d = site / (dirname or f"{name.replace('-', '_')}-{version}.dist-info")
    d.mkdir()
    (d / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n")
    return d


class World:
    """A source tree, a release wheel, an image stand-in and an installation."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
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
        venv = [sys.executable, "-m", "venv", "--without-pip", str(self.image)]
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
        dist(self.site, "pip", "24.0")
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

    def runner(self, argv, cwd=None):
        name = Path(argv[0]).name
        if name == "docker":
            self.docker_calls.append(argv)
            args = argv[3:]
            if args[:2] == ["image", "inspect"]:
                assert args[2:4] == ["--format", "{{json .}}"]
                config = {"Env": self.config_env, "User": "pwuser", "Entrypoint": None}
                return json.dumps({"Id": IMAGE_ID, "Created": self.created, "Config": config})
            if args[0] == "run":
                assert IMAGE_ID in args, "the measurement must run the inspected ID"
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
         "--expect-id", "x", "--wheel", "w"],
        ["--profile", "load", "--docker-host", "h", "--source", "s", "--installed", "p",
         "--expect-id", "x", "--expect-wheel-sha256", "y"],
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
    call = text[text.index("image_manifest.py") :]
    assert "--profile load" in call and '--installed "$PREFIX"' in call
    assert '--expect-id "$EXPECTED"' in call


def _incomplete(code: int, report: dict, words: str) -> None:
    assert (code, report["verdict"]) == (2, "INCOMPLETE")
    assert words in report["incomplete"][0]


def _fail_runner(w: World, name: str, error: Exception | None = None, out: str | None = None):
    def runner(argv, cwd=None):
        if Path(argv[0]).name == name and (name != "docker" or "run" in argv):
            if error is not None:
                raise error
            return out
        return w.runner(argv, cwd)

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
    "inspect-not-json": (lambda w, m: m.setattr(im, "run_command", lambda argv, cwd=None: "[]"),
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
        next((w.prefix / "venv").rglob("site-packages")), "brandsentinel", "0.2.0"),
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


def _shadow(w: World) -> dict:
    shadow = w.enable_user_site() / "brandsentinel"  # the user site precedes the venv's
    shadow.mkdir()
    (shadow / "__init__.py").write_text("")
    return {}


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
    "dist_info_count": lambda w: dist(w.site, "brandsentinel", "0.2.0") and {},
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
    "package_shadowed": _shadow,
    "startup_hook": lambda w: (w.site / "zzz.pth").write_text("/nonexistent\n") and {},
    "dependency_missing": lambda w: shutil.rmtree(w.site / "dep_a-1.0.dist-info") or {},
    "dependency_version": _bump_version,
    "dependency_outside_venv": _outside,
    "user_site": lambda w: w.enable_user_site() and {},
    "image_environment": lambda w: w.config_env.append("PYTHONPATH=/srv/override") or {},
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


def test_every_rule_has_a_damage_case():
    assert set(CASES) == set(im.RULES)

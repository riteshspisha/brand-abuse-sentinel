"""Identity, provenance and contents of the sandbox image (SP1; B7 PR-2).

Checks an image on one Docker endpoint against references kept outside it. One
network-less container run (`--network none --pull never`) measures the image; every
comparison happens here.

    # Build time, developer: the evidence recorded for a release.
    python image_manifest.py --profile release \
        --docker-host unix:///run/user/N/docker.sock --source . \
        --wheel <release wheel> --expect-wheel-sha256 <its recorded sha256> \
        [--expect-id sha256:...] [--expect-manifest-sha256 <sha256>]

    # Load time, service account (load-image.sh).
    <prefix>/venv/bin/python image_manifest.py --profile load \
        --docker-host unix:///run/user/N/docker.sock --source <prefix>/src \
        --installed <prefix> --expect-id sha256:... [--expect-manifest-sha256 <sha256>]

Exit status: 0 every check of the profile passed; 1 a mismatch; 2 the inspection is
incomplete, so nothing can be concluded. Incomplete outranks a mismatch, and any
failure to look counts as incomplete, never as a pass.

Checked against the references:
- payload: every entry under the image's installed `brandsentinel/` outside
  `__pycache__` (sources, data, assets) is a regular file whose name and sha256 equal
  the reference package's; nothing missing, extra or changed. The reference package
  must itself equal `<source>/src/brandsentinel`;
- bytecode: every `__pycache__` entry is the bytecode of a package source for the
  image's interpreter, nothing else. Each one's header matches its source, and its
  code objects equal `compile(source, in-image path)` (the B2 method), with every
  nested `co_filename` equal to the in-image path, because code equality ignores it;
- metadata: exactly one `brandsentinel-*.dist-info`. Every file of the reference's
  dist-info except `RECORD` (`METADATA`, `WHEEL`, `entry_points.txt`, ...) is
  byte-equal in the image. Installer-written files are excluded and listed, and the
  image `RECORD`'s package entries must match the measured hashes;
- import path: measured under `-S`, so no startup hook runs first. `brandsentinel`
  resolves to the virtual environment's copy; there is no user site-packages
  directory; the environment's site-packages holds no startup hook (`*.pth`,
  `sitecustomize`, `usercustomize`); and the image config sets no Python variable
  besides `PYTHONDONTWRITEBYTECODE` and `PYTHONUNBUFFERED`. Startup hooks of the
  base image (system site-packages, the standard library) are hashed into the
  manifest and listed as excluded, not judged;
- dependencies (release profile): the distributions the image resolves equal the
  exact pins of `uv export --frozen --offline --no-dev --extra sandbox` of the
  source, after evaluating their markers in the image's environment; each comes from
  the virtual environment, and nothing else is installed there except the seeded
  `pip`;
- identity: the wheel's sha256 equals `--expect-wheel-sha256` (required by
  `release`); the image ID equals `--expect-id` (required by `load`); the manifest
  digest equals `--expect-manifest-sha256` when given. Expected values must be full
  sha256 digests.

Exclusions are by exact name and place, and only these: `__pycache__` entries
(judged by the bytecode rules instead), and the dist-info files an installer writes
(`INSTALLER_FILES`), whose contents are not judged (none of them is imported or
executed; `RECORD`'s package entries are cross-checked). Any other extra file in the
package or the dist-info is a violation.

References by profile: `release` uses the release wheel, the source tree and its
lock. `load` uses the installed source tree and the installed package under
`--installed`. Its dependency set is not re-derived (the account has no uv); it is
bound to the release check through the image ID, which `load` requires.

Binding and approval: `binding` in the report says what each result is tied to. A
`release` result whose image ID is not bound (no `--expect-id`, as at build time)
checks the image against the approved wheel and the lock; it identifies the image
(`image_id`, `manifest_sha256`) but does not approve it. Approval is the owner's
decision, recorded with the wheel's sha256, the image ID, the manifest digest and this
result in sealed build evidence kept outside the repository. `load` must be given the
image ID from that record; this tool cannot tell where an argument came from.

Trust: the image ID is the anchor. It names the image config and so every layer's
content. The measurement runs the image's own interpreter, so it shows that the
image matches the references, but it cannot vouch for an image it measures.
The measured image is addressed by the ID that was compared, never by the tag.
`manifest_sha256`, a digest of the measured inventory without the creation time or
host paths, identifies a measurement for the release record. It is stable for one
image, not across rebuilds. It is never trusted in
place of the image ID. Not checked: the contents of dependency files (pip enforced
their wheel hashes at build time; afterwards only the image ID binds them), the
base image's system packages beyond their names and versions, and launchers in the
image's `bin/`.

Assumptions proven only against stand-ins, to be verified on the real image (U3):
pip installed the package under `sysconfig` purelib of the environment's own scheme
and compiled timestamp bytecode at that path; `site.venv()`/`site.getsitepackages()`
behave on the image's Ubuntu interpreter as upstream (system dist-packages from
`--system-site-packages`); pip installed every pin into the environment rather than
reusing a system distribution; the base image sets no other `PYTHON*` variable; and
the base image's system startup hooks are known and acceptable (reviewed, not judged
here).
"""

import argparse
import base64
import csv
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

IMAGE = "brandsentinel-sandbox:local"
PACKAGE = "brandsentinel"
SCHEMA = "brandsentinel-image-manifest/2"

RULES = {
    "image_id_mismatch": "the image ID is not the expected one",
    "wheel_sha256_mismatch": "the wheel is not the expected one",
    "manifest_sha256_mismatch": "the measured manifest is not the expected one",
    "reference_mismatch": "the reference package differs from the source tree",
    "payload_missing": "a reference package file is missing from the image",
    "payload_extra": "the image package has a file the reference does not",
    "payload_modified": "an image package file differs from the reference",
    "payload_not_regular": "an image package entry is not a regular file or directory",
    "unexpected_bytecode": "a __pycache__ entry that is not the bytecode of a package source",
    "bytecode_missing": "a package source has no bytecode",
    "bytecode_not_regular": "the bytecode is not a regular file",
    "bytecode_bad_header": "the bytecode is shorter than its header",
    "bytecode_bad_magic": "the bytecode is for another interpreter",
    "bytecode_bad_flags": "the bytecode header has unknown flags",
    "bytecode_stale_header": "the timestamp header does not match the source",
    "bytecode_hash_mismatch": "the hash header does not match the source",
    "bytecode_bad_body": "the bytecode body does not load as a code object",
    "bytecode_source_invalid": "the source does not compile",
    "bytecode_body_differs": "the bytecode was not compiled from this source",
    "bytecode_filename_differs": "the bytecode was compiled for another path",
    "dist_info_count": "not exactly one brandsentinel dist-info",
    "metadata_missing": "a reference dist-info file is missing from the image",
    "metadata_modified": "an image dist-info file differs from the reference",
    "metadata_extra": "the image dist-info has a file that is neither reference nor installer",
    "record_mismatch": "the image RECORD disagrees with the measured package",
    "package_shadowed": "brandsentinel does not resolve to the environment's copy",
    "startup_hook": "a startup hook (.pth, sitecustomize, usercustomize) in the environment",
    "user_site": "a user site-packages directory that every process would import from",
    "image_environment": "the image config sets a Python variable that changes imports",
    "dependency_missing": "a pinned dependency is not installed",
    "dependency_version": "a dependency's version differs from its pin",
    "dependency_outside_venv": "a pinned dependency resolves outside the environment",
    "dependency_unexpected": "a distribution in the environment that is not pinned",
    "dependency_duplicate": "a distribution is installed twice in the environment",
}

# dist-info files the installer writes; they are not part of the wheel.
INSTALLER_FILES = {
    "INSTALLER": "written by the installer",
    "REQUESTED": "written by the installer",
    "direct_url.json": "written by the installer (the install source's location)",
    "RECORD": "rewritten by the installer; its package entries are cross-checked",
    "uv_cache.json": "written by uv (holds an install timestamp)",
}
# Python variables an image config may set: neither changes what is imported.
IMAGE_ENV_ALLOWED = {"PYTHONDONTWRITEBYTECODE", "PYTHONUNBUFFERED"}
TIMEOUT_SECONDS = 600
# Distributions in the image's environment that do not come from the lock.
SEEDED = {"pip": "seeded into the environment by python3 -m venv (ensurepip)"}

# Runs in the image, under its own interpreter. It must not import brandsentinel.
INSIDE = r"""
import hashlib, importlib.machinery, importlib.metadata, importlib.util, json, marshal, os
import platform, site, stat, sys, sysconfig, types

def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()

def kind(mode):
    if stat.S_ISREG(mode): return "file"
    if stat.S_ISDIR(mode): return "dir"
    if stat.S_ISLNK(mode): return "symlink"
    return "other"

def codes(code):
    yield code
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            yield from codes(const)

def judge(src, pyc):
    try:
        info = os.lstat(pyc)
    except FileNotFoundError:
        return "missing", None
    except OSError:
        return "unreadable", None
    if not stat.S_ISREG(info.st_mode):
        return "not_regular", None
    try:
        with open(pyc, "rb") as f: data = f.read()
        with open(src, "rb") as f: source = f.read()
        st = os.stat(src)
    except OSError:
        return "unreadable", None
    if len(data) < 16: return "bad_header", None
    if data[:4] != importlib.util.MAGIC_NUMBER: return "bad_magic", None
    flags = int.from_bytes(data[4:8], "little")
    if flags == 0:
        mode = "timestamp"
        if (int.from_bytes(data[8:12], "little") != int(st.st_mtime) & 0xFFFFFFFF
                or int.from_bytes(data[12:16], "little") != st.st_size & 0xFFFFFFFF):
            return "stale_header", mode
    elif flags in (1, 3):
        mode = "checked-hash" if flags == 3 else "unchecked-hash"
        if data[8:16] != importlib.util.source_hash(source): return "hash_mismatch", mode
    else:
        return "bad_flags", None
    try:
        stored = marshal.loads(data[16:])
    except Exception:
        return "bad_body", mode
    if not isinstance(stored, types.CodeType): return "bad_body", mode
    try:
        expected = compile(source, src, "exec", dont_inherit=True, optimize=0)
    except (SyntaxError, ValueError):
        return "source_invalid", mode
    if stored != expected: return "body_differs", mode
    if any(c.co_filename != src for c in codes(stored)): return "filename_differs", mode
    return "ok", mode

def tree(root, errors):
    out = {}
    def onerror(e): errors.append("cannot list: %s" % e.filename)
    for d, dirs, files in os.walk(root, onerror=onerror):
        for name in sorted(dirs + files):
            path = os.path.join(d, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            try:
                k = kind(os.lstat(path).st_mode)
            except OSError:
                errors.append("cannot inspect: " + rel); continue
            out[rel] = {"type": k}
            if k == "file":
                try: out[rel]["sha256"] = digest(path)
                except OSError: errors.append("unreadable: " + rel)
    return out

def hook(path, in_venv, errors):
    try:
        return {"path": path, "sha256": digest(path), "in_venv": in_venv}
    except OSError:
        errors.append("unreadable startup hook: " + path)
        return {"path": path, "in_venv": in_venv}

def main():
    # Runs under -S, so no .pth file or sitecustomize has executed: the site
    # directories are derived here, in the order site.main() would add them.
    errors = []
    # site.venv() reads pyvenv.cfg and sets sys.prefix and site.PREFIXES. It also adds
    # the site-packages, which would run .pth files, so that step is stubbed out. It
    # must run before sysconfig computes (and caches) any path.
    add = site.addsitepackages
    site.addsitepackages = lambda known_paths, prefixes=None: known_paths
    try:
        site.venv(set())
    finally:
        site.addsitepackages = add
    if sys.prefix == sys.base_prefix:
        raise RuntimeError("the interpreter is not a virtual environment's")
    site_dir = sysconfig.get_paths()["purelib"]
    root = os.path.join(site_dir, "brandsentinel")
    system = sys.base_prefix in site.PREFIXES  # include-system-site-packages = true
    user_site = site.getusersitepackages() if system else None  # venv without system: off
    system_sites = [p for p in site.getsitepackages() if os.path.isdir(p)
                    and os.path.realpath(p) != os.path.realpath(site_dir)]
    search = ([user_site] if user_site and os.path.isdir(user_site) else []) + [site_dir]
    search += system_sites
    spec = importlib.machinery.PathFinder.find_spec("brandsentinel", search)
    located = [os.path.abspath(p) for p in (spec.submodule_search_locations or [])] if spec else []
    package, bytecode = {}, {}
    if os.path.isdir(root) and not os.path.islink(root):
        package = tree(root, errors)
    else:
        errors.append("no package directory in the environment's site-packages")
    for rel, entry in sorted(package.items()):
        parts = rel.split("/")
        if entry["type"] != "file" or not rel.endswith(".py") or "__pycache__" in parts:
            continue
        src = os.path.join(root, *parts)
        pyc = importlib.util.cache_from_source(src)
        status, mode = judge(src, pyc)
        if status == "unreadable":
            errors.append("unreadable bytecode or source: " + rel)
        bytecode[rel] = {"pyc": os.path.relpath(pyc, root).replace(os.sep, "/"),
                         "status": status, "mode": mode}
    dist_info = {}
    for name in sorted(os.listdir(site_dir)):
        if name.lower().startswith("brandsentinel-") and name.endswith(".dist-info"):
            dist_info[name] = tree(os.path.join(site_dir, name), errors)
    record = None
    if len(dist_info) == 1:
        try:
            with open(os.path.join(site_dir, next(iter(dist_info)), "RECORD"),
                      encoding="utf-8") as f:
                record = f.read()
        except OSError:
            record = None
    names = ("sitecustomize.py", "usercustomize.py", "sitecustomize", "usercustomize")
    hooks = []
    for d in [site_dir] + system_sites:
        for n in sorted(os.listdir(d)):
            if n.endswith(".pth") or n in names:
                hooks.append(hook(os.path.join(d, n), d == site_dir, errors))
    seen = {h["path"] for h in hooks}
    for module in ("sitecustomize", "usercustomize"):
        found = importlib.machinery.PathFinder.find_spec(module, sys.path + search)
        if found and found.origin and found.origin not in seen:
            hooks.append(hook(found.origin, found.origin.startswith(site_dir + os.sep), errors))
    distributions = []
    for entry in search:
        found = [{"name": d.metadata["Name"] or "", "version": d.version or "",
                  "path": os.path.abspath(entry),
                  "in_venv": os.path.abspath(entry) == os.path.abspath(site_dir)}
                 for d in importlib.metadata.distributions(path=[entry])]
        # the search order decides which copy wins; within one entry, sort (listdir order)
        distributions += sorted(found, key=lambda d: (d["name"].lower(), d["version"]))
    env = {
        "implementation_name": sys.implementation.name,
        "implementation_version": platform.python_version(),
        "os_name": os.name,
        "platform_machine": platform.machine(),
        "platform_release": platform.release(),
        "platform_system": platform.system(),
        "platform_version": platform.version(),
        "python_full_version": platform.python_version(),
        "platform_python_implementation": platform.python_implementation(),
        "python_version": ".".join(platform.python_version_tuple()[:2]),
        "sys_platform": sys.platform,
    }
    print(json.dumps({
        "python": {"version": platform.python_version(), "cache_tag": sys.implementation.cache_tag,
                   "magic": importlib.util.MAGIC_NUMBER.hex()},
        "site": site_dir, "located": located, "package": package, "bytecode": bytecode,
        "dist_info": dist_info, "record": record, "startup_hooks": hooks,
        "user_site": user_site if user_site and os.path.exists(user_site) else None,
        "distributions": distributions, "marker_environment": env, "errors": errors,
    }))

try:
    main()
except Exception as e:
    print(json.dumps({"fatal": "%s: %s" % (type(e).__name__, e)}))
"""


class Incomplete(Exception):
    """The inspection cannot be completed; nothing can be concluded."""


def run_command(argv: list[str], cwd: Path | None = None) -> str:
    return subprocess.run(  # noqa: S603 - fixed argv
        argv, check=True, capture_output=True, text=True, cwd=cwd, timeout=TIMEOUT_SECONDS
    ).stdout


def docker(host: str, *args: str) -> str:
    binary = shutil.which("docker") or "/usr/bin/docker"
    try:
        return run_command([binary, "--host", host, *args]).strip()
    except (OSError, subprocess.SubprocessError) as error:
        raise Incomplete(f"docker {args[0]} failed: {_detail(error)}") from None


def _detail(error: Exception) -> str:
    stderr = getattr(error, "stderr", None)
    text = (stderr or str(error)).strip().splitlines()
    return text[-1][:200] if text else type(error).__name__


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _files(root: Path, what: str) -> dict[str, str]:
    """Regular files under `root` outside __pycache__, by relative path."""
    if not root.is_dir() or root.is_symlink():
        raise Incomplete(f"{what} is not a directory: {root}")
    out = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if "__pycache__" in rel.parts:
            continue
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise Incomplete(f"{what} has an entry that is not a regular file: {rel}")
        if path.is_file():
            out[rel.as_posix()] = sha256_file(path)
    if not out:
        raise Incomplete(f"{what} has no files")
    return out


class Reference:
    """The expected package and dist-info, from a wheel or an installation."""

    def __init__(self, kind: str, payload: dict[str, str], dist_info: dict[str, str]):
        self.kind = kind
        self.payload = payload
        self.dist_info = dist_info  # wheel-origin files, RECORD excluded


def wheel_reference(path: Path) -> tuple[Reference, str]:
    try:
        data = path.read_bytes()
        archive = zipfile.ZipFile(io.BytesIO(data))
        members = [i for i in archive.infolist() if not i.is_dir()]
        names = [i.filename for i in members]
        if len(names) != len(set(names)):
            raise Incomplete("the wheel has duplicate members")
        content = {name: archive.read(name) for name in names}
    except (OSError, zipfile.BadZipFile) as error:
        raise Incomplete(f"the wheel cannot be read: {type(error).__name__}") from None
    payload, dist_info, record_name = {}, {}, None
    for name, body in content.items():
        if name.startswith(PACKAGE + "/"):
            payload[name[len(PACKAGE) + 1 :]] = sha256_bytes(body)
        elif re.fullmatch(rf"{PACKAGE}-[^/]+\.dist-info/.+", name):
            rel = name.split("/", 1)[1]
            if rel == "RECORD":
                record_name = name
            else:
                dist_info[rel] = sha256_bytes(body)
        else:
            raise Incomplete(f"the wheel has a member outside the package: {name}")
    if record_name is None or not payload:
        raise Incomplete("the wheel has no RECORD or no package files")
    listed = {}
    for row in csv.reader(io.StringIO(content[record_name].decode("utf-8"))):
        if row and row[0] != record_name:
            listed[row[0]] = row[1] if len(row) > 1 else ""
    if set(listed) != set(content) - {record_name} or any(
        listed[n] != _record_hash(content[n]) for n in listed
    ):
        raise Incomplete("the wheel's RECORD does not match its members")
    return Reference("wheel", payload, dist_info), sha256_bytes(data)


def _record_hash(data: bytes) -> str:
    return _record_hash_hex(sha256_bytes(data))


def installed_reference(prefix: Path) -> tuple[Reference, str | None]:
    sites = sorted((prefix / "venv" / "lib").glob("python3.*/site-packages"))
    if len(sites) != 1:
        raise Incomplete("the installation has not exactly one site-packages")
    site = sites[0]
    infos = sorted(site.glob(f"{PACKAGE}-*.dist-info"))
    if len(infos) != 1:
        raise Incomplete("the installation has not exactly one brandsentinel dist-info")
    direct = infos[0] / "direct_url.json"
    if direct.is_file():
        try:
            editable = json.loads(direct.read_text()).get("dir_info", {}).get("editable")
        except (ValueError, AttributeError):
            raise Incomplete("the installation's direct_url.json cannot be read") from None
        if editable:
            raise Incomplete("the installation is editable, not a release install")
    dist_info = {
        rel: sha
        for rel, sha in _files(infos[0], "the installed dist-info").items()
        if rel not in INSTALLER_FILES
    }
    payload = _files(site / PACKAGE, "the installed package")
    wheel_sha = None
    record = prefix / "INSTALL"
    if record.is_file():
        for line in record.read_text().splitlines():
            if line.startswith("wheel_sha256:"):
                wheel_sha = line.split(":", 1)[1].strip()
    return Reference("installed", payload, dist_info), wheel_sha


def expected_pins(source: Path) -> list[tuple[str, str, str | None]]:
    uv = shutil.which("uv")
    if uv is None:
        raise Incomplete("uv not found: the dependency pins cannot be derived from the lock")
    argv = [uv, "export", "--frozen", "--offline", "--no-dev", "--extra", "sandbox",
            "--no-emit-project", "--no-hashes", "--no-annotate", "--no-header",
            "--format", "requirements-txt"]  # fmt: skip
    try:
        text = run_command(argv, cwd=source)
    except (OSError, subprocess.SubprocessError) as error:
        raise Incomplete(f"uv export failed: {_detail(error)}") from None
    pins = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        requirement, _, marker = line.partition(";")
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s=]+)", requirement.strip())
        if not match:
            raise Incomplete(f"not an exact pin in the lock export: {line[:80]}")
        pins.append((normalize(match.group(1)), match.group(2), marker.strip() or None))
    if not pins:
        raise Incomplete("the lock export has no pins")
    return pins


class Report:
    def __init__(self) -> None:
        self.violations: list[dict[str, str]] = []
        self.excluded: list[dict[str, str]] = []

    def violation(self, rule: str, path: str) -> None:
        if rule not in RULES:
            raise ValueError(rule)
        self.violations.append({"rule": rule, "path": path})

    def exclude(self, path: str, reason: str) -> None:
        self.excluded.append({"path": path, "reason": reason})


def compare_payload(measured: dict, reference: Reference, report: Report) -> int:
    compared = 0
    image = {}
    for rel, entry in measured["package"].items():
        if "__pycache__" in rel.split("/"):
            continue
        if entry["type"] == "file":
            image[rel] = entry.get("sha256")
        elif entry["type"] != "dir":
            report.violation("payload_not_regular", rel)
    for rel in sorted(reference.payload.keys() | image.keys()):
        if rel not in image:
            report.violation("payload_missing", rel)
        elif rel not in reference.payload:
            report.violation("payload_extra", rel)
        elif image[rel] != reference.payload[rel]:
            report.violation("payload_modified", rel)
        else:
            compared += 1
    return compared


def compare_bytecode(measured: dict, report: Report) -> int:
    expected = {}
    for rel, entry in measured["bytecode"].items():
        expected[entry["pyc"]] = rel
        if entry["status"] != "ok":
            report.violation(f"bytecode_{entry['status']}", rel)
    for rel, entry in measured["package"].items():
        parts = rel.split("/")
        if "__pycache__" not in parts:
            continue
        if (
            parts[-1] == "__pycache__"
            and entry["type"] == "dir"
            and parts.count("__pycache__") == 1
        ):
            continue
        if rel not in expected:
            report.violation("unexpected_bytecode", rel)
    return sum(1 for e in measured["bytecode"].values() if e["status"] == "ok")


def compare_metadata(measured: dict, reference: Reference, report: Report) -> int:
    infos = measured["dist_info"]
    if len(infos) != 1:
        report.violation("dist_info_count", ", ".join(sorted(infos)) or "none")
        return 0
    name, files = next(iter(infos.items()))
    image = {}
    for rel, entry in files.items():
        if entry["type"] == "file":
            image[rel] = entry.get("sha256")
        elif entry["type"] != "dir":
            report.violation("metadata_extra", f"{name}/{rel}")
    compared = 0
    for rel in sorted(reference.dist_info.keys() | image.keys()):
        if rel in INSTALLER_FILES and rel not in reference.dist_info:
            if rel in image:
                report.exclude(f"{name}/{rel}", INSTALLER_FILES[rel])
            continue
        if rel not in image:
            report.violation("metadata_missing", f"{name}/{rel}")
        elif rel not in reference.dist_info:
            report.violation("metadata_extra", f"{name}/{rel}")
        elif image[rel] != reference.dist_info[rel]:
            report.violation("metadata_modified", f"{name}/{rel}")
        else:
            compared += 1
    _check_record(measured, report)
    return compared


def _check_record(measured: dict, report: Report) -> None:
    text = measured.get("record")
    if text is None:
        report.violation("record_mismatch", "RECORD (missing)")
        return
    listed = {}
    for row in csv.reader(io.StringIO(text)):
        if row and row[0].startswith(PACKAGE + "/") and "/__pycache__/" not in row[0]:
            listed[row[0][len(PACKAGE) + 1 :]] = row[1] if len(row) > 1 else ""
    payload = {
        rel: e.get("sha256")
        for rel, e in measured["package"].items()
        if e["type"] == "file" and "__pycache__" not in rel.split("/")
    }
    for rel in sorted(listed.keys() | payload.keys()):
        sha = payload.get(rel)
        if rel not in listed or sha is None or listed[rel] != _record_hash_hex(sha):
            report.violation("record_mismatch", rel)


def _record_hash_hex(sha_hex: str) -> str:
    raw = bytes.fromhex(sha_hex)
    return "sha256=" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def check_import_path(measured: dict, report: Report) -> None:
    root = measured["site"].rstrip("/") + "/" + PACKAGE
    if measured["located"] != [root]:
        report.violation("package_shadowed", ", ".join(measured["located"]) or "not found")
    if measured["user_site"]:
        report.violation("user_site", measured["user_site"])
    for hook in measured["startup_hooks"]:
        if hook["in_venv"]:
            report.violation("startup_hook", hook["path"])
        else:
            report.exclude(
                hook["path"],
                "base image startup hook: runs in every process; recorded in the manifest, "
                "bound by the base image digest and the image ID, not judged",
            )


def check_image_config(config: dict, report: Report) -> None:
    for item in config.get("Env") or []:
        name = item.split("=", 1)[0]
        if name.startswith("PYTHON") and name not in IMAGE_ENV_ALLOWED:
            report.violation("image_environment", name)


def compare_dependencies(measured: dict, pins: list, report: Report) -> int:
    from packaging.markers import Marker  # host side; part of the project's dependencies

    env = measured["marker_environment"]
    expected = {}
    for name, version, marker in pins:
        if marker is None or Marker(marker).evaluate(env):
            expected[name] = version
        else:
            report.exclude(f"dependency {name}=={version}", f"marker false in the image: {marker}")
    resolved: dict[str, dict] = {}
    in_venv: dict[str, int] = {}
    for dist in measured["distributions"]:
        name = normalize(dist["name"] or "")
        resolved.setdefault(name, dist)
        if dist["in_venv"]:
            in_venv[name] = in_venv.get(name, 0) + 1
    compared = 0
    for name, version in sorted(expected.items()):
        dist = resolved.get(name)
        if dist is None:
            report.violation("dependency_missing", f"{name}=={version}")
        elif not dist["in_venv"]:
            report.violation("dependency_outside_venv", f"{name}=={dist['version']}")
        elif dist["version"] != version:
            report.violation("dependency_version", f"{name}=={dist['version']} (pin {version})")
        else:
            compared += 1
    for name, count in sorted(in_venv.items()):
        if count > 1:
            report.violation("dependency_duplicate", name)
        if name in expected or name == PACKAGE:
            continue
        if name in SEEDED:
            report.exclude(f"dependency {name}=={resolved[name]['version']}", SEEDED[name])
        else:
            report.violation("dependency_unexpected", f"{name}=={resolved[name]['version']}")
    return compared


def manifest_digest(measured: dict) -> str:
    """The measured inventory, without the image's creation time, host paths or the
    marker environment (which names the host kernel). It is stable for one image but
    not across rebuilds: timestamp bytecode headers embed source mtimes."""
    stable = {
        "schema": SCHEMA,
        "python": measured["python"],
        "site": measured["site"],
        "package": measured["package"],
        "bytecode": measured["bytecode"],
        "dist_info": measured["dist_info"],
        "startup_hooks": measured["startup_hooks"],
        "user_site": measured["user_site"],
        "distributions": measured["distributions"],
    }
    canonical = json.dumps(stable, sort_keys=True, separators=(",", ":"))
    return sha256_bytes(canonical.encode())


def measure(host: str, image: str) -> dict:
    # -S: no .pth file or sitecustomize may run before it is inventoried.
    out = docker(host, "run", "--rm", "--pull", "never", "--network", "none",
                 "--entrypoint", "python3", image, "-I", "-S", "-B", "-c", INSIDE)  # fmt: skip
    try:
        measured = json.loads(out)
    except ValueError:
        raise Incomplete("the in-image measurement did not return JSON") from None
    if "fatal" in measured:
        raise Incomplete(f"the in-image measurement failed: {measured['fatal']}")
    if measured["errors"]:
        raise Incomplete("the in-image measurement could not read: " + measured["errors"][0])
    if not measured["bytecode"]:
        raise Incomplete("no package source was inspected in the image")
    return measured


def verify(a: argparse.Namespace) -> tuple[dict, int]:
    report = Report()
    result: dict = {"schema": SCHEMA, "profile": a.profile, "image": a.image}
    try:
        inspected = json.loads(
            docker(a.docker_host, "image", "inspect", "--format", "{{json .}}", a.image)
        )
        result["image_id"], result["created"] = inspected["Id"], inspected.get("Created")
        config = inspected.get("Config") or {}
    except (ValueError, KeyError, TypeError):
        raise Incomplete("docker image inspect did not return the image") from None
    result["config"] = {k: config.get(k) for k in ("User", "Entrypoint", "Cmd")}
    check_image_config(config, report)
    dockerfile = a.source / "docker" / "Dockerfile.sandbox"
    base = (
        re.search(r"^FROM\s+(\S+)", dockerfile.read_text(), re.M) if dockerfile.is_file() else None
    )
    result["dockerfile_base"] = base.group(1) if base else None

    source = _files(a.source / "src" / PACKAGE, "the source package")
    if a.profile == "release":
        reference, wheel_sha = wheel_reference(a.wheel)
        result["references"] = {"wheel_sha256": wheel_sha}
        pins = expected_pins(a.source)
    else:
        reference, wheel_sha = installed_reference(a.installed)
        result["references"] = {"installed_wheel_sha256": wheel_sha}
        pins = None
    result["references"].update(
        {
            "kind": reference.kind,
            "source_files": len(source),
            "package_files": len(reference.payload),
        }
    )
    for rel in sorted(source.keys() | reference.payload.keys()):
        if source.get(rel) != reference.payload.get(rel):
            report.violation("reference_mismatch", rel)

    measured = measure(a.docker_host, result["image_id"])  # the ID compared, never the tag
    result["python"] = measured["python"]
    checks, compared = {}, {}
    compared["payload_files"] = compare_payload(measured, reference, report)
    compared["bytecode_files"] = compare_bytecode(measured, report)
    compared["dist_info_files"] = compare_metadata(measured, reference, report)
    check_import_path(measured, report)
    if pins is not None:
        compared["dependencies"] = compare_dependencies(measured, pins, report)
        checks["dependencies"] = "compared with the lock"
    else:
        checks["dependencies"] = "bound by the expected image ID to the release check"

    manifest = manifest_digest(measured)
    result["manifest_sha256"] = manifest
    if a.expect_id:
        result["expected_id"] = a.expect_id
        result["id_matches"] = result["image_id"] == a.expect_id
        if not result["id_matches"]:
            report.violation("image_id_mismatch", result["image_id"])
    checks["image_id"] = "compared" if a.expect_id else "not bound (no --expect-id)"
    result["binding"] = {
        "image_id": "bound to --expect-id"
        if a.expect_id
        else "NOT BOUND: this result identifies the image; it does not approve it",
        "wheel": "bound to --expect-wheel-sha256"
        if a.profile == "release"
        else "the installation's (INSTALL record), reported, not compared",
        "manifest": "bound to --expect-manifest-sha256"
        if a.expect_manifest_sha256
        else "reported, not compared",
        "approval": "none: approval is the owner's, recorded in sealed build evidence",
    }
    if a.expect_wheel_sha256 and wheel_sha != a.expect_wheel_sha256:
        report.violation("wheel_sha256_mismatch", str(wheel_sha))
    if a.expect_manifest_sha256 and manifest != a.expect_manifest_sha256:
        report.violation("manifest_sha256_mismatch", manifest)

    result.update(checks=checks, compared=compared, excluded=report.excluded)
    result["violations"] = report.violations
    ok = not report.violations
    result["verdict"] = "ok" if ok else "MISMATCH"
    return result, 0 if ok else 1


def parse(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--profile", choices=("release", "load"), required=True)
    ap.add_argument("--docker-host", required=True)
    ap.add_argument("--source", type=Path, required=True)
    ap.add_argument("--image", default=IMAGE)
    ap.add_argument("--wheel", type=Path, help="release: the release wheel")
    ap.add_argument("--installed", type=Path, help="load: the installation prefix")
    ap.add_argument("--expect-id")
    ap.add_argument("--expect-wheel-sha256")
    ap.add_argument("--expect-manifest-sha256")
    a = ap.parse_args(argv)
    if a.profile == "release" and (
        a.wheel is None or a.installed is not None or not a.expect_wheel_sha256
    ):
        ap.error("--profile release takes --wheel and --expect-wheel-sha256 (not --installed)")
    for name, value, pattern in (
        ("--expect-id", a.expect_id, r"sha256:[0-9a-f]{64}"),
        ("--expect-wheel-sha256", a.expect_wheel_sha256, r"[0-9a-f]{64}"),
        ("--expect-manifest-sha256", a.expect_manifest_sha256, r"[0-9a-f]{64}"),
    ):
        if value is not None and not re.fullmatch(pattern, value):
            ap.error(f"{name} must be a full sha256 digest")
    if a.profile == "load" and (a.installed is None or a.wheel is not None or not a.expect_id):
        ap.error("--profile load takes --installed and --expect-id (and not --wheel)")
    if a.profile == "load" and a.expect_wheel_sha256:
        ap.error("--expect-wheel-sha256 applies to --profile release")
    return a


def main(argv: list[str] | None = None) -> int:
    a = parse(sys.argv[1:] if argv is None else argv)
    try:
        result, code = verify(a)
    except Incomplete as reason:
        result, code = {"schema": SCHEMA, "profile": a.profile, "image": a.image,
                        "incomplete": [str(reason)], "verdict": "INCOMPLETE"}, 2  # fmt: skip
    except Exception as error:  # any failure to look must not read as a pass
        result = {"schema": SCHEMA, "profile": a.profile, "image": a.image,
                  "incomplete": [f"internal error: {type(error).__name__}: {str(error)[:200]}"],
                  "verdict": "INCOMPLETE"}  # fmt: skip
        code = 2
    print(json.dumps(result, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main())

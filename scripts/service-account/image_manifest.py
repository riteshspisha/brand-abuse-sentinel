"""Identity, provenance and contents of the sandbox image (SP1; B7 PR-2).

Checks an image on one Docker endpoint against references kept outside it. The image
is inspected first: an image whose ID is malformed or not `--expect-id`, or whose
config sets a dynamic loader variable anywhere in its environment, is reported and
never run. Otherwise one container run, addressed by the inspected ID and locked down
like the sandbox runner's containers (`--network none --pull never --read-only
--cap-drop ALL`, no-new-privileges, limits, a unique name), measures the image; every
comparison happens here. After a timeout, Ctrl-C, SIGTERM or SIGHUP the container is
removed with `docker rm -f`, best effort: a failed removal is named in the INCOMPLETE
report after a timeout, and on stderr only after a signal (a signal ends the run with
128 + its number and prints no report). Exit 2 also covers usage errors and a report
that could not be written.

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
  code objects equal `compile(source, in-image path)` field by field, including the
  raw instruction stream (`==` ignores co_qualname and co_stacksize, and `co_code`
  hides specialized opcodes); every nested `co_filename` is the in-image path; and
  nothing follows the code object in the file;
- metadata: exactly one `brandsentinel-*.dist-info`. Every file of the reference's
  dist-info except `RECORD` (`METADATA`, `WHEEL`, `entry_points.txt`, ...) is
  byte-equal in the image. Installer-written files are excluded and listed, and the
  image `RECORD`'s package entries must match the measured hashes;
- import path: measured under `-S`, so no startup hook runs first. Over the runtime
  search order (the standard library, then the environment, user and system site
  directories), `brandsentinel` resolves to the virtual environment's copy, and every
  other top-level name of the environment the path-based finder can load (a directory,
  or a file with an import suffix, whose name has no dot; identifier or not) resolves
  to its single entry there (nothing earlier on the path, no second entry with the
  same import name); there is no user site-packages directory; every top-level entry
  of the environment's site directories is a real directory or regular file (no
  symlink, no special file) and belongs to a distribution there by its RECORD, and
  the package's own RECORD claims only its package, its dist-info and `../` launcher
  rows; the environment holds no startup hook (`*.pth`, `sitecustomize`,
  `usercustomize`); the image has no `/etc/ld.so.preload` (checked by the image's own
  interpreter, so only as trustworthy as it is); and every entry of its config's
  environment is a `NAME=value` string, no name is set twice, none is `LD_*`, and
  no `PYTHON*` variable is set but `PYTHONDONTWRITEBYTECODE` and `PYTHONUNBUFFERED`.
  The report lists the first 200 variable names, the total and whether it was cut;
  every entry is judged. Startup hooks
  outside the environment (the base image or a later layer) are hashed into the
  manifest and listed as excluded, bound only by the image ID, not judged;
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

Trust: the image ID is the anchor. It is a digest that binds the image's config and
every layer's content (with the containerd image store, through the manifest).
Checking it against `--expect-id` proves the image is the one named; it does not prove
that the name was approved. The measurement runs the image's own interpreter, so it shows that the
image matches the references, but it cannot vouch for an image it measures.
The measured image is addressed by the ID that was compared, never by the tag.
`manifest_sha256`, a digest of the measured inventory (not of the image config, the
creation time or the host's marker environment) identifies a measurement for the
release record. It is stable for one
image, not across rebuilds. It is never trusted in
place of the image ID. Not checked: the contents of dependency files (pip enforced
their wheel hashes at build time; afterwards only the image ID binds them), the
base image's system packages beyond their names and versions, and launchers in the
image's `bin/`, Entrypoint, Cmd or PATH (reported for the U3 review), and the RECORD
files used for ownership, which the image itself provides (bound by the image ID).
Report text that comes from the image is escaped and truncated.

Assumptions proven only against stand-ins, to be verified on the real image (U3):
pip installed the package under `sysconfig` purelib of the environment's own scheme
and compiled timestamp bytecode at that path; `site.venv()`/`site.getsitepackages()`
behave on the image's Ubuntu interpreter as upstream (system dist-packages from
`--system-site-packages`); pip installed every pin into the environment rather than
reusing a system distribution, and its RECORDs own every top-level entry; the base
image sets no other `PYTHON*` and no `LD_*` variable; the measurement fits the
container limits; the image ID survives `docker save | docker load` between daemons
(containerd image store); and the base image's system startup hooks are known and
acceptable (reviewed, not judged here).
"""

import argparse
import base64
import contextlib
import csv
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import signal
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
    "bytecode_trailing_data": "the bytecode file has data after its code object",
    "dist_info_count": "not exactly one brandsentinel dist-info",
    "metadata_missing": "a reference dist-info file is missing from the image",
    "metadata_modified": "an image dist-info file differs from the reference",
    "metadata_extra": "the image dist-info has a file that is neither reference nor installer",
    "record_mismatch": "the image RECORD disagrees with the measured package",
    "package_shadowed": "brandsentinel does not resolve to the environment's copy",
    "startup_hook": "a startup hook (.pth, sitecustomize, usercustomize) in the environment",
    "user_site": "a user site-packages directory that every process would import from",
    "image_environment": "the image config sets an unreviewed PYTHON* variable or a name twice",
    "image_loader_environment": "the image config sets a dynamic loader variable (LD_*)",
    "site_unowned": "a site-packages entry no installed distribution's RECORD owns",
    "dependency_shadowed": "an importable name of the environment resolves to another entry",
    "site_not_regular": "a top-level site-packages entry is a symlink or a special file",
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
ENV_REPORTED = 200  # environment names listed in a report; all of them are judged
CLEANUP_TIMEOUT_SECONDS = 60
MAX_LISTED = 1000  # violations and exclusions listed in a report; the total is always given
# The measurement container gets the sandbox runner's lockdown (sandbox/runner.py).
MEASURE_FLAGS = (
    "--rm", "--pull", "never", "--network", "none", "--read-only",
    "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m",  # noqa: S108 - container path
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
    "--memory", "1g", "--memory-swap", "1g", "--cpus", "1", "--pids-limit", "64",
    "--ipc", "private", "--ulimit", "core=0", "--ulimit", "nofile=1024:1024",
    "--no-healthcheck", "--workdir", "/tmp",  # noqa: S108 - container path
    "--label", "brandsentinel.role=image-manifest",
)  # fmt: skip
# Distributions in the image's environment that do not come from the lock.
SEEDED = {"pip": "seeded into the environment by python3 -m venv (ensurepip)"}

# Runs in the image, under its own interpreter. It must not import brandsentinel.
INSIDE = r"""
import csv, hashlib, importlib.machinery, importlib.metadata, importlib.util, io, json
import marshal, os, platform, site, stat, sys, sysconfig, types

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

# Code equality (==) ignores co_filename, co_qualname, co_stacksize and more, so the
# stored and compiled trees are compared field by field (co_filename separately).
FIELDS = ("co_argcount", "co_posonlyargcount", "co_kwonlyargcount", "co_nlocals",
          "co_stacksize", "co_flags", "co_code", "co_names", "co_varnames", "co_freevars",
          "co_cellvars", "co_name", "co_qualname", "co_firstlineno", "co_linetable",
          "co_exceptiontable", "_co_code_adaptive")
# co_code is de-optimized on read: it hides specialized and superinstruction opcodes
# stored in the file. _co_code_adaptive is the raw instruction stream (3.11+); a
# faithful file holds base opcodes with zeroed caches, as compile() produces.

def same_const(a, b):
    if type(a) is not type(b): return False
    if isinstance(a, types.CodeType): return same_code(a, b)
    if isinstance(a, tuple): return len(a) == len(b) and all(map(same_const, a, b))
    if isinstance(a, frozenset): return a == b and sorted(map(repr, a)) == sorted(map(repr, b))
    if isinstance(a, (float, complex)): return repr(a) == repr(b)
    return a == b

def slot_names(code):
    # The order of the local, cell and free slots (co_varnames, co_cellvars and
    # co_freevars give membership, not this interleaving). The slot kinds themselves are
    # not exposed to Python.
    name_of = code._varname_from_oparg  # checked to exist in main(); 3.11+
    names = []
    for i in range(1 << 16):
        try:
            names.append(name_of(i))
        except (IndexError, ValueError):
            return names
    return object()  # implausibly many slots: never equal, so never a pass

def same_code(a, b):
    return (all(getattr(a, f, None) == getattr(b, f, None) for f in FIELDS)
            and slot_names(a) == slot_names(b)
            and same_const(a.co_consts, b.co_consts))

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
    body = io.BytesIO(data[16:])
    try:
        stored = marshal.load(body)  # consumes exactly one object
    except Exception:
        return "bad_body", mode
    if not isinstance(stored, types.CodeType): return "bad_body", mode
    if body.tell() != len(data) - 16: return "trailing_data", mode
    try:
        expected = compile(source, src, "exec", dont_inherit=True, optimize=0)
    except (SyntaxError, ValueError):
        return "source_invalid", mode
    if not same_code(stored, expected): return "body_differs", mode
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
    if not hasattr(compile("", "", "exec"), "_varname_from_oparg"):
        # without it the slot order cannot be compared: incomplete, never skipped
        errors.append("this interpreter does not expose the code slot order")
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
    venv_root = os.path.realpath(sys.prefix)
    def in_venv(path):
        real = os.path.realpath(path)
        return real == venv_root or real.startswith(venv_root + os.sep)
    system = sys.base_prefix in site.PREFIXES  # include-system-site-packages = true
    user_site = site.getusersitepackages() if system else None  # venv without system: off
    sites = [p for p in site.getsitepackages() if os.path.isdir(p)]
    venv_sites = [site_dir] + [p for p in sites if in_venv(p)
                               and os.path.realpath(p) != os.path.realpath(site_dir)]
    system_sites = [p for p in sites if not in_venv(p)]
    # site.venv() adds the environment's site-packages before the user site (3.12).
    search = list(venv_sites)
    search += [user_site] if user_site and os.path.isdir(user_site) else []
    search += system_sites
    # The runtime order: the interpreter's own entries (under -I -S, exactly the
    # standard library), then what site.main() adds.
    runtime = list(sys.path) + search
    spec = importlib.machinery.PathFinder.find_spec("brandsentinel", runtime)
    located = [os.path.abspath(p) for p in (spec.submodule_search_locations or [])] if spec else []
    origin = os.path.abspath(spec.origin) if spec and spec.origin else None
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
    for d in venv_sites + system_sites:
        for n in sorted(os.listdir(d)):
            if n.endswith(".pth") or n in names:
                hooks.append(hook(os.path.join(d, n), d in venv_sites, errors))
    seen = {h["path"] for h in hooks}
    for module in ("sitecustomize", "usercustomize"):
        found = importlib.machinery.PathFinder.find_spec(module, runtime)
        if found and found.origin and found.origin not in seen:
            hooks.append(hook(found.origin, in_venv(found.origin), errors))
    distributions = []
    for entry in search:
        found = []
        for d in importlib.metadata.distributions(path=[entry]):
            name, version = d.metadata["Name"], d.version
            if not name or not version:
                errors.append("unreadable distribution metadata in " + entry)
                continue
            found.append({"name": name, "version": version, "path": os.path.abspath(entry),
                          "in_venv": entry in venv_sites})
        # the search order decides which copy wins; within one entry, sort (listdir order)
        distributions += sorted(found, key=lambda d: (d["name"].lower(), d["version"]))
    # Every top-level entry of the environment's site directories must belong to a
    # distribution there, by the first component of a path in its RECORD (files, so
    # directories, namespace packages, extension modules and __pycache__ included).
    # A distribution without a RECORD owns nothing, not even its own dist-info.
    unowned = []
    for d in venv_sites:
        owned = set()
        for dist in importlib.metadata.distributions(path=[d]):
            # The RECORD text itself: Distribution.files would stat every entry.
            for row in csv.reader(io.StringIO(dist.read_text("RECORD") or "")):
                parts = row[0].replace("\\", "/").split("/") if row and row[0] else []
                if parts and parts[0] and ".." not in parts:
                    owned.add(parts[0])
        unowned += [os.path.join(d, n) for n in sorted(os.listdir(d)) if n not in owned]
    # Whoever owns them, every importable top-level name of the environment must resolve,
    # over the runtime order, to its single entry there: a module planted earlier on the
    # path (standard library, user site) or a second entry with the same import name
    # (a package beside a module, an extension beside a .py) would shadow it.
    suffixes = sorted(importlib.machinery.all_suffixes(), key=len, reverse=True)
    def import_name(name, path):
        # What the path-based finder can load under this name: a directory (followed
        # through a symlink, as the finder does) or a file with an import suffix. Any
        # name without a dot is loadable through importlib, identifier or not; a dotted
        # name would mean a submodule, which a top-level entry cannot be.
        if os.path.isdir(path):
            stem = name
        else:
            stem = next((name[: -len(x)] for x in suffixes if name.endswith(x)), None)
        return stem if stem and "." not in stem else None
    entries, irregular = {}, []
    for d in venv_sites:
        for n in sorted(os.listdir(d)):
            path = os.path.join(d, n)
            try:
                mode = os.lstat(path).st_mode
            except OSError:
                errors.append("cannot inspect: " + path)
                continue
            if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                irregular.append(path)  # pip installs neither symlinks nor special files
            if n == "__pycache__" or n.endswith((".dist-info", ".egg-info", ".pth")):
                continue
            stem = import_name(n, path)
            if stem:
                entries.setdefault(stem, []).append(path)
    shadowed = []
    for stem, paths in sorted(entries.items()):
        found = importlib.machinery.PathFinder.find_spec(stem, runtime)
        where = None
        if found is not None:
            where = found.origin if found.origin not in (None, "namespace") else None
            if where is None and found.submodule_search_locations:
                where = list(found.submodule_search_locations)[0]
        target = os.path.dirname(where) if where and os.path.basename(where).startswith(
            "__init__.") else where
        if (len(paths) > 1 or not target
                or os.path.realpath(target) != os.path.realpath(paths[0])):
            shadowed.append({"name": stem, "entries": paths, "resolved": where})
    preload = "/etc/ld.so.preload"
    ld_so_preload = hook(preload, False, errors).get("sha256", "unreadable") if os.path.lexists(
        preload) else None
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
        "site": site_dir, "located": located, "origin": origin, "package": package,
        "bytecode": bytecode, "unowned": unowned, "shadowed": shadowed,
        "irregular": irregular,
        "ld_so_preload": ld_so_preload,
        "interpreter": {"prefix": sys.prefix, "executable": sys.executable},
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


def run_command(argv: list[str], cwd: Path | None = None, timeout: int | None = None) -> str:
    return subprocess.run(  # noqa: S603 - fixed argv
        argv,
        check=True,
        capture_output=True,
        text=True,
        cwd=cwd,
        timeout=TIMEOUT_SECONDS if timeout is None else timeout,
    ).stdout


def docker_binary() -> str:
    return shutil.which("docker") or "/usr/bin/docker"


def docker(host: str, *args: str) -> str:
    try:
        return run_command([docker_binary(), "--host", host, *args]).strip()
    except (OSError, subprocess.SubprocessError) as error:
        raise Incomplete(f"docker {args[0]} failed: {_detail(error)}") from None


def _detail(error: Exception) -> str:
    if isinstance(error, subprocess.TimeoutExpired):  # str() starts with the whole argv
        return f"timed out after {error.timeout} s"
    stderr = getattr(error, "stderr", None)
    if isinstance(stderr, bytes):  # TimeoutExpired keeps bytes
        stderr = stderr.decode("utf-8", "replace")
    text = (stderr or str(error)).strip().splitlines()
    return bounded(text[-1], 200) if text else type(error).__name__


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


def bounded(text: object, limit: int = 300) -> str:
    """Image-controlled text, made printable (ASCII escapes) and cut to `limit`."""
    shown = ascii(str(text))[1:-1]
    return shown if len(shown) <= limit else shown[:limit] + "...(truncated)"


class Report:
    def __init__(self) -> None:
        self.violations: list[dict[str, str]] = []
        self.excluded: list[dict[str, str]] = []
        self.totals = {"violations": 0, "excluded": 0}

    def violation(self, rule: str, path: str) -> None:
        if rule not in RULES:
            raise ValueError(rule)
        self.totals["violations"] += 1
        if len(self.violations) < MAX_LISTED:
            self.violations.append({"rule": rule, "path": bounded(path)})

    def exclude(self, path: str, reason: str) -> None:
        self.totals["excluded"] += 1
        if len(self.excluded) < MAX_LISTED:
            self.excluded.append({"path": bounded(path), "reason": reason})


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
    dist_info = next(iter(measured["dist_info"]), "")
    for row in csv.reader(io.StringIO(text)):
        if not row:
            continue
        # The package's RECORD may claim only its package, its dist-info and launchers
        # (../ rows): any other row would let it "own" an unrelated site entry.
        top = row[0].replace("\\", "/").split("/")[0]
        if top not in (PACKAGE, dist_info, ".."):
            report.violation("record_mismatch", row[0])
        elif top == PACKAGE and "/__pycache__/" not in row[0]:
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
    if measured["located"] != [root] or measured["origin"] != root + "/__init__.py":
        found = measured["origin"] or ", ".join(measured["located"]) or "not found"
        report.violation("package_shadowed", found)
    if measured["user_site"]:
        report.violation("user_site", measured["user_site"])
    for path in measured["unowned"]:
        report.violation("site_unowned", path)
    for path in measured["irregular"]:
        report.violation("site_not_regular", path)
    for item in measured["shadowed"]:
        report.violation(
            "dependency_shadowed",
            f"{item['name']}: {', '.join(item['entries'])} -> {item['resolved'] or 'not found'}",
        )
    if measured["ld_so_preload"] is not None:
        report.violation("image_loader_environment", "/etc/ld.so.preload")
    for hook in measured["startup_hooks"]:
        if hook["in_venv"]:
            report.violation("startup_hook", hook["path"])
        else:
            report.exclude(
                hook["path"],
                "startup hook outside the virtual environment (base image or a later layer): "
                "runs in every process; recorded in the manifest; bound only by the image ID; "
                "not judged (reviewed on the real image, U3)",
            )


def image_environment(config: dict) -> list[tuple[str, str]]:
    """Every entry of the image config's Env as (name, value), in order. An entry that is
    not a `NAME=value` string makes the inspection incomplete, never a pass."""
    raw = config.get("Env")
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise Incomplete("the image config's Env is not a list")
    env = []
    for item in raw:
        name, sep, value = item.partition("=") if isinstance(item, str) else ("", "", "")
        if not sep or not name:
            raise Incomplete(f"the image config has a malformed Env entry: {bounded(item, 100)}")
        env.append((name, value))
    return env


def check_image_config(env: list[tuple[str, str]], report: Report) -> bool:
    """Judge every entry of the image config's environment. Returns True when it sets a
    dynamic loader variable: such an image is not run at all, not even for the
    measurement. A name set twice is ambiguous and a mismatch."""
    loader = False
    seen: set[str] = set()
    for name, _ in env:
        if name in seen:
            report.violation("image_environment", f"{name} (set more than once)")
        seen.add(name)
        if name.startswith("LD_"):
            report.violation("image_loader_environment", name)
            loader = True
        elif name.startswith("PYTHON") and name not in IMAGE_ENV_ALLOWED:
            report.violation("image_environment", name)
    return loader


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
        "origin": measured["origin"],
        "unowned": measured["unowned"],
        "shadowed": measured["shadowed"],
        "irregular": measured["irregular"],
        "ld_so_preload": measured["ld_so_preload"],
        "interpreter": measured["interpreter"],
        "distributions": measured["distributions"],
    }
    canonical = json.dumps(stable, sort_keys=True, separators=(",", ":"))
    return sha256_bytes(canonical.encode())


def remove_container(host: str, name: str) -> str | None:
    """Best-effort `docker rm -f`. Returns None when the container is gone, else why not."""
    try:
        argv = [docker_binary(), "--host", host, "rm", "-f", name]
        run_command(argv, timeout=CLEANUP_TIMEOUT_SECONDS)
    except subprocess.CalledProcessError as error:
        if "no such container" in _detail(error).lower():
            return None  # it exited and --rm removed it
        return _detail(error)
    except (OSError, subprocess.SubprocessError) as error:
        return _detail(error)
    return None


def measure(host: str, image: str) -> dict:
    name = f"brandsentinel-image-manifest-{os.getpid()}-{secrets.token_hex(4)}"
    # -S: no .pth file or sitecustomize may run before it is inventoried.
    argv = ["run", "--name", name, *MEASURE_FLAGS,
            "--entrypoint", "python3", image, "-I", "-S", "-B", "-c", INSIDE]  # fmt: skip
    try:
        out = docker(host, *argv)
    except BaseException as error:
        # A timeout or an interruption kills the docker client, not the container.
        problem = remove_container(host, name)
        if problem is not None:
            reason = (
                f"the measurement did not finish and its container {name} could not be "
                f"removed ({bounded(problem, 200)}); it may still be running"
            )
            if isinstance(error, Exception):
                raise Incomplete(reason) from None
            print(f"image_manifest: {reason}", file=sys.stderr)
        raise
    try:
        measured = json.loads(out)
    except ValueError:
        raise Incomplete("the in-image measurement did not return JSON") from None
    if not isinstance(measured, dict):
        raise Incomplete("the in-image measurement did not return an object")
    if "fatal" in measured:
        raise Incomplete(f"the in-image measurement failed: {bounded(measured['fatal'], 200)}")
    if measured["errors"]:
        problem = bounded(measured["errors"][0], 200)
        raise Incomplete(f"the in-image measurement could not read: {problem}")
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
        image_id = inspected["Id"]
        config = inspected.get("Config")
        config = {} if config is None else config  # only a missing config is empty
        if not isinstance(image_id, str) or not isinstance(config, dict):
            raise TypeError
        result["created"] = bounded(inspected.get("Created"), 64)
    except (ValueError, KeyError, TypeError, AttributeError):
        raise Incomplete("docker image inspect did not return the image") from None
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise Incomplete(f"the daemon reported a malformed image ID: {bounded(image_id, 80)}")
    result["image_id"] = image_id
    env = image_environment(config)  # all of it; only the report below is cut short
    result["config"] = {
        k: bounded(json.dumps(config.get(k)), 500) for k in ("User", "Entrypoint", "Cmd")
    }
    paths = [value for name, value in env if name == "PATH"]
    result["config"]["path"] = bounded(paths[-1], 500) if paths else None
    result["config"]["env_total"] = len(env)
    result["config"]["env_truncated"] = len(env) > ENV_REPORTED
    result["config"]["env_names"] = [bounded(name, 100) for name, _ in env[:ENV_REPORTED]]
    loader = check_image_config(env, report)
    result["binding"] = binding(a)
    if a.expect_id:
        result["expected_id"] = a.expect_id
        result["id_matches"] = result["image_id"] == a.expect_id
        if not result["id_matches"]:
            report.violation("image_id_mismatch", result["image_id"])
    if loader or result.get("id_matches") is False:
        # Never run an image that is not the expected one, or whose config would preload
        # code into the measurement itself.
        result["measured"] = False
        return finish(result, report)
    result["measured"] = True
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
    result["python"] = {k: bounded(v, 100) for k, v in measured["python"].items()}
    result["interpreter"] = {k: bounded(v, 300) for k, v in measured["interpreter"].items()}
    result["site"] = bounded(measured["site"], 300)
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
    checks["image_id"] = "compared" if a.expect_id else "not bound (no --expect-id)"
    if a.expect_wheel_sha256 and wheel_sha != a.expect_wheel_sha256:
        report.violation("wheel_sha256_mismatch", str(wheel_sha))
    if a.expect_manifest_sha256 and manifest != a.expect_manifest_sha256:
        report.violation("manifest_sha256_mismatch", manifest)
    result.update(checks=checks, compared=compared)
    return finish(result, report)


def binding(a: argparse.Namespace) -> dict:
    return {
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


def finish(result: dict, report: Report) -> tuple[dict, int]:
    result["excluded"] = report.excluded
    result["violations"] = report.violations
    result["totals"] = report.totals
    ok = report.totals["violations"] == 0
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


def _terminate(signum: int, frame: object) -> None:
    raise SystemExit(128 + signum)  # unwinds through measure()'s container cleanup


def main(argv: list[str] | None = None) -> int:
    a = parse(sys.argv[1:] if argv is None else argv)
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, _terminate)
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
    if sys.stdout is None:  # started with no stdout: the caller gets no report
        return 2
    try:
        print(json.dumps(result, indent=2), flush=True)
    except (OSError, ValueError):  # the caller did not get the report: never a pass
        # let the interpreter's own final flush succeed, so the exit code stays 2
        with contextlib.suppress(OSError, ValueError):
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 2
    return code


if __name__ == "__main__":
    sys.exit(main())

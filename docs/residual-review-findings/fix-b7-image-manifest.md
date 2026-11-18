# Residual findings: sandbox image verification (B7 PR-2, 2026-11-15)

These are the accepted limits of `scripts/service-account/image_manifest.py`, after three full-depth reviews and one focused review (B7 PR-2, 2026-11-11 to 2026-11-15). The control checks the image against references kept outside it: either the release wheel, the source tree and the lock, or the installation. Its anchor is the image ID. A passing result is not an approval.

## Trust dependencies

- **The image's own interpreter performs the measurement.** A malicious interpreter can report anything; only the image ID and the owner's approval of it bind the result. The measurement runs under `-I -S -B` in a locked-down container with no network. The checks on site-packages contents, bytecode, startup hooks and `/etc/ld.so.preload` all run inside the image. A library preloaded through `/etc/ld.so.preload` could hide that file from the check. Only the image config (ID, environment) is judged on the host, before anything runs.
- **Ownership comes from the image's RECORD files.**
  - A top-level site-packages entry passes if a distribution's RECORD claims it. That RECORD is in the image, so only the image ID binds it.
  - The package's own RECORD may claim only its package, its dist-info and `../` launcher rows.
  - Every loadable top-level name is also checked to resolve to its single entry, whoever owns it.
  - A RECORD row that claims a name nothing imports (for example a data file) is still trusted.
- **Bytecode slot kinds.**
  - Compared: the order of the local, cell and free slots, read through CPython's private `_varname_from_oparg`. An interpreter without it makes the inspection INCOMPLETE.
  - Not compared: the slots' kind flags, which Python does not expose. Only the PEP 709 "hidden" flag can change alone without the comparison noticing, and on CPython 3.12 that has no observable effect.
- **Dependency file contents are not compared.** pip enforced the lock's wheel hashes at build time; after that only the image ID binds them.
- **Only the source's committed lock decides the exported dependency set** (added 2026-11-17, after the U10/U11 integration review). uv 0.12.20 otherwise follows `UV_PROJECT` or `UV_WORKING_DIR` to another project, drops the dev group on `UV_NO_DEV`, and exports the lock of a workspace declared in an ancestor directory, all with exit 0; a build and a verifier that followed the same decoy would agree. The release profile, the image build and `install.sh` therefore clear every `UV_*` variable, pass `--no-config --no-cache --project <absolute physical dir> --frozen --offline`, and refuse a `pyproject.toml` in any ancestor directory (logical or physical path), because no uv flag stops workspace discovery. The two shell paths share `scripts/uv-export-locked.sh`, which also refuses an empty or option-like project argument or one containing a newline; the image build exports without uv's header so no host path enters an image layer. Remaining limits:
  - **Installs and builds** (added 2026-11-17, owner-authorized follow-up). `install.sh`'s `uv venv` and `uv pip install` calls and both `uv build` paths run through `scripts/uv-clean.sh` with `--no-config`. uv 0.12.20 otherwise drops a hash-pinned package on `UV_EXCLUDE`, takes another platform's pinned wheels on `_PYTHON_HOST_PLATFORM`, adds bytecode on `UV_COMPILE_BYTECODE` or a `uv.toml` (user or working directory), builds another project on `UV_PROJECT` or `UV_WORKING_DIR` (all exit 0), and runs the backend with `PYTHONPATH` or in the interpreter `VIRTUAL_ENV` or `CONDA_PREFIX` names. A prefix denylist missed some of these, so the wrapper runs uv under `env -i` with an allow-list: `PATH`, `HOME`, `TMPDIR`, `XDG_DATA_HOME`, `XDG_CACHE_HOME`, `UV_OFFLINE`, `UV_CACHE_DIR`, `UV_LINK_MODE` (the U3 offline-cache contract and `install.sh`'s copy mode), and the proxy and CA variables. It uses only shell syntax and absolute paths, so, run with `sh` as every caller does, an exported shell function cannot widen it. Not covered:
    - **`uv python install` is not wrapped.** It reads the caller's uv settings and configuration, and a `UV_PYTHON_DOWNLOADS_JSON_URL` or a `uv.toml` naming another downloads list installs an archive checked only against the checksum that list supplies (reproduced in review). It carries U3's Python-archive contract, which does not yet say which settings it needs. **This is not an accepted limit:** it is recorded as X21 in the B7 plan, an unresolved, mandatory blocker before U3's release build. Until then `install.sh` (run by the developer, runbook step 4) must run from a clean environment, in a directory with no `uv.toml`, with no user or system uv configuration: an `env -i` run alone still reads `~/.config/uv/uv.toml` and `/etc/uv/uv.toml` (reproduced in review).
    - **The allowed variables are trusted.** `UV_CACHE_DIR` names the cache uv installs from; hashes bind what uv unpacks, not unpacked entries it reuses (the U11 cache residual). `HOME`, `XDG_CACHE_HOME` and `TMPDIR` locate the default cache and temporary files when `UV_CACHE_DIR` is unset, so the same residual applies there. `UV_LINK_MODE` is set by `install.sh` itself. `PATH`, `HOME`, `XDG_DATA_HOME` choose which `uv` and which interpreter build the wheel (the build interpreter is unpinned, a U11 residual; U3 records it). Proxy and CA variables affect transport only.
    - **Interpreter-discovery variables are dropped** (`UV_PYTHON`, `UV_PYTHON_INSTALL_DIR`, ...). A caller that relied on them for `uv build` gets the default discovery (`.python-version`, managed interpreters under `HOME`, `PATH`) or a closed failure; the U11 and U3 harnesses set none.
    - **`UV_VENV_SEED`** fails closed offline; its online effect (seeding pip and setuptools) was not tested here, but the wrapper drops it.
  - **`--no-config` also drops the project's own `[tool.uv]` table.** There is none; a test fails if one is added, because the export would then diverge from `uv sync`.
  - **Helper refusals exit 1**, a code uv's own failures (passed through) can also return; they are told apart by the `uv-export-locked: refusing:` prefix on stderr. The verifier reports either as INCOMPLETE.
  - **The `uv` binary is the one first on `PATH`** (as for the U11 build pin and the wrapper). A different uv could treat the lock differently; U3 records the uv version and hash (KTD13).
  - **The verifier's launcher is not hardened.** Runbook step 1 starts it with `uv run`, which itself follows `UV_PROJECT` to choose the interpreter. The verifier imports only the standard library, so its result does not depend on that interpreter, but a hostile environment there runs code as the developer, as any hostile developer environment would.
  - **Ancestor refusal is a superset of uv's discovery.** A `pyproject.toml` anywhere above the project, workspace or not, makes the export fail closed; so does a git worktree created inside the repository (sibling worktrees are unaffected).
- **The load profile does not re-derive the dependency set**, because the service account has no `uv`. It relies on the release check, through the expected image ID.
- **An expected value is only as trustworthy as the record it is copied from.** `--expect-id` and `--expect-wheel-sha256` must come from sealed build evidence. The tool checks their format, not where they came from.

## Not judged (inventoried or reported)

- **Startup hooks outside the virtual environment** (system site-packages, the standard library, later layers) are hashed into the manifest and listed as excluded, bound only by the image ID. The owner reviews them on the real image (U3).
- **The image's environment:**
  - Every entry is judged. The report lists the first 200 names, plus the total and whether the list was cut.
  - Rejected:
    - a malformed environment (not a list of `NAME=value` strings), as INCOMPLETE;
    - a name set twice;
    - any `LD_*` variable, and `/etc/ld.so.preload`;
    - any `PYTHON*` variable other than the two allowed. This rule is broad on purpose: a base image's `PYTHON_VERSION` fails closed until reviewed.
  - Not judged: other variables that can load or change native code, such as `GCONV_PATH`, `GLIBC_TUNABLES` and `NODE_OPTIONS`. Entrypoint, Cmd and PATH are reported (bounded) for U3, not judged; with a duplicate PATH the measurement still runs.
- **Launchers in the image's `bin/`, and `pyvenv.cfg`,** are not checked.
- **Directories:** an extra empty directory inside the package is not reported.
- **Non-dotted names only:** a top-level file whose name contains a dot before its import suffix (`a.b.py`) is not resolution-checked, because the finder cannot load it as a top-level module.
- **An unbound release check** (no `--expect-id`) exits 0. Its report says `NOT BOUND`, and it is diagnostic only. Automated callers must read `binding`, not just the exit code.
- **The release profile reads the working tree**, not a git commit, and does not require a clean tree.

## Operational limits

- **Loading is not transactional.** `load-image.sh` loads and tags the image before the check. A failed check leaves the image loaded under the stream's tags, and the script warns if `:local` names it. Sandbox preflight checks only that the tag exists. This is a promotion blocker until U3/U4 settle the loading strategy with plan G1/G5.
- **Container cleanup is best effort.** After a timeout, Ctrl-C, SIGTERM or SIGHUP, the measurement container is removed with `docker rm -f`.
  - After a timeout, a failed removal is named in the INCOMPLETE report.
  - After a signal, the run ends with 128 plus the signal number and prints no report; a failed removal is named on stderr only.
  - The operator has to clean up after:
    - a SIGKILL or SIGQUIT of the verifier;
    - a second signal during the cleanup;
    - a client killed before the daemon created the container (the removal then finds nothing).
  - The container has no `--log-driver none`, so the daemon's log keeps its output (the inventory) until `--rm` removes it.
- **`docker load` accepts every tag in the stream.** `load-image.sh` refuses a stream that loaded any image other than the expected one, or one it cannot inspect.
- **Exit codes:** exit 2 means a usage error (no JSON), an incomplete inspection, or a report that could not be written (including a closed or full stdout). All of these fail closed.
- **Root-only skips:** two tests skip when run as root, because unreadable files cannot be simulated for root. Run the suite unprivileged.

## Unverified until the real image (U3)

- **Image ID:** with the containerd image store, the ID must survive `docker save | docker load` between daemons, and it must have the form `sha256:<64 hex>`.
- **pip's install and compile paths:** `sysconfig` purelib, and timestamp `.pyc` at that path whose code matches field by field (the raw instruction stream and the slot order included) under the image's interpreter (Ubuntu 3.12, which must expose `_varname_from_oparg`).
- **Ubuntu's `site.venv()` and `getsitepackages()`,** including any extra site directory inside the environment.
- **System packages:** no pin is satisfied from system dist-packages.
- **pip's layout:**
  - pip's RECORDs own every top-level site-packages entry;
  - pip creates no top-level symlink;
  - no loadable top-level name of the pinned distributions duplicates a standard-library name or another entry.
- **The base image's environment:** it sets no other `PYTHON*` and no `LD_*` variable, and sets no name twice.
- **User site:** the image user has no user site directory.
- **Container limits:** the measurement fits them (1 GiB memory, 64 processes).
- **Wheel reproducibility:** load-profile dist-info equality across two separate wheel builds requires reproducible builds. PR-3 (U11) now pins the build backend with hashes on both build paths ([its residuals](fix-b7-build-backend-pin.md)); byte-equal wheels were shown in development only, and equality on the release commit is taken in U3.
- **The real daemon:** tests fake `docker` and `uv`, and drive the real command runner only against stub executables. A real daemon's behaviour (output volume, hangs, signal delivery to the container) is not exercised.

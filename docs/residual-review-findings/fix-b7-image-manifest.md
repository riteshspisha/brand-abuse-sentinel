# Residual findings: sandbox image verification (B7 PR-2, 2026-11-12)

Accepted limits of `scripts/service-account/image_manifest.py` after three full-depth reviews (B7 PR-2, 2026-11-11 to 2026-11-12). The control checks the image against references kept outside it: the release wheel, the source tree and the lock, or the installation. Its anchor is the image ID. A passing result is not an approval.

## Trust dependencies

- **The image's own interpreter performs the measurement.** A malicious interpreter can report anything; only the image ID and the owner's approval of it bind the result. The measurement runs under `-I -S -B` in a locked-down, network-less container.
- **Ownership comes from the image's RECORD files.** A top-level site-packages entry passes if a distribution's RECORD claims it. That RECORD is in the image, so the image ID binds it. The package's own RECORD may claim only its package, dist-info and launchers. Importable names are also checked to resolve to their single entry, whoever owns them. A RECORD row that claims a name nobody imports (for example a data file) is still trusted.
- **Dependency file contents are not compared.** pip enforced the lock's wheel hashes at build time; afterwards only the image ID binds them.
- **The load profile does not re-derive the dependency set** (the service account has no `uv`). It relies on the release check through the expected image ID.
- **An expected value is only as trustworthy as the record it is copied from.** `--expect-id` and `--expect-wheel-sha256` must come from sealed build evidence. The tool cannot tell where an argument came from.

## Not judged (inventoried or reported)

- **Startup hooks outside the virtual environment** (system site-packages, the standard library, later layers) are hashed into the manifest and listed as excluded, bound only by the image ID. The owner reviews them on the real image (U3).
- **The image's Entrypoint, Cmd, PATH and other variables** are reported (bounded), not judged. `LD_*`, `/etc/ld.so.preload` and any `PYTHON*` variable other than the two allowed are rejected. The `PYTHON*` rule is broad on purpose: a base image's `PYTHON_VERSION` fails closed until reviewed. `GLIBC_TUNABLES`, `NODE_OPTIONS` and similar are not judged.
- **Launchers in the image's `bin/` and `pyvenv.cfg`** are not checked.
- **An unbound release check** (no `--expect-id`) exits 0. Its report says `NOT BOUND`, and it is diagnostic only.
- **The release profile reads the working tree**, not a git commit, and does not require a clean tree.

## Operational limits

- **Loading is not transactional.** `load-image.sh` loads and tags the image before the check. A failed check leaves the image loaded under the stream's tags, and the script warns if `:local` names it. Sandbox preflight checks only that the tag exists. This is a promotion blocker until U3/U4 settle the loading strategy with plan G1/G5.
- **Container cleanup is best effort.** After a timeout, Ctrl-C, SIGTERM or SIGHUP, the measurement container is removed with `docker rm -f`. If that fails, the report says the container may still be running. The operator has to clean up after:
  - a SIGKILL of the verifier;
  - a second signal during the cleanup;
  - a client killed before the daemon created the container (the removal then finds nothing).
- **`docker load` accepts every tag in the stream.** `load-image.sh` refuses a stream that loaded any image other than the expected one.
- **Exit 2 means a usage error (no JSON) or an incomplete inspection.** Both fail closed. A signal ends the run with 128 plus its number.
- **Two tests skip when run as root** (unreadable files cannot be simulated for root). Run the suite unprivileged.

## Unverified until the real image (U3)

- With the containerd image store, the image ID must survive `docker save | docker load` between daemons.
- pip's install and compile paths: `sysconfig` purelib, and timestamp `.pyc` at that path whose code matches field by field, including the raw instruction stream, under the image's interpreter (Ubuntu 3.12).
- Ubuntu's `site.venv()` and `getsitepackages()`, including any extra site directory inside the environment.
- No pin is satisfied from system dist-packages.
- pip's RECORDs own every top-level site-packages entry.
- The base image sets no other `PYTHON*` and no `LD_*` variable.
- The image user has no user site directory.
- The measurement fits the container limits (1 GiB memory, 64 processes).
- Load-profile dist-info equality across two separate wheel builds requires reproducible builds (PR-3).
- The top-level importable names of the pinned distributions resolve to their own entries (no pinned module duplicates a standard-library name).
- Tests fake `docker` and `uv`. A real daemon's behaviour (output volume, hangs, signal handling) is not exercised.

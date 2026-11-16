# Residual findings: build backend pin (B7 U11)

Accepted limits after a full-depth review. The control makes both wheel-build paths use
one hash-pinned backend. It does not make the build environment trustworthy by itself.

- **The pin binds what uv installs, not what it reuses.** uv checks hashes when it
  downloads or unpacks an archive, and trusts unpacked cache entries afterwards. A
  tampered cache with the same versions would pass `--require-hashes` and the image
  script's `Generator` check. The release build relies on U3 verifying its private cache
  copy against the content and metadata pins before each build.
- **Offline is the caller's job (assumption A1).** The scripts do not force `--offline`.
  U3 sets `UV_OFFLINE=1` and `UV_CACHE_DIR`, inside a boundary with no network. Online,
  the hashes still bind the backend's identity.
- **The uv binary is not pinned by the scripts.** They run the `uv` first on `PATH`. A
  uv with another cache layout (`/usr/bin/uv` 0.13.8 on the development host uses
  `simple-v27`; the pinned cache is `simple-v25`) finds nothing offline and fails closed.
  Enforcement was shown with uv 0.12.20 only. U3 records the uv version and hash (KTD13).
- **The install path does not check its own `Generator` line.** It relies on uv's
  enforcement, with build isolation and hash checks protected by clearing their
  variables and `--no-config`. The image path checks it, and U3 compares the two wheels.
- **The build interpreter is not pinned.** hatchling is pure Python and the wheel is
  `py3-none-any`, so bytes are not expected to depend on it. U3's wheel equality covers it.
- **Equality needs a clean tree.** The image script builds the working tree and prints
  the commit, marked when there are uncommitted changes. `install.sh` builds a
  `git archive` of `HEAD` and refuses a dirty tree. Only clean builds of the same commit
  are comparable.
- **`export-ignore`.** The test checks only the root `.gitattributes`. A nested or
  `.git/info/attributes` rule dropping `build-constraints.txt` makes `install.sh` fail
  closed, not build unpinned.
- **The backend closure is a constant.** The test compares the pin file with a fixed set,
  not hatchling's metadata. A new build dependency in a future backend fails the build
  (`--require-hashes`), so it is caught when the pin is changed.
- **Evidence is development evidence.** Wheel equality and the refusals were shown offline
  on the developer host, against private cache copies. Acceptance is taken in U3 on the
  release commit (KTD13).

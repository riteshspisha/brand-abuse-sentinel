"""Check the production anchor and store marker of an installation, changing nothing.

    <prefix>/venv/bin/python -I -B check_anchor.py <prefix> [--marker]

Run as the service account. No Docker is needed, so B7 can run it before Docker is
authorized: first without `--marker` (just after the anchor is installed), then with it
(after the live store is marked). `validate.sh` runs it with `--marker`.

Exit codes: 0 every check passed; 1 violations; 2 the inspection is incomplete, so
nothing can be concluded. Prints one line per check, with names only.

A pass means the anchor is present and root-owned with a root-owned directory chain,
names this prefix, agrees with the installed `service.yaml`, has a store path with no
symlink component, and the running package lies inside the prefix; with `--marker`,
the store holds a valid marker. It does not mean the store or the installation is
unmodified, and the marker is an accidental-misuse signal, not an identity
(docs/concepts/security.md).
"""

import os
import stat
import sys
from pathlib import Path


def _symlink_free(path: Path) -> bool:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        if stat.S_ISLNK(os.lstat(current).st_mode):
            return False
    return True


def _under(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def check(prefix: Path, *, marker: bool) -> list[tuple[str, bool]]:
    from brandsentinel.config import load_config
    from brandsentinel.store import identity

    results: list[tuple[str, bool]] = []
    try:
        anchor = identity.load_anchor()
    except identity.StoreRefused:
        return [("anchor_safe", False)]
    results.append(("anchor_present", anchor is not None))
    if anchor is None:
        return results
    results.append(("anchor_safe", True))
    results.append(("prefix_matches_anchor", anchor.install_prefix == prefix))
    results.append(("store_path_symlink_free", _symlink_free(anchor.store_path)))
    results.append(
        ("config_matches_anchor", load_config(anchor.config_path).data_dir == anchor.store_path)
    )
    package = identity.package_dir()
    results.append(("package_installed", _under(package, anchor.install_prefix.resolve() / "venv")))
    if marker:
        try:
            valid = identity._read_marker(anchor.store_path)
        except identity.StoreRefused:
            valid = False
        results.append(("marker_valid", valid))
    return results


def main(argv: list[str]) -> int:
    args = [a for a in argv if a != "--marker"]
    if len(args) != 1:
        print("usage: check_anchor.py <prefix> [--marker]", file=sys.stderr)
        return 2
    # load_config honours these, so the comparison would not be the installed file's.
    if os.environ.get("BRANDSENTINEL_CONFIG") or os.environ.get("BRANDSENTINEL_DATA_DIR"):
        print("INCOMPLETE  store variables are set: unset them", file=sys.stderr)
        return 2
    try:
        results = check(Path(args[0]), marker="--marker" in argv)
    except Exception as e:  # any failure to look is incomplete, never a pass
        print(f"INCOMPLETE  {type(e).__name__}", file=sys.stderr)
        return 2
    for name, ok in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    return 0 if all(ok for _, ok in results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

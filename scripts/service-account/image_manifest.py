"""Identity and provenance of the sandbox image (SP1).

Prints, and checks, three facts about an image on one Docker endpoint:

- its ID (the sha256 of the image config, which names every layer's content, so
  two daemons holding the same ID hold identical content);
- the base image digest pinned in the Dockerfile of the given source tree;
- whether every Python file of the `brandsentinel` package inside the image is
  byte-identical to the given source tree (computed in a network-less container).

    python image_manifest.py --docker-host unix:///run/user/N/docker.sock \
        --source /opt/brandsentinel/src [--expect-id sha256:...]

Exit status 0 only when the package matches the source (and the ID matches
`--expect-id`, when given).
"""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

IMAGE = "brandsentinel-sandbox:local"
INSIDE = r"""
import hashlib, json, pathlib, brandsentinel
root = pathlib.Path(brandsentinel.__file__).parent
print(json.dumps({str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in sorted(root.rglob("*")) if p.suffix in (".py", ".sql", ".j2")}))
"""


def docker(host: str, *args: str) -> str:
    binary = shutil.which("docker") or "/usr/bin/docker"
    return subprocess.run(  # noqa: S603 - fixed argv
        [binary, "--host", host, *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--docker-host", required=True)
    ap.add_argument("--source", type=Path, required=True)
    ap.add_argument("--image", default=IMAGE)
    ap.add_argument("--expect-id")
    a = ap.parse_args()

    image_id = docker(a.docker_host, "image", "inspect", "--format", "{{.Id}}", a.image)
    created = docker(a.docker_host, "image", "inspect", "--format", "{{.Created}}", a.image)
    inside = json.loads(
        docker(
            a.docker_host,
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "python3",
            a.image,
            "-c",
            INSIDE,
        )
    )
    pkg = a.source / "src" / "brandsentinel"
    local = {
        str(p.relative_to(pkg)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(pkg.rglob("*"))
        if p.suffix in (".py", ".sql", ".j2")
    }
    differ = sorted(k for k in local.keys() | inside.keys() if local.get(k) != inside.get(k))
    base = re.search(r"^FROM\s+(\S+)", (a.source / "docker/Dockerfile.sandbox").read_text(), re.M)
    report = {
        "image": a.image,
        "image_id": image_id,
        "created": created,
        "dockerfile_base": base.group(1) if base else None,
        "package_files": len(local),
        "package_files_differing": differ,
    }
    ok = not differ
    if a.expect_id:
        report["expected_id"] = a.expect_id
        report["id_matches"] = image_id == a.expect_id
        ok = ok and report["id_matches"]
    report["verdict"] = "ok" if ok else "MISMATCH"
    print(json.dumps(report, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

"""MkDocs hook: repository links.

Pages link to repository files with relative paths (`../../src/brandsentinel/cli.py`,
`../plans/...md`) so they work when read on GitHub or in a checkout. On the site such a
target is either outside `docs/` or deliberately not published (`exclude_docs`), so
this hook rewrites those links to the file on the repository host, and fails the build
when the target does not exist in the repository. Links to published pages are left to
MkDocs' own validation.
"""

from __future__ import annotations

import posixpath
import re
from pathlib import Path

from mkdocs.exceptions import PluginError

LINK = re.compile(r"(?<!!)\[(?P<text>[^\]\n]+)\]\((?P<target>[^)\s]+)\)")
FENCE = re.compile(r"^(```|~~~)")


def _repo_root(config) -> Path:
    return Path(config["config_file_path"]).resolve().parent


def on_page_markdown(markdown: str, page, config, files):
    root = _repo_root(config)
    docs_dir = Path(config["docs_dir"]).resolve()
    repo_url = config["repo_url"].rstrip("/")
    page_dir = (docs_dir / page.file.src_uri).parent
    published = {f.src_uri for f in files if f.inclusion.is_included()}

    def rewrite(m: re.Match) -> str:
        target = m.group("target")
        if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith(("#", "/")):
            return m.group(0)
        path, _, anchor = target.partition("#")
        resolved = (page_dir / path).resolve()
        try:
            rel_repo = resolved.relative_to(root).as_posix()
        except ValueError:
            raise PluginError(
                f"{page.file.src_uri}: link {target!r} leaves the repository"
            ) from None
        try:
            rel_docs = resolved.relative_to(docs_dir).as_posix()
        except ValueError:
            rel_docs = None
        if rel_docs is not None and rel_docs in published:
            return m.group(0)  # a published page or asset: MkDocs validates it
        if (
            rel_docs is not None
            and resolved.is_dir()
            and posixpath.join(rel_docs, "index.md") in published
        ):
            return m.group(0)
        if not resolved.exists():
            raise PluginError(f"{page.file.src_uri}: link {target!r} -> {rel_repo} does not exist")
        kind = "tree" if resolved.is_dir() else "blob"
        url = f"{repo_url}/{kind}/main/{rel_repo}" + (f"#{anchor}" if anchor else "")
        return f"[{m.group('text')}]({url})"

    out, in_fence = [], False
    for line in markdown.split("\n"):
        if FENCE.match(line.lstrip()):
            in_fence = not in_fence
        out.append(line if in_fence else LINK.sub(rewrite, line))
    return "\n".join(out)

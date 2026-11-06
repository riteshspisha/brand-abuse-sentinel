"""Documentation checks (docs/development/documentation.md, "Automated checks").

They keep README.md, AGENTS.md and docs/ consistent with the implementation: the generated
CLI reference, documented commands and options, configuration examples, repository links,
diagram fences, and the absence of host-specific or personal data in published pages.
The strict site build (mkdocs build --strict) is run separately; it needs the docs
toolchain from docs/requirements.txt.
"""

import importlib.util
import re
import shlex
from functools import cache
from pathlib import Path

import pytest
import typer.main
import yaml

from brandsentinel.cli import app
from brandsentinel.config import Config, load_config

REPO = Path(__file__).resolve().parents[2]
DOCS = REPO / "docs"
FENCE = re.compile(r"^(?P<indent>\s*)(?P<fence>```|~~~)(?P<info>[^\n`]*)$")
LINK = re.compile(r"(?<!!)\[[^\]\n]+\]\((?P<target>[^)\s]+)\)")


# --- which files ---------------------------------------------------------------------


class _Loader(yaml.SafeLoader):
    pass


_Loader.add_multi_constructor("tag:yaml.org,2002:python/", lambda loader, suffix, node: suffix)


@cache
def mkdocs_config() -> dict:
    return yaml.load((REPO / "mkdocs.yml").read_text(), Loader=_Loader)  # noqa: S506 - restricted loader


def _excluded(rel: str) -> bool:
    for pattern in mkdocs_config()["exclude_docs"].split():
        pattern = pattern.strip()
        if pattern.endswith("/") and rel.startswith(pattern):
            return True
        if Path(rel).match(pattern):
            return True
    return False


def all_markdown() -> list[Path]:
    return [REPO / "README.md", REPO / "AGENTS.md", *sorted(DOCS.rglob("*.md"))]


def published_markdown() -> list[Path]:
    out = [REPO / "README.md", REPO / "AGENTS.md"]
    for p in sorted(DOCS.rglob("*.md")):
        if not _excluded(p.relative_to(DOCS).as_posix()):
            out.append(p)
    return out


# Maintained by this documentation system. History pages (milestone demo log, review
# findings, solutions) and plans record what was true at the time and are not rewritten.
def maintained_markdown() -> list[Path]:
    history = ("plans/", "residual-review-findings/", "solutions/", "runbooks/")
    return [
        p
        for p in all_markdown()
        if not p.is_relative_to(DOCS) or not p.relative_to(DOCS).as_posix().startswith(history)
    ]


def code_blocks(path: Path) -> list[tuple[str, str, int]]:
    """(info string, body, first line number) of every fenced block."""
    blocks, cur, info, start = [], None, "", 0
    for n, line in enumerate(path.read_text().split("\n"), 1):
        m = FENCE.match(line)
        if m and cur is None:
            cur, info, start = [], m.group("info").strip(), n + 1
        elif m and cur is not None and not m.group("info").strip():
            blocks.append((info, "\n".join(cur), start))
            cur = None
        elif cur is not None:
            cur.append(line)
    return blocks


def prose_lines(path: Path):
    inside = False
    for n, line in enumerate(path.read_text().split("\n"), 1):
        if FENCE.match(line):
            inside = not inside
            continue
        if not inside:
            yield n, line


def ids(paths: list[Path]) -> list[str]:
    return [p.relative_to(REPO).as_posix() for p in paths]


# --- the CLI reference and documented commands ---------------------------------------


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "gen_cli_reference", DOCS / "tools/gen_cli_reference.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_cli_reference_is_generated_from_the_current_cli():
    gen = _load_generator()
    assert (DOCS / "reference/cli.md").read_text() == gen.render(), (
        "docs/reference/cli.md is stale: run `uv run python docs/tools/gen_cli_reference.py`"
    )


@cache
def command_tree():
    return typer.main.get_command(app)


def _options(cmd) -> set[str]:
    return {
        o for p in cmd.params for o in (*getattr(p, "opts", ()), *getattr(p, "secondary_opts", ()))
    }


SHELL_STOP = {"|", "||", "&&", ";", ">", ">>", "<", "2>&1", "&", "\\"}


def check_invocation(words: list[str]) -> str | None:
    """words: everything after `brandsentinel`. Returns an error or None."""
    root = command_tree()
    i = 0
    while i < len(words) and words[i] in ("-c", "--config"):
        i += 2
    cmd, path = root, []
    while hasattr(cmd, "commands") and i < len(words):
        name = words[i]
        if name.startswith("-") or name.startswith("<") or name in SHELL_STOP:
            break
        if name not in cmd.commands:
            return f"unknown command {' '.join([*path, name])!r}"
        cmd, path, i = cmd.commands[name], [*path, name], i + 1
    if hasattr(cmd, "commands"):
        return None  # a group shown on its own (`brandsentinel cases`)
    known = _options(cmd) | {"--help"}
    for w in words[i:]:
        if w in SHELL_STOP or w.startswith("#"):
            break
        if w.startswith("--") and w.split("=", 1)[0] not in known:
            return f"{' '.join(path)}: unknown option {w!r}"
    return None


INVOCATION = re.compile(r"(?:^|\s|/)brandsentinel(?=\s)(?P<rest>.*)$")


def documented_invocations(path: Path):
    for info, body, start in code_blocks(path):
        if info.split()[:1] and info.split()[0] not in ("sh", "bash", "console", "shell", "text"):
            continue
        for off, line in enumerate(body.split("\n")):
            m = INVOCATION.search(line)
            if not m or "brandsentinel-" in line.split("brandsentinel", 1)[0][-1:]:
                continue
            try:
                words = shlex.split(m.group("rest"), comments=True)
            except ValueError:
                words = m.group("rest").split()
            yield start + off, line.strip(), words


@pytest.mark.parametrize("path", maintained_markdown(), ids=ids(maintained_markdown()))
def test_documented_commands_and_options_exist(path):
    errors = []
    for n, line, words in documented_invocations(path):
        err = check_invocation(words)
        if err:
            errors.append(f"{path.relative_to(REPO)}:{n}: {err}: {line}")
    assert not errors, "\n".join(errors)


def test_the_command_check_catches_mistakes():
    assert check_invocation(["-c", "x.yaml", "cases", "show", "1"]) is None
    assert check_invocation(["run", "--until-idle", "--duration", "5"]) is None
    assert check_invocation(["run", "--no-fetch"]) is None
    assert "unknown option" in check_invocation(["run", "--until-done"])
    assert "unknown command" in check_invocation(["cases", "delete", "1"])
    assert "unknown command" in check_invocation(["frobnicate"])


# --- configuration -------------------------------------------------------------------


def config_examples():
    for path in all_markdown():
        for info, body, start in code_blocks(path):
            if info.split()[:1] == ["yaml"] and re.search(r"^data_dir:", body, re.M):
                yield pytest.param(body, id=f"{path.relative_to(REPO)}:{start}")


@pytest.mark.parametrize("body", list(config_examples()))
def test_config_examples_in_the_docs_validate(body):
    Config.model_validate(yaml.safe_load(body))


@pytest.mark.parametrize("name", ["brandsentinel.example.yaml", "lab.yaml", "service.yaml"])
def test_committed_configs_validate(name, monkeypatch):
    monkeypatch.delenv("BRANDSENTINEL_CONFIG", raising=False)
    monkeypatch.delenv("BRANDSENTINEL_DATA_DIR", raising=False)
    load_config(REPO / "config" / name)


def _missing(model, data, prefix="") -> list[str]:
    out = []
    for name, field in model.model_fields.items():
        sub = data.get(name) if isinstance(data, dict) else None
        if hasattr(field.annotation, "model_fields"):
            out += _missing(field.annotation, sub or {}, f"{prefix}{name}.")
        elif not isinstance(data, dict) or name not in data:
            out.append(prefix + name)
    return out


def test_example_config_lists_every_setting():
    example = yaml.safe_load((REPO / "config/brandsentinel.example.yaml").read_text())
    assert _missing(Config, example) == [], "add these keys to config/brandsentinel.example.yaml"


# --- links and diagrams --------------------------------------------------------------


@pytest.mark.parametrize("path", all_markdown(), ids=ids(all_markdown()))
def test_relative_links_resolve(path):
    broken = []
    for n, line in prose_lines(path):
        for m in LINK.finditer(line):
            target = m.group("target")
            if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
                continue
            file_part = target.split("#", 1)[0]
            if not (path.parent / file_part).resolve().exists():
                broken.append(f"{path.relative_to(REPO)}:{n}: {target}")
    assert not broken, "\n".join(broken)


MERMAID_TYPES = (
    "flowchart",
    "graph",
    "sequenceDiagram",
    "stateDiagram-v2",
    "stateDiagram",
    "classDiagram",
    "erDiagram",
    "gantt",
)


@pytest.mark.parametrize("path", all_markdown(), ids=ids(all_markdown()))
def test_mermaid_blocks_name_a_diagram_type(path):
    for info, body, start in code_blocks(path):
        if info == "mermaid":
            first = next((ln.strip() for ln in body.split("\n") if ln.strip()), "")
            assert first.split()[0] in MERMAID_TYPES, f"{path.relative_to(REPO)}:{start}: {first!r}"


# --- nothing sensitive in published pages --------------------------------------------

SENSITIVE = {
    "home directory path": re.compile(r"/home/[a-z_][a-z0-9_-]*/|/Users/[A-Za-z]"),
    "e-mail address": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "private key": re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
    "token": re.compile(
        r"\b(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,})"
    ),
    "evidence directory": re.compile(r"\b[a-z0-9-]+-\d{8}T\d{6}Z\b"),
}
# Documentation and project addresses: loopback, the pinned Docker subnets
# (172.31.250-254.x), cloud metadata (as an example of what is refused), RFC 5737.
ALLOWED_IPV4 = re.compile(
    r"^(127\.|0\.0\.0\.0$|172\.31\.25[0-4]\.|169\.254\.169\.254$|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)"
)
IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
# Reviewed exact values that are generic, not host-specific. Add with a reason.
REVIEWED = {
    "1.1.1.1": "public resolver, a bypass-test destination (runbooks)",
    "8.8.8.8": "public resolver, a bypass-test destination (runbooks)",
    "9.9.9.9": "public resolver, a bypass-test destination (runbooks)",
    "10.0.2.2": "rootlesskit/slirp4netns standard host address, a refused destination",
    "10.0.0.1": "example private address inside IPv6 wrappers netguard refuses",
    "info@site.org": "generic extractor example in the M5 review findings",
}


def sensitive_findings(text: str) -> list[str]:
    found = [
        f"{kind}: {m.group(0)}"
        for kind, rx in SENSITIVE.items()
        for m in rx.finditer(text)
        if m.group(0) not in REVIEWED
    ]
    found += [
        f"IPv4 address: {ip}"
        for ip in IPV4.findall(text)
        if not ALLOWED_IPV4.match(ip) and ip not in REVIEWED
    ]
    return found


@pytest.mark.parametrize("path", published_markdown(), ids=ids(published_markdown()))
def test_published_pages_carry_no_host_specific_or_personal_data(path):
    found = sensitive_findings(path.read_text())
    assert not found, f"{path.relative_to(REPO)}: " + "; ".join(found)


def test_the_sensitive_content_check_catches_examples():
    sample = "see /home/alice/x, mail bob@example.org, /var/lib/x/gate4-20261028T073350Z, 10.0.0.5"
    kinds = {f.split(":")[0] for f in sensitive_findings(sample)}
    assert kinds == {"home directory path", "e-mail address", "evidence directory", "IPv4 address"}
    assert not sensitive_findings(
        "proxy 172.31.251.2:3128, harness 127.77.0.1, refused 169.254.169.254"
    )


def test_excluded_pages_are_not_published():
    published = {p.relative_to(REPO).as_posix() for p in published_markdown()}
    assert "docs/runbooks/handoff.md" not in published
    assert "docs/runbooks/service-account.md" not in published
    assert not any(p.startswith("docs/plans/") for p in published)

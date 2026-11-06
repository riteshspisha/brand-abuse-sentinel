# Documentation system

## The rule

> A change that affects public behaviour, configuration, architecture, security
> properties or deployment updates the relevant documentation **in the same change**.
> A change of maturity (something merged, accepted, or found broken) updates
> [Status and maturity](../project/status.md).

What "relevant" means in practice:

| You changed… | Update |
|---|---|
| a CLI command or option | regenerate `docs/reference/cli.md`; guides that show the command |
| a config key or default | `config/brandsentinel.example.yaml` (a test enforces completeness); [Configuration](../reference/configuration.md) if it is safety-relevant |
| a stage, trigger or job behaviour | [Pipeline](../concepts/pipeline.md) |
| a rule, point or threshold | `config/policy.yaml` (bump `version`); [Evidence and scoring](../concepts/scoring.md) if a concept changed |
| a network, sandbox or account control | [Security model](../concepts/security.md), the relevant runbook |
| installation, promotion or recovery | [Deployment and recovery](../operations/deployment.md), the runbooks |
| what is done, accepted or pending | [Status and maturity](../project/status.md), [Roadmap](../project/roadmap.md) |

## Sources and layout

- **One source of truth:** Markdown under `docs/`, plus `README.md` and `AGENTS.md` at
  the repository root. The website is generated from the Markdown; there is no hand-written
  HTML.
- **Generated:** `docs/reference/cli.md`, from the Typer application, by
  `docs/tools/gen_cli_reference.py`.
- **Included at build time:** `config/policy.yaml` and `config/brandsentinel.example.yaml`
  are pulled in by snippet includes (`--8<--`), so the pages cannot drift from the files.
- **Sections:**
  - `guide/`: tasks;
  - `concepts/`: explanations;
  - `reference/`: lookup;
  - `development/`, `operations/`, `project/`;
  - the existing `runbooks/`, `solutions/` and `residual-review-findings/` are published
    as they are.

## Building the site

```sh
uv run --no-project --with-requirements docs/requirements.txt mkdocs build --strict   # → site/
uv run --no-project --with-requirements docs/requirements.txt mkdocs serve            # preview on 127.0.0.1:8000
```

**Toolchain:** MkDocs 1.6 with Material for MkDocs 9.8, pinned in `docs/requirements.txt`.

- It is never installed into the project environment, the wheel or the sandbox image.
- `--strict` turns every warning into a failure: broken links and anchors, pages missing
  from the navigation, and snippet files that do not exist.
- A small hook ([`docs/tools/mkdocs_hooks.py`](../tools/mkdocs_hooks.py)) rewrites links
  to repository files (source, config, plans) into links to the repository host. It fails
  the build if such a target does not exist.

**Why this tool:**

- MkDocs reads plain Markdown that also renders on GitHub, and needs no JavaScript build.
- Material gives search, navigation, light and dark themes, a responsive layout and
  accessible defaults.
- Mermaid diagrams render client-side.

Material for MkDocs reaches end of life on **2027-05-05**; it gets critical fixes until
then, according to the notice the 9.8.0 build prints. Its maintained successor, Zensical,
reads `mkdocs.yml`. Because the sources are plain Markdown with standard `pymdownx`
extensions and one small hook, the move should be a configuration change, not a rewrite.
Plan it before that date and verify it with the same checks.

Diagrams: Material loads Mermaid in the browser, from a CDN, when a page contains a
diagram. Offline viewing of the built site therefore shows diagram sources rather than
pictures; self-hosting the script is a follow-up if the site must work offline.

## Automated checks

`tests/unit/test_docs.py` runs in the normal test suite, with no extra dependencies:

| Check | Catches |
|---|---|
| CLI reference is current | a command or option changed without regenerating `docs/reference/cli.md` |
| Documented commands exist | `brandsentinel …` lines in code blocks naming a command or long option the CLI does not have |
| Config examples validate | YAML blocks that look like a BrandSentinel config (they have `data_dir:`) and every `config/*.yaml` that is a full config, loaded by the real model |
| Example config is complete | a model field missing from `config/brandsentinel.example.yaml` |
| Repository links resolve | relative links in `README.md`, `AGENTS.md` and `docs/**.md` that point at missing files |
| Diagrams are well-formed | each `mermaid` block starts with a known diagram type (rendering itself is client-side; review it in `mkdocs serve`) |
| Nothing sensitive is published | in published pages: home-directory paths, e-mail addresses, private keys or tokens, evidence directory names, and non-documentation IP addresses |

`tests/integration/test_offline_demo.py` runs the [offline demo](../guide/demo.md) end to
end and checks every case against its `expected.yaml`. The strict site build is the
remaining check. Run it before merging documentation changes.
[`.github/workflows/checks.yml`](../../.github/workflows/checks.yml) runs lint, the
offline suite, the CLI reference check and the strict build on every pull request. It
does not run the `docker or security` gate, which needs the rootless sandbox runtime.

## What is published

Everything under `docs/` is published except what `mkdocs.yml` excludes:

- `docs/plans/`: decision artifacts, linked as repository files;
- `docs/runbooks/handoff.md` and `docs/runbooks/service-account.md`: they record
  host-specific validation details;
- tooling: `docs/tools/`, `docs/demo/*.py`, `docs/requirements.txt`.

**Excluding a page is not access control.** `exclude_docs` keeps a page off the site,
but the repository is public: the source file, and every earlier version of it in the
git history, can be read on the repository host. Published pages link to excluded files
as repository links. So:

- never commit anything that must stay private (credentials, personal data, home
  directory paths, private evidence), excluded or not; the sensitive-content check
  covers published pages, `README.md` and `AGENTS.md` only;
- removing a record from the current tree does not remove it from the history.

The excluded runbooks hold operational records from the owner's host: install and
evidence directory names, timestamps, commit hashes, container bridge addresses and
locally bound listeners. They hold no credentials or personal data. They are excluded
because they are records rather than current guidance.

Publishing an excluded page is a decision. Remove host-specific records first, then delete
it from `exclude_docs`, and the sensitive-content check will cover it.

## Style

- Say what the code does, at what version, and where it was verified (developer machine,
  developer runtime, service account, production). Give counts and dates for test
  results.
- Mark anything copied from a milestone record and not re-run as *reported*.
- Never describe planned work as done. Never present lab or fixture results as field
  accuracy.
- Prefer a table or a command with its expected output over prose.

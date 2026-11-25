# In lab mode the host fetcher resolved a public name before refusing it

**Context.** In lab mode (KTD13) the host fetcher may fetch only lab hostnames,
and only through the lab proxy. `Fetcher._walk` validates every hop with
`NetGuard.validate`, which resolves a hostname that is not in the lab map. The
lab-only egress proxy has refused other names before DNS since M4. B7 PR-1 added
a resolver tripwire (`tests/resolver_tripwire.py`), installed for every test by
`tests/conftest.py`: any in-process query to the host's resolver is refused and
fails the test.

**Problem.** The first `docker or security` run (SP3) on the U14 branch, on
2026-11-25, gave 592 passed, 1 failed, 1 error, 0 skipped. Both the failure and
the error were
`tests/lab/test_lab_sites_up.py::test_host_fetcher_refuses_public_urls_in_lab_mode`.
It fetches `http://example.com/` with the lab fetcher and expects `blocked` with
`not_lab_host`. It got `dns_error`, and the tripwire teardown reported "the test
tried to use the host resolver". `config/lab.yaml` sets no nameservers, so the
lab resolver reads the host's configuration. Nothing was fetched, but in lab
mode a DNS query for a public name left the host before the policy refused it.
The U14 change touched nothing on this path; the test could not pass on any
commit since the tripwire landed.

**What did not help / why it hid.**

- The offline fetcher test,
  `test_public_url_is_refused_in_lab_mode_without_contacting_anything`, asserted
  that nothing was dialled (`calls == []`), not that nothing was resolved. Its
  harness resolver answered the query, so the refusal looked clean.
- The PR that added the tripwire changed shared test infrastructure only. It
  judged SP3 not applicable, because nothing under `src/brandsentinel/net/` or
  `src/brandsentinel/sandbox/` changed. The tripwire also applies to the Docker
  and lab suites, so the break stayed latent for 14 days and surfaced in an
  unrelated unit's merge gate.

**Root cause.** The lab-mode refusal ran after the function that resolves.
`validate` resolved any hostname outside the lab map, and the fetcher checked
`target.lab` only on the result. "Refuse before resolve" held in the proxy
([M4 correction](../residual-review-findings/feat-m4-sandbox-egress-lab.md#post-merge-correction-host-header-checked-before-dns)),
not in the host fetcher.

**Fix.** `NetGuard.validate` gains `lab_only`. A hostname outside the lab map is
refused before resolution. An IP literal needs no query: its address
classification runs first (a redirect to `169.254.169.254` is still refused as
a blocked link-local address), and a literal that is not a lab host is then refused. The fetcher
passes `lab_only` on every hop and drops its own check.

Before (`net/netguard.py`, `net/fetcher.py`):

```python
    async def validate(self, url: str) -> Validated:
        ...
        elif lab_host:
            addresses = [self._lab_hosts[t.host]]
        else:
            addresses = await self.resolver.resolve(t.host)
        return self.check_addresses(t, addresses, lab_host=lab_host)

# Fetcher._walk
                target = await self.guard.validate(current)
                if host_allowed is not None and not host_allowed(target.host):
                    raise PolicyViolation("host_not_allowed", {"host": target.host})
                if self.guard.lab_mode and not target.lab:
                    raise PolicyViolation("not_lab_host", {"host": target.host})
```

After:

```python
    async def validate(self, url: str, *, lab_only: bool = False) -> Validated:
        ...
        elif lab_host:
            addresses = [self._lab_hosts[t.host]]
        elif lab_only:
            raise PolicyViolation("not_lab_host", {"host": t.host})
        else:
            addresses = await self.resolver.resolve(t.host)
        validated = self.check_addresses(t, addresses, lab_host=lab_host)
        if lab_only and not validated.lab:
            raise PolicyViolation("not_lab_host", {"host": t.host})
        return validated

# Fetcher._walk
                target = await self.guard.validate(current, lab_only=self.guard.lab_mode)
                if host_allowed is not None and not host_allowed(target.host):
                    raise PolicyViolation("host_not_allowed", {"host": target.host})
```

Without `lab_only`, and outside lab mode, nothing changes. The accepted limits
(reason codes in lab mode, two exits in `validate`, lab-map key spelling) are in
the [residual findings for this fix](../residual-review-findings/fix-b7-lab-mode-dns-before-policy.md).

**Why this works.** The refusal now sits inside the function that would resolve,
on the only branch that would resolve. No caller can reach the resolver with a
non-lab name in lab mode, on the first hop or on a redirect, and a caller's
`host_allowed` check never sees such a name. Regression tests count resolver
queries (`StaticResolver.calls == []`) for direct fetches, redirects to public
names and literals, canonical and IDNA spellings, numeric and IPv6 literals, and
ordering against `host_allowed` (`tests/security/test_netguard.py`,
`test_lab_only_*`; `tests/security/test_lab_transport.py`). On the old code 26
failed and one errored. After the fix was merged into the U14 branch, SP3 gave
622 passed, 0 failed, 0 errors, 0 skipped (2747 deselected), with every named
regression test passing, the lab test included. That is development evidence
(AGENTS.md D5). U14 and the fix were merged together (#37); nothing here is
released or promoted.

**Prevention.**

- For every refusal that must precede DNS, assert the resolver's call count, not
  only that nothing was dialled. "Nothing contacted" includes the resolver.
- When a live gate fails, reproduce it offline if you can. Here the shipped
  `config/lab.yaml` and its real resolver, under the tripwire, reproduce the SP3
  failure without Docker
  (`test_shipped_lab_config_refuses_public_urls_without_the_host_resolver`).
- Shared test infrastructure is SP3-relevant: `tests/conftest.py`, the tripwire,
  autouse fixtures and pytest configuration load in the Docker and lab suites. The
  standing-gate triggers in AGENTS.md name only `src/brandsentinel/net/` and
  `src/brandsentinel/sandbox/`; widening them is a separate change. Until then, run `docker or security` for such changes anyway, and
  run the full gate early on a scratch daemon rather than only as the final merge
  gate.

**Gate evidence practice.** Lessons from running the gate twice in one day:

- When a gate fails, fix the code and rebind the same procedure to the new
  commit. Do not change acceptance (0 failed, 0 errors, 0 skipped) to get a pass.
- Prepare authorization forms in advance and hash the template, so the owner's
  edits can be verified by reverting the owner's fields and reproducing the hash.
- Decide deadlines on the measured limit of the runtime unit, not on an entered
  estimate. Where the two disagree, record both and use the measured one.
- Compare image inventories on machine fields (ID, `repo:tag`, digest), never on
  the human table, whose `CREATED` column is relative time.
- Parse wrapper logs by timestamped records, not physical lines: multi-line
  arguments span several lines.
- When a hard runtime limit applies, prepare the next phase's authorization
  before starting the current phase, so it can start as soon as the current one
  is sealed.

**Lesson.** A policy that must hold before DNS belongs inside the function that
resolves, and its tests must count resolver queries. See also
[name resolution in tests](../development/testing.md#name-resolution-in-tests).

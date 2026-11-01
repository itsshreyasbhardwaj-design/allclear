<div align="center">

# allclear

**Account-wide GitHub exposure audit that tells you which findings are real.**

[![CI](https://github.com/itsshreyasbhardwaj-design/allclear/actions/workflows/ci.yml/badge.svg)](https://github.com/itsshreyasbhardwaj-design/allclear/actions/workflows/ci.yml)
[![Security](https://github.com/itsshreyasbhardwaj-design/allclear/actions/workflows/security.yml/badge.svg)](https://github.com/itsshreyasbhardwaj-design/allclear/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-%E2%89%A53.9-blue.svg)](https://www.python.org)
[![dependencies: none](https://img.shields.io/badge/dependencies-none-success.svg)](pyproject.toml)

</div>

---

## Why this exists

I audited 48 GitHub repositories. A secret scanner produced **139 findings**.

**Every single one was a false positive.** Deliberate test fixtures, documentation
examples, vendored upstream code. Zero live credentials.

That is the actual problem. Not the absence of a scanner — scanners are free and
excellent. The problem is that a scanner pointed at real repositories produces a
volume of findings nobody can read, so people switch it off, and *then* the next
leak happens. The exposure is downstream of the noise.

So `allclear` does not try to find more. It tries to be **right about less**.

```
repositories examined : 48
findings that need you: 3
findings explained away: 136  (71 fixture, 42 example, 23 vendored)
```

## What it does that a scanner does not

### 1. It classifies findings, with reasons

Every finding gets a verdict and the rule that produced it, so you can disagree:

```
EXPLAINED (no action)
  [fixture]     src/lib/redact.test.ts:6   — a test file: the value is the test's own input
  [example]     docs/api.md:18             — documentation, where credentials are illustrative
  [vendored]    vendor/upstream/key.py     — lives under 'vendor/', third-party code
  [placeholder] .env.example:4             — '.env.example' is a template file by convention
```

Two rules make this trustworthy rather than merely quiet:

- **Unknown is treated as real.** Only an affirmative, explainable reason
  downgrades anything. A classifier that guesses "probably fine" is how a real
  credential gets missed.
- **A service-role or secret key is real wherever it lives** — including in a
  test file. Supabase *anon* keys are designed to reach a browser; service-role
  keys bypass row-level security entirely. The two must never be confused.

### 2. It knows severity is not exposure

The most useful thing the audit found was a **CRITICAL unauthenticated RCE that
could not execute**, because the site is a static export. There is no server.
The vulnerable code shipped nothing and ran never.

```console
$ allclear reachable ./marketing-site --advisory GHSA-2464-fhr4-w9xw
runs a server  : False
evidence:
  - next.config sets output: 'export' — the build emits static files only
  - images.loader is 'custom' — image URLs bypass /_next/image

GHSA-2464-fhr4-w9xw   unreachable   severity→low
```

The same advisory against a dashboard with middleware and server actions stays
`critical`. That difference decides which one you do first — and no CVSS score
contains it.

### 3. It finds the control that is off *everywhere*

Per-repository tools cannot make this finding. The audit's largest systemic gap
was Dependabot vulnerability alerts **disabled on 48 of 48 repositories** — free,
one API call each, invisible because no per-repo tool says "and also, none of
your others have this either."

```
SYSTEMIC (the same control is off nearly everywhere)
  dependabot-alerts: 48 of 48 repositories
```

### 4. It knows what your plan cannot do

Branch protection is unavailable for private repositories on the Free plan.
Reporting that as a finding tells you to fix something you cannot fix, and
trains you to ignore the tool. So it is reported separately:

```
Blocked by plan
  o/private-app  branch-protection  rulesets need Pro for private repositories
```

### 5. Its allowlist does not go blind

The lazy way to silence a known-benign finding is a path glob — ignore
`**/*.test.ts` and the noise goes away. So does the signal, permanently, in one
of the likeliest places for a real credential to land during debugging.

`allclear` writes **fingerprints** (`path:rule:line`), so a *new* secret in the
same file still fails. `allowlist.verify()` refuses to write an allowlist that
would hide anything actionable.

## Install

No dependencies. Python 3.9+ and the [`gh` CLI](https://cli.github.com)
(already authenticated — this tool never asks for a token, never reads one from
the environment, and never writes one anywhere).

```bash
git clone https://github.com/itsshreyasbhardwaj-design/allclear
cd allclear
python3 -m allclear --help          # or: pip install -e .
```

## Use

```bash
allclear audit                           # configuration across every repo you administer
allclear audit --markdown report.md      # ...and write a report
allclear secrets . --write-allowlist     # scan, classify, emit an audited .gitleaksignore
allclear reachable . --advisory GHSA-…   # is it actually exploitable as deployed?
allclear baseline .                      # write dependabot/security.yml/SECURITY.md
allclear apply --alerts --yes            # turn on what is off (the only writing command)
allclear selftest                        # verify the pinned gitleaks digests upstream
```

`audit` exits non-zero when something needs action, so it works as a CI gate.

### The baseline it writes

- **`dependabot.yml` — security updates only, by default.** Rolling version
  updates across 38 repositories produced **302 open pull requests in a few
  hours**. At that volume nobody reads them, and an unread dependency PR is
  worse than none because it buries the one that mattered.
  `open-pull-requests-limit: 0` disables version updates; GitHub does not apply
  that limit to security updates, so fixes still arrive. Pass
  `--allow-version-updates` to opt in.
- **`security.yml` — gitleaks from its official release binary**, pinned by
  version and verified against a published SHA-256, with `actions/checkout`
  pinned to a commit SHA. No third-party action, no mutable tag, no licence
  gate, and reproducible locally with the same binary.
- **`SECURITY.md`** pointing at private vulnerability reporting.

## What this is not

Being clear about this matters more than breadth:

- **Not a code scanner.** It will not find SQL injection or XSS in your source.
  For that, use [Sentinel AI](https://github.com/itsshreyasbhardwaj-design/sentinel-ai),
  CodeQL, or Semgrep. `allclear` audits *configuration* and *triages scanner output*.
- **Not a secret scanner.** gitleaks does the finding; this does the deciding.
- **Reachability covers Next.js only** today, because that is where the evidence
  was. Anything it has not been taught returns `unknown` and stays at full
  severity. An honest "I don't know" ranks above a confident guess.
- **It will not rotate a credential for you.** It tells you which provider and
  which key, and never prints the value.
- **Not a substitute for GitHub's own features.** Where secret scanning and push
  protection are available, turn them on; this helps you notice they are off.

## Design notes worth reading

Three bugs found by pointing this tool at itself and at real repositories, each
now a regression test:

1. **`"/docs/"` never matched `docs/api.md`.** A leading slash meant
   repository-root documentation went unclassified, which made a CI secret scan
   fail on day one. Path rules now match **segments**, not substrings.
2. **`lstrip("./")` ate the leading dot of dotfiles**, turning `.env.example`
   into `env.example`. `str.lstrip` takes a *set* of characters. Dotfiles are
   exactly the files a secret scanner cares about.
3. **A comment claimed `output: 'export'`** in a dashboard's `next.config.mjs`
   — describing a *different* site. The regex matched inside the comment and a
   CRITICAL image-optimiser RCE was reported **unreachable on an app that runs a
   server**. A false negative on an RCE is the worst error available here.
   Comments are now stripped, and optimiser availability is no longer derived
   from a static-export claim until that claim has survived contradiction.

Running `allclear secrets .` on this repository also reported two of its own
test fixtures as critical, because they were credential-shaped literals
indistinguishable from real keys. The allowlist **refused** to silence them —
correctly — so the fixtures are now assembled at runtime instead. A test that
needs a credential-shaped string should not commit one.

## Licence

MIT

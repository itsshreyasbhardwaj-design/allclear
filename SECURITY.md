# Security Policy

## Reporting a vulnerability

Please report security issues **privately**, not in a public issue.

Use GitHub's private vulnerability reporting on this repository:
**Security → Report a vulnerability**. If that is unavailable, contact
the maintainer address on this account's GitHub profile with `SECURITY` in the subject.

Please include what the issue is, how to reproduce it, the affected version or
commit, and anything you already know about impact.

**Please do not** open a public issue, a pull request containing an exploit, or
a public discussion thread for an unfixed vulnerability.

## What to expect

- Acknowledgement within **7 days**.
- An assessment, and either a fix or a clear explanation of why something is not
  considered a vulnerability, within **30 days** where that is achievable.
- Credit in the release notes if you would like it — please say so.

Response times are best-effort and stated honestly rather than optimistically.

## Scope

In scope: this repository's own source, its build and release workflows, and
its dependency manifests.

Out of scope: third-party dependencies with an existing public advisory —
Dependabot raises those. Directories documented as deliberately insecure
fixtures are not vulnerabilities; findings inside them are expected.

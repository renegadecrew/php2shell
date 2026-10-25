# Contributing

Thanks for helping improve PHP2Shell Exposure Check. Contributions should keep the tool bounded, transparent, and useful for defensive asset inventory.

## Before you start

- Open an issue for substantial changes so the approach can be discussed before implementation.
- For small fixes, a pull request is fine; explain the problem and the intended behavior.
- Do not include real organization hostnames, IP addresses, scan output, credentials, or other sensitive data in issues, tests, screenshots, or fixtures. Use reserved examples such as `example.com`.
- Do not add exploit payloads, intrusive probes, redirect following, or behavior that expands scans beyond the documented limits.

## Local development

Requirements: Node.js 20 or later and npm.

```sh
npm ci
npm test
npm start
```

Keep changes focused. Update documentation and tests when behavior changes. Tests must use local fixtures or reserved example domains; do not make live requests to third-party systems from tests.

## Branches and commits

Use short, descriptive branch names:

- `feat/<topic>` for features
- `fix/<topic>` for bug fixes
- `docs/<topic>` for documentation
- `chore/<topic>` for maintenance
- `security/<topic>` for security improvements

Use Conventional Commit subjects, for example:

```text
feat(scanner): report the checked PHP endpoint
fix(api): reject malformed scan identifiers
docs: clarify local-only access
test(scanner): cover HTTP 403 responses
chore(deps): update tldts
```

Keep the subject imperative and concise. Pull request titles should follow the same convention.

## Issues

Use the Bug report or Feature request form and keep one issue focused on one problem. The forms set the initial labels and title prefixes (`fix:` or `feat:`); maintainers may adjust labels during triage. Add sanitized logs only, and never attach live target findings.

## Pull requests and review

1. Explain the motivation, user-visible behavior, and any security impact.
2. Link the related issue when one exists.
3. Run `npm test` and include the result. CI must pass on every supported Node.js version.
4. Update the README or API documentation when behavior or limits change.
5. Request review from the relevant code owner. Maintainers should review scope, input validation, network behavior, privacy, and test coverage before approval.
6. Address review comments or explain why a change is not applicable. Do not merge while required checks are failing.

The author must not approve their own pull request. A maintainer may merge after review and passing CI. `CODEOWNERS` requests review from the current maintainer. The repository currently has one code owner, so branch protection requiring an independent approval is not enabled; it can be tightened when another reviewer is available.

## Security and disclosure

Report suspected vulnerabilities privately using the process in [SECURITY.md](SECURITY.md). Do not publish exploit details or affected third-party hosts in an issue or pull request.


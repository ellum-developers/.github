# Security Policy

## Reporting a vulnerability

Please report security issues privately — open a
[security advisory](https://github.com/ellum-developers/.github/security/advisories/new)
or contact the maintainers directly. Do not open a public issue for a
vulnerability. We aim to acknowledge reports within two business days.

## Automated supply-chain scanning

Every repository in this organization runs
[`supply-chain-guard`](.github/workflows/supply-chain-guard.yml) on push, on pull
requests, and daily on a schedule. It fails the build on anything critical or
high. To add it to a new repository:

```yaml
# .github/workflows/supply-chain-guard.yml
name: Supply-chain guard
on:
  push:
    branches: [main, master, develop, dev, staging]
  pull_request:
  schedule:
    - cron: '19 6 * * *'
  workflow_dispatch:
permissions:
  contents: read
jobs:
  guard:
    uses: ellum-developers/.github/.github/workflows/supply-chain-guard.yml@<FULL_COMMIT_SHA>
```

Pin the `uses:` ref to a full commit SHA of the reusable workflow, never a
branch. The guard reads its scanner from the same commit as the workflow
(`job.workflow_sha`), so a pinned ref fixes both the rules and the scanner that
runs them. A repository that tracks `@main` is judged by whatever is on that
branch at run time, so one commit there changes the rules for every repository
at once, with no review, no pinning, and nothing to notice it.

### What it looks for

The guard targets a dropper family that hides executable payloads in places
reviewers do not read, and takes its instructions from a public blockchain
rather than a server — so there is no domain to block and no host to take down.

| Rule | Severity | What it catches |
| --- | --- | --- |
| `known-c2-wallet` | critical | A known command-and-control wallet address |
| `campaign-marker` | critical | Constants unique to the dropper |
| `global-require-stash` | critical | `require`/`module` copied onto `global` — the bootstrap |
| `hidden-payload-padding` | critical | ≥16 tabs or ≥200 spaces before code, used to push a payload off-screen |
| `blockchain-c2` | critical | Ethereum JSON-RPC calls combined with process spawning |
| `masqueraded-asset` | critical | JavaScript wearing a `.woff2`/`.png`/`.wasm` extension |
| `exec-in-config` | critical | A build config spawning a child process |
| `magic-mismatch` | high | A binary asset whose header does not match its extension |
| `unused-createRequire` | high | `createRequire()` added to an ESM config that never calls `require` |
| `long-line-in-config` | high | A config line over 1000 characters — configs are not minified |
| `risky-install-hook` | high | `pre`/`post`install scripts that fetch or `eval` code |
| `vscode-folder-open-task` | high | A `.vscode` task set to run automatically on folder open |
| `vscode-auto-tasks-trusted` | high | `task.allowAutomaticTasks: true` — pre-approves auto-run tasks |
| `eth-rpc-endpoint` | medium | A public Ethereum RPC endpoint in source |

### Why these signals

The payload is appended to a file that already exists and is rarely reopened —
a PostCSS or ESLint config, or a font under `public/`. A long run of tab
characters sits between the legitimate code and the payload, so an editor shows
an apparently normal file and a diff shows one changed line. Structural rules
(`hidden-payload-padding`, `masqueraded-asset`, `long-line-in-config`) therefore
matter more than the indicator lists: they still fire when the wallet address
and constants change.

The same payload family also arms an editor loader: a `.vscode` task that runs
on folder open, with `task.allowAutomaticTasks` set so nothing prompts first.
The guard flags both keys in every repository, matching the pre-commit hook
that only `ellumAI_backend` runs today.

### Suppressing a false positive

Add the path to `.github/supply-chain-allow.txt`, one per line. Keep the list
short and justify each entry in the pull request that adds it.

## Hardening we expect of every repository

- Pin GitHub Actions to a full commit SHA, never a moving tag.
- Keep `permissions:` at `contents: read` unless a job genuinely needs more.
- Set `persist-credentials: false` on checkout unless you are pushing.
- Commit lockfiles, and review lockfile diffs as carefully as source diffs.
- Never commit credentials. Use repository or organization secrets.
- Prefer `npm ci --ignore-scripts` / `bun install --no-scripts` in CI where the
  build does not need install hooks.

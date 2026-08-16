# Seku CI/CD Integrations

Run a Seku security scan inside your pipeline, publish findings as **SARIF**, and
**fail the build** when issues meet or exceed a severity threshold — DevSecOps in
one step. No servers to run: the scan executes on Seku (sec.erticaz.com) and the
runner just orchestrates the API.

```
integrations/
├── ci/seku-scan.sh                    # portable POSIX runner (the engine)
├── github-action/action.yml           # GitHub composite Action
├── github-action/example-workflow.yml # drop-in .github/workflows sample
└── gitlab/seku-scan.gitlab-ci.yml     # GitLab CI template
```

## 1) One-time setup
1. **Create an API key** — Account → API Keys → generate. It starts with `vsk_`.
2. **Verify the domain** you'll scan (Targets → Verify: DNS TXT or `/.well-known` file).
   Non-admin keys can only scan **verified** domains (SSRF/abuse guard).
3. **Store the key as a CI secret**: `SEKU_API_KEY` (GitHub secret / GitLab masked variable).

## 2) GitHub Actions
Copy [`github-action/example-workflow.yml`](github-action/example-workflow.yml) to
`.github/workflows/seku.yml` and set `target:`. It uploads SARIF to the repo's
**Security → Code scanning** tab automatically.

```yaml
- uses: ./integrations/github-action
  with:
    api-key: ${{ secrets.SEKU_API_KEY }}
    target: https://app.example.com
    policy: standard      # light|standard = free · deep = pay-per-scan
    fail-on: high         # none|low|medium|high|critical
```
Outputs: `grade`, `score`, `critical`, `high`, `medium`, `low`, `sarif`, `result-id`.

## 3) GitLab CI
```yaml
include:
  - local: 'integrations/gitlab/seku-scan.gitlab-ci.yml'
```
Set `SEKU_API_KEY` + `SEKU_TARGET` in CI/CD variables. SARIF is stored as an
artifact and surfaced under the Security tab (Ultimate).

## 4) Any pipeline / local
The engine is a plain script — run it anywhere `curl` + `jq` exist:
```sh
SEKU_API_KEY=vsk_xxx SEKU_TARGET=https://app.example.com \
  SEKU_POLICY=standard SEKU_FAIL_ON=high sh integrations/ci/seku-scan.sh
```

## Policy-as-code (`.seku.yml`)
Drop a `.seku.yml` at the repo root to set defaults without touching pipeline YAML
(env vars still override it):
```yaml
policy: standard
fail_on: high
```

## Configuration reference
| Env | Default | Meaning |
|---|---|---|
| `SEKU_API_KEY` | — (required) | API key, `vsk_...` |
| `SEKU_TARGET` | — (required) | Full URL to scan |
| `SEKU_API_URL` | `https://sec.erticaz.com/api` | API base |
| `SEKU_POLICY` | `standard` | `light` \| `standard` \| `deep` (deep = paid) |
| `SEKU_FAIL_ON` | `high` | Gate severity: `none`\|`low`\|`medium`\|`high`\|`critical` |
| `SEKU_COUNT_WARN` | `0` | `1` = also count `warn` findings |
| `SEKU_SARIF_OUT` | `seku-results.sarif` | SARIF output path |
| `SEKU_TIMEOUT` | `900` | Max seconds to wait |

**Exit codes:** `0` clean/under-threshold · `1` gate breached · `2` config/scan error.

**Notes**
- `deep` policy (and any intrusive tool) is **pay-per-scan**; a non-admin key without
  credit gets HTTP 402 — use `standard` in CI, or purchase a deep-scan credit.
- Publishing the Action standalone? Copy `ci/seku-scan.sh` next to `action.yml`
  and update the `run:` path.

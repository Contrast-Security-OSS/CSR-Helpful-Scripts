# Security Review Status

This file tracks the security findings raised in `vulnerabilities-by-business-unit/fix-these-vulns.md` and which of them are addressed on the current branch.

## Addressed on `security-review-fixes`

| ID    | Title                                          | Status |
|-------|------------------------------------------------|--------|
| H-1   | Missing HTTP timeouts                          | Fixed across all in-branch scripts |
| H-3   | CSV injection                                  | `safe_csv_cell` helper added to SDK, applied at write sites |
| H-4   | Unconditional debug JSON dumps                 | Gated behind `--debug-dir` (0700 dir, 0600 file) |
| H-5   | Loose `.gitignore`                             | Broadened to glob output files |
| H-7   | Raw `response.text` printed on error           | Replaced with status-only, full body behind `--debug` |
| M-2   | Hardcoded server IDs                           | Removed or replaced with `--server-ids` argparse arg |
| M-3   | toggle-server-protect lacked audit log         | Status capture, `~/.contrast-csr/toggle-audit.log`, `--yes` flag |
| M-4   | Customer-identifying examples in comments      | Replaced with synthetic identifiers in-tree |
| M-5   | App name flowed into filename                  | `sanitize_filename` from SDK applied |
| M-6   | sessionMetadata printed to stdout              | `redact_response` helper added, prints gated behind `--verbose` |
| M-7   | Dependencies loosely pinned                    | `requirements.lock` generated with hashes via pip-compile |
| M-8   | No `LICENSE` file                              | Apache-2.0 added |
| M-9   | No retry/backoff                               | `requests.Session` + `urllib3.util.Retry` adapter added |
| M-10  | `/applications` fetched without pagination     | `offset`/`limit=50` loop added |
| M-11  | Module-level `headers` dict overwritten        | Moved inside `main()` |
| M-12  | Naive CSV parsing via `line.split(",")`        | Replaced with `csv.reader` |
| L-1   | No `chmod 600` guidance for `.creds`           | Added to `template.creds` and README |
| L-2   | `print(headers)` leaked Authorization          | Removed or replaced with `list(headers.keys())` |
| L-4   | `os.system('clear')` hid errors                | Removed |
| L-5   | No data-handling guidance                      | New "Handling Exported Data" section in README |
| L-7   | `specific_apps.csv` historical content         | Already empty in HEAD, warning comment added |
| Info-2 | `verify=True` explicit                        | Skipped, default behaviour is already safe |

## Deferred — Files Not Present on `get-user-info` Branch

The following scripts are on separate feature branches not yet merged into `main` or this branch. Each branch needs the same patterns applied before merging.

| ID    | File                                              | Branch                                | Patterns to Apply |
|-------|---------------------------------------------------|---------------------------------------|---|
| H-2   | `get-agents-info/get-agents-info.py`              | `agents` (or unmerged)                | Stop mutating shared `headers` dict, build Basic auth value once in main |
| H-3   | `get-attacks-csv/get-attacks-csv.py`              | `feature/get-attacks-csv`             | `safe_csv_cell` on every cell |
| H-3   | `get-vulnerabilities-csv/get-vulnerabilities-csv.py` | `feature/get-vulns-csv`             | `safe_csv_cell` on every cell |
| H-3   | `risk-sense-integration/risk-sense-integration.py` | `feature/risk-sense-integration`     | `safe_csv_cell` on every cell |
| H-4   | (same three files above)                          | same                                  | Gate debug dumps behind `--debug-dir` |
| H-7   | (same three files above)                          | same                                  | Replace `response.text` with status-only |
| L-6   | `get-vulnerabilities-csv/get-vulnerabilities-csv.py` | `feature/get-vulns-csv`             | Validate CWE URL with `urllib.parse`, silent empty on malformed |
| M-1   | `risk-sense-integration/risk-sense-integration.py` | `feature/risk-sense-integration`    | Narrow `except Exception` to `requests.RequestException`, fail-fast on auth error |
| M-9   | All four absent scripts                           | various                               | Add Session + Retry adapter |

When merging any of these feature branches into a release branch, also apply the helper imports from `contrast_security.utils` (`safe_csv_cell`, `redact_response`) and the `_make_session()` pattern used in the other in-branch scripts.

## Not Addressed — User Decision

| ID    | Title                                          | Decision |
|-------|------------------------------------------------|----------|
| H-6   | Sample CSV may contain real Semgrep output     | User opted to treat as synthetic. The file lives on `feature/risk-sense-integration`, not this branch. No history rewrite. Re-validate when that branch merges. |
| L-3   | `inventory-win-webapps.ps1` is placeholder     | Out of scope for this sweep |
| Info-1 | GHA workflow is a positive control            | No action required |
| Info-3 | Add disclosure email at repo root              | Optional, skipped |

## Helpers Added

Two new utility functions live in `contrast-security-api-client/contrast_security/utils.py`:

- `safe_csv_cell(value)` — prefixes spreadsheet-formula characters (`=+-@\t\r`) with a single quote so CSV cells render as literal text.
- `redact_response(data)` — deep-walk dict/list, replaces values under sensitive keys (Authorization, API-Key, cookies, sessionMetadata, request_headers, response_headers, etc.) with `"<redacted>"`.

The existing `sanitize_filename` was also brought into play.

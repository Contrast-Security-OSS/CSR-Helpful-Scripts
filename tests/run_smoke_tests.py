# SPDX-License-Identifier: Apache-2.0
"""
Integration smoke-test runner for CSR-Helpful-Scripts.

Invokes each script in this repo as a subprocess against a live Contrast org
and reports pass / fail.

Usage:

    python tests/run_smoke_tests.py
        # read-only scripts only, against the .creds file at repo root.

    python tests/run_smoke_tests.py --list
        # print the registry without running anything.

    python tests/run_smoke_tests.py --only get-user-info,get-licensed-apps
        # run a comma-separated subset (matched by script-name token).

    python tests/run_smoke_tests.py --include-mutating --confirm-org=<UUID>
        # also run the mutating scripts. The UUID must match the ORG_ID in
        # the .creds file. Without both flags, mutating scripts are skipped.

    python tests/run_smoke_tests.py --timeout 120
        # per-script timeout in seconds (default 60).

    python tests/run_smoke_tests.py --creds path/to/.creds
        # alternate creds file location.

Safety notes:

- Mutating scripts (toggle-server-protect, app-add-label, scan-add-label,
  policy-add-to-all-orgs, distribute-parent-rbac-to-children) are skipped by
  default. Run them only against a throwaway sandbox tenant.

- The runner runs scripts with stdin closed so any input() prompt fails
  immediately rather than hanging. Make sure .creds is fully populated.

- The runner never prints credential values. Header keys and status counts
  only.

- Output of each script is captured. Tails are printed on failure for
  diagnosis. Full output goes to --log-dir if provided (file mode 0600).
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclasses.dataclass
class ScriptSpec:
    name: str                       # short token used by --only and reports
    path: str                       # relative to REPO_ROOT
    kind: str                       # "read" or "mutate"
    args: List[str] = dataclasses.field(default_factory=list)
    requires: List[str] = dataclasses.field(default_factory=list)
    description: str = ""


# -------------------------------------------------------------------------
# Script registry.
#
# Add entries here as new scripts land. Keep kind="mutate" for anything that
# does a POST/PUT/PATCH/DELETE that changes server-side state.
# -------------------------------------------------------------------------
SCRIPTS: List[ScriptSpec] = [
    # Read-only fetchers
    ScriptSpec(
        name="get-licensed-apps",
        path="get-licensed-apps/get-licensed-apps.py",
        kind="read",
        description="List licensed applications with server info.",
    ),
    ScriptSpec(
        name="get-licensed-servers",
        path="get-licensed-servers/get-licensed-servers.py",
        kind="read",
        description="List licensed servers.",
    ),
    ScriptSpec(
        name="get-server-app-metadata",
        path="get-server-application-metadata/get-server-app-metadata.py",
        kind="read",
        description="Fetch server+application metadata pairs.",
    ),
    ScriptSpec(
        name="get-user-info",
        path="get-user-info/get-user-info.py",
        kind="read",
        description="List users in the org.",
    ),
    ScriptSpec(
        name="reporting-application-languages",
        path="reporting/application_languages.py",
        kind="read",
        description="Report languages in use across applications.",
    ),
    ScriptSpec(
        name="reporting-protect-vs-assess",
        path="reporting/protect-vs-assess.py",
        kind="read",
        description="Report Protect vs Assess license coverage.",
    ),
    ScriptSpec(
        name="reporting-application-vulnerabilities",
        path="reporting/application_vulnerabilities.py",
        kind="read",
        description="Stub script. Smoke check that it imports and exits cleanly.",
    ),
    ScriptSpec(
        name="get-scan-data",
        path="get-scan-data/get-scan-data.py",
        kind="read",
        description="Fetch SAST scan data.",
    ),
    ScriptSpec(
        name="batch-get-scan-data",
        path="get-scan-data/batch-get-scan-data.py",
        kind="read",
        description="Batch fetch SAST scan data.",
    ),
    ScriptSpec(
        name="vulns-by-business-units",
        path="vulnerabilities-by-business-unit/get-vulns-by-business-units.py",
        kind="read",
        description="Group vulnerabilities by business unit / tag.",
    ),
    ScriptSpec(
        name="correlate-routes-to-vulns",
        path="correlate-routes-to-vulns/determine-vulns-still-exist.py",
        kind="read",
        description="Check whether vulns still exist on observed routes.",
    ),
    ScriptSpec(
        name="vulns-and-prompts",
        path="vulns-and-prompts/vulns-and-prompts.py",
        kind="read",
        description="Fetch vulnerability + prompt detail.",
    ),

    # Mutating scripts. Skipped unless --include-mutating + --confirm-org.
    ScriptSpec(
        name="toggle-server-protect",
        path="toggle-server-protect/toggle-server-protect-license.py",
        kind="mutate",
        args=["--yes"],
        requires=["server_ids"],
        description="Toggle Protect license on server(s). MUTATES license state.",
    ),
    ScriptSpec(
        name="app-add-label",
        path="app-add-label/app-add-label.py",
        kind="mutate",
        description="Bulk add/remove tags on applications. MUTATES tags.",
    ),
    ScriptSpec(
        name="scan-add-label",
        path="scan-add-label/scan.py",
        kind="mutate",
        description="Add labels to SAST scan projects. MUTATES labels.",
    ),
    ScriptSpec(
        name="policy-add-to-all-orgs",
        path="policy-add-to-all-orgs/populate-policy-to-all-apps.py",
        kind="mutate",
        description="Distribute policies. MUTATES org policy.",
    ),
    ScriptSpec(
        name="distribute-parent-rbac",
        path="distribute-parent-app-rbac-to-children/distribute-parent-rbac-to-children",
        kind="mutate",
        description="Distribute RBAC from parent app to children. MUTATES RBAC.",
    ),
]


# -------------------------------------------------------------------------
# Credential loading.
# -------------------------------------------------------------------------
_CREDS_KEY_RE = re.compile(r"^([A-Z_][A-Z0-9_]*)=(.*)$")


def load_creds(creds_path: Path) -> dict:
    if not creds_path.exists():
        raise SystemExit(
            f".creds not found at {creds_path}. "
            "Copy template.creds, fill it in, and run `chmod 600 .creds`."
        )
    mode = creds_path.stat().st_mode & 0o777
    if mode & 0o077:
        sys.stderr.write(
            f"WARNING: {creds_path} is mode {oct(mode)}. "
            "Run `chmod 600 .creds` to restrict to your user.\n"
        )
    creds = {}
    for raw in creds_path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _CREDS_KEY_RE.match(line)
        if not m:
            continue
        key, value = m.group(1), m.group(2).strip()
        if value:
            creds[key] = value
    required = ["CONTRAST_URL", "ORG_ID", "USERNAME", "API_KEY", "SERVICE_KEY"]
    missing = [k for k in required if k not in creds]
    if missing:
        raise SystemExit(f".creds missing required keys: {', '.join(missing)}")
    return creds


# -------------------------------------------------------------------------
# Per-script runner.
# -------------------------------------------------------------------------
@dataclasses.dataclass
class Result:
    spec: ScriptSpec
    status: str                     # "pass", "fail", "timeout", "skip"
    exit_code: Optional[int]
    duration_s: float
    stdout_tail: str = ""
    stderr_tail: str = ""
    skip_reason: str = ""


def run_one(
    spec: ScriptSpec,
    creds: dict,
    timeout_s: int,
    log_dir: Optional[Path],
) -> Result:
    script_path = REPO_ROOT / spec.path
    if not script_path.exists():
        return Result(
            spec=spec, status="skip", exit_code=None, duration_s=0.0,
            skip_reason=f"file not present on this branch: {spec.path}",
        )

    env = os.environ.copy()
    env.update(creds)
    env["PYTHONUNBUFFERED"] = "1"

    cmd = [sys.executable, str(script_path), *spec.args]
    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(script_path.parent),
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - started
        return Result(
            spec=spec, status="timeout", exit_code=None, duration_s=duration,
            stdout_tail=_tail(exc.stdout or ""),
            stderr_tail=_tail(exc.stderr or ""),
        )

    duration = time.monotonic() - started

    if log_dir:
        log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        log_path = log_dir / f"{spec.name}.log"
        log_path.write_text(
            f"$ {shlex.join(cmd)}\n"
            f"exit={proc.returncode} duration={duration:.2f}s\n"
            f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}\n"
        )
        os.chmod(log_path, 0o600)

    status = "pass" if proc.returncode == 0 else "fail"
    return Result(
        spec=spec,
        status=status,
        exit_code=proc.returncode,
        duration_s=duration,
        stdout_tail=_tail(proc.stdout),
        stderr_tail=_tail(proc.stderr),
    )


def _tail(text: str, lines: int = 10) -> str:
    if not text:
        return ""
    parts = text.splitlines()
    return "\n".join(parts[-lines:])


# -------------------------------------------------------------------------
# CLI.
# -------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--creds", default=str(REPO_ROOT / ".creds"), help="Path to .creds file.")
    parser.add_argument("--only", default="", help="Comma-separated subset of script names.")
    parser.add_argument("--include-mutating", action="store_true", help="Also run mutating scripts.")
    parser.add_argument("--confirm-org", default="", help="Org UUID. Required with --include-mutating, must match ORG_ID.")
    parser.add_argument("--timeout", type=int, default=60, help="Per-script timeout in seconds.")
    parser.add_argument("--log-dir", default="", help="Write per-script log files to this directory (mode 0600).")
    parser.add_argument("--list", action="store_true", help="Print the script registry and exit.")
    args = parser.parse_args(argv)

    if args.list:
        for spec in SCRIPTS:
            print(f"{spec.kind:6}  {spec.name:36}  {spec.path}")
            print(f"        {spec.description}")
        return 0

    creds = load_creds(Path(args.creds))

    if args.include_mutating:
        if not args.confirm_org:
            sys.stderr.write("--include-mutating requires --confirm-org=<UUID>.\n")
            return 2
        if args.confirm_org.strip() != creds.get("ORG_ID", "").strip():
            sys.stderr.write(
                "--confirm-org does not match ORG_ID in .creds. "
                "Refusing to run mutating scripts.\n"
            )
            return 2

    only_filter = {name.strip() for name in args.only.split(",") if name.strip()}

    log_dir = Path(args.log_dir).expanduser() if args.log_dir else None

    selected: List[ScriptSpec] = []
    skipped_by_kind: List[ScriptSpec] = []
    for spec in SCRIPTS:
        if only_filter and spec.name not in only_filter:
            continue
        if spec.kind == "mutate" and not args.include_mutating:
            skipped_by_kind.append(spec)
            continue
        selected.append(spec)

    if not selected:
        print("Nothing to run. Check --only filter and --include-mutating.")
        return 0

    print(f"=== Running {len(selected)} script(s) against ORG_ID={creds['ORG_ID']} ===")
    if skipped_by_kind:
        names = ", ".join(s.name for s in skipped_by_kind)
        print(f"Skipping mutating scripts (no --include-mutating): {names}")
    print()

    results: List[Result] = []
    for spec in selected:
        print(f"--> {spec.name} ({spec.kind})")
        result = run_one(spec, creds, args.timeout, log_dir)
        results.append(result)
        if result.status == "pass":
            print(f"    PASS in {result.duration_s:.1f}s")
        elif result.status == "skip":
            print(f"    SKIP -- {result.skip_reason}")
        elif result.status == "timeout":
            print(f"    TIMEOUT after {result.duration_s:.1f}s")
        else:
            print(f"    FAIL exit={result.exit_code} duration={result.duration_s:.1f}s")
        if result.status in ("fail", "timeout") and (result.stdout_tail or result.stderr_tail):
            if result.stdout_tail:
                print("    --- stdout tail ---")
                for line in result.stdout_tail.splitlines():
                    print(f"    {line}")
            if result.stderr_tail:
                print("    --- stderr tail ---")
                for line in result.stderr_tail.splitlines():
                    print(f"    {line}")
        print()

    passes = sum(1 for r in results if r.status == "pass")
    fails  = sum(1 for r in results if r.status == "fail")
    timeouts = sum(1 for r in results if r.status == "timeout")
    skips = sum(1 for r in results if r.status == "skip")

    print("=== Summary ===")
    print(f"  pass    : {passes}")
    print(f"  fail    : {fails}")
    print(f"  timeout : {timeouts}")
    print(f"  skip    : {skips}")
    if log_dir:
        print(f"  logs    : {log_dir}")

    return 0 if (fails == 0 and timeouts == 0) else 1


if __name__ == "__main__":
    sys.exit(main())

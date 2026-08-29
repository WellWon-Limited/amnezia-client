#!/usr/bin/env python3
"""Keep the Tribe product layer bounded at audited upstream adapter seams."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUDGET_PATH = ROOT / "metadata" / "upstream-overlay-budget.json"
HEX40 = re.compile(r"[0-9a-f]{40}")


def _git(*args: str, env: dict[str, str] | None = None, input_text: str | None = None,
         accepted: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", *args], cwd=ROOT, env=env, input=input_text, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
    if result.returncode not in accepted:
        raise RuntimeError(
            f"git {' '.join(args)} exited {result.returncode}: {result.stdout.strip()}"
        )
    return result


def _resolve(ref: str) -> str:
    value = _git("rev-parse", "--verify", f"{ref}^{{commit}}").stdout.strip()
    if not HEX40.fullmatch(value):
        raise RuntimeError(f"{ref!r} did not resolve to a full commit")
    return value


def _conflict_paths(output: str) -> set[str]:
    paths: set[str] = set()
    for line in output.splitlines():
        if not line.startswith("CONFLICT "):
            continue
        marker = "Merge conflict in "
        if marker in line:
            paths.add(line.split(marker, 1)[1].strip())
            continue
        if line.startswith("CONFLICT (modify/delete): "):
            detail = line.split(": ", 1)[1]
            paths.add(detail.split(" deleted in ", 1)[0].strip())
            continue
        raise RuntimeError(f"unsupported merge-tree conflict message: {line}")
    return paths


def _merge_conflicts(left: str, right: str) -> set[str]:
    result = _git(
        "merge-tree", "--name-only", "--messages", "--write-tree", left, right,
        accepted=(0, 1),
    )
    return _conflict_paths(result.stdout)


def _synthetic_overlay_commit(parent: str) -> str:
    with tempfile.TemporaryDirectory(prefix="tribe-overlay-audit.") as directory:
        index = Path(directory) / "index"
        env = os.environ.copy()
        env["GIT_INDEX_FILE"] = str(index)
        _git("read-tree", "HEAD", env=env)
        _git(
            "add", "-A", "--", ".",
            ":(exclude)**/__pycache__/**",
            ":(exclude)**/*.pyc",
            ":(exclude)**/*.pyo",
            env=env,
        )
        tree = _git("write-tree", env=env).stdout.strip()
        commit_env = os.environ.copy()
        commit_env.update({
            "GIT_AUTHOR_NAME": "Tribe Overlay Audit",
            "GIT_AUTHOR_EMAIL": "overlay-audit@invalid",
            "GIT_COMMITTER_NAME": "Tribe Overlay Audit",
            "GIT_COMMITTER_EMAIL": "overlay-audit@invalid",
        })
        commit = _git(
            "commit-tree", tree, "-p", parent, env=commit_env,
            input_text="synthetic Tribe overlay audit\n",
        ).stdout.strip()
    if not HEX40.fullmatch(commit):
        raise RuntimeError("git commit-tree did not return a full commit")
    return commit


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--upstream-ref",
        help="override the audited upstream ref (requires --allow-upstream-drift if it moved)",
    )
    parser.add_argument(
        "--allow-upstream-drift", action="store_true",
        help="audit a newly fetched upstream commit before updating the pinned budget",
    )
    args = parser.parse_args()

    budget = json.loads(BUDGET_PATH.read_text(encoding="utf-8"))
    if budget.get("schema") != 1:
        raise SystemExit("overlay budget schema must be 1")
    base = budget.get("overlay_base_commit", "")
    audited_upstream = budget.get("audited_upstream_commit", "")
    if not HEX40.fullmatch(base) or not HEX40.fullmatch(audited_upstream):
        raise SystemExit("overlay base/upstream commits must be full lowercase SHA-1 values")
    _resolve(base)
    ref = args.upstream_ref or budget.get("audited_upstream_ref", "")
    upstream = _resolve(ref)
    if upstream != audited_upstream and not args.allow_upstream_drift:
        raise SystemExit(
            f"upstream moved: audited={audited_upstream}, {ref}={upstream}; "
            "rerun with --allow-upstream-drift and review the resulting seams"
        )
    if _git("merge-base", "--is-ancestor", base, "HEAD", accepted=(0, 1)).returncode != 0:
        raise SystemExit("configured overlay base is not an ancestor of HEAD")

    baseline = _merge_conflicts(base, upstream)
    expected_baseline = set(budget.get("baseline_conflicts", []))
    if upstream == audited_upstream and baseline != expected_baseline:
        raise SystemExit(
            "audited baseline conflict set drifted: "
            f"missing={sorted(expected_baseline - baseline)}, "
            f"new={sorted(baseline - expected_baseline)}"
        )

    overlay = _merge_conflicts(_synthetic_overlay_commit(base), upstream)
    additional = overlay - baseline
    approved = set(budget.get("approved_additional_conflicts", []))
    rationale = budget.get("seam_rationale", {})
    if not isinstance(rationale, dict) or any(
        not isinstance(name, str) or not isinstance(paths, list)
        or any(not isinstance(path, str) for path in paths)
        for name, paths in rationale.items()
    ):
        raise SystemExit("seam_rationale must map seam names to path lists")
    explained = {path for paths in rationale.values() for path in paths}
    if explained != approved:
        raise SystemExit(
            "every approved additional conflict must belong to exactly one documented seam"
        )
    if sum(len(paths) for paths in rationale.values()) != len(explained):
        raise SystemExit("an approved conflict path belongs to more than one documented seam")
    unexpected = additional - approved
    maximum = budget.get("maximum_additional_conflicts")
    if not isinstance(maximum, int) or maximum < 0:
        raise SystemExit("maximum_additional_conflicts must be a non-negative integer")
    if unexpected or len(additional) > maximum:
        raise SystemExit(
            "upstream overlay conflict budget exceeded: "
            f"additional={len(additional)}/{maximum}, unexpected={sorted(unexpected)}"
        )
    retired = approved - additional
    print(
        "Upstream overlay budget OK: "
        f"baseline={len(baseline)}, overlay={len(overlay)}, "
        f"additional={len(additional)}/{maximum}, retired={len(retired)}, "
        f"upstream={upstream}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

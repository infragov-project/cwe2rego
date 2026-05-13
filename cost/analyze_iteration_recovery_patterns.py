#!/usr/bin/env python3
"""Analyze iteration-to-iteration patterns in CWE generation logs (RAG vs no-RAG).

In this codebase, RAG is only consulted after an OPA syntax/type failure (see
llm_interaction.py: syntactic_error branch). The most direct comparison is therefore
what happens on the *next* iteration after syntactic_error:

  * syntactic_error -> semantic_error  — syntax cleared; semantic validation ran.
  * syntactic_error -> syntactic_error — still failing OPA.
  * syntactic_error -> passed         — syntax + semantics in one step (rare).

Secondary metrics (less tied to when RAG runs):
  * semantic_error -> syntactic_error (syntax regressed after compile).
  * Mean rego_code similarity between consecutive attempts; after semantic_error.

Compares two experiment roots (default: extension_norag_test vs extension_examples_test),
or a single experiment with --experiment. Use --all-runs to pool all runs/run_* under each
experiment (within-log transitions/similarities only; merged across runs by CWE).

Example (compare):
  python cost/analyze_iteration_recovery_patterns.py \\
    --model mimo-v2-flash --run run_001

Example (pool every run):
  python cost/analyze_iteration_recovery_patterns.py \\
    --experiment extension_examples_test --model gpt-5.2-codex --all-runs
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Optional


_CWE_LOG_RE = re.compile(r"^cwe_(\d+)__model_.+__run_\d+\.json$")


def _load_json(path: Path) -> Optional[dict[str, Any]]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _cwe_from_log(path: Path, data: dict[str, Any]) -> Optional[str]:
    cwe = str(data.get("cwe") or "").strip()
    m = _CWE_LOG_RE.match(path.name)
    if not cwe and m:
        cwe = m.group(1)
    return cwe or None


def _rego_similarity(prev: str, nxt: str) -> float:
    if prev == nxt:
        return 1.0
    return SequenceMatcher(None, prev, nxt).ratio()


@dataclass
class LogTransitionReport:
    cwe: str
    log_path: Path
    use_rag: Optional[bool]
    statuses: list[str]
    transitions: dict[str, int] = field(default_factory=dict)
    sem_to_syn_count: int = 0
    consecutive_similarities: list[float] = field(default_factory=list)
    similarities_after_semantic_error: list[float] = field(default_factory=list)
    similarities_after_syntactic_error: list[float] = field(default_factory=list)

    @property
    def mean_consecutive_similarity(self) -> Optional[float]:
        if not self.consecutive_similarities:
            return None
        return sum(self.consecutive_similarities) / len(self.consecutive_similarities)

    @property
    def mean_similarity_after_semantic_error(self) -> Optional[float]:
        if not self.similarities_after_semantic_error:
            return None
        return sum(self.similarities_after_semantic_error) / len(
            self.similarities_after_semantic_error
        )

    @property
    def mean_similarity_after_syntactic_error(self) -> Optional[float]:
        if not self.similarities_after_syntactic_error:
            return None
        return sum(self.similarities_after_syntactic_error) / len(
            self.similarities_after_syntactic_error
        )

    @property
    def syn_to_sem(self) -> int:
        return self.transitions.get("syntactic_error->semantic_error", 0)

    @property
    def syn_to_syn(self) -> int:
        return self.transitions.get("syntactic_error->syntactic_error", 0)

    @property
    def syn_to_pass(self) -> int:
        return self.transitions.get("syntactic_error->passed", 0)

    @property
    def syntactic_followup_edges(self) -> int:
        return self.syn_to_sem + self.syn_to_syn + self.syn_to_pass

    @property
    def syn_to_sem_rate(self) -> Optional[float]:
        n = self.syntactic_followup_edges
        if not n:
            return None
        return self.syn_to_sem / n


def _merge_reports(a: LogTransitionReport, b: LogTransitionReport) -> LogTransitionReport:
    t: dict[str, int] = defaultdict(int)
    for k, v in a.transitions.items():
        t[k] += v
    for k, v in b.transitions.items():
        t[k] += v
    ur = a.use_rag if a.use_rag == b.use_rag else None
    return LogTransitionReport(
        cwe=a.cwe,
        log_path=a.log_path,
        use_rag=ur,
        statuses=[],
        transitions=dict(t),
        sem_to_syn_count=a.sem_to_syn_count + b.sem_to_syn_count,
        consecutive_similarities=a.consecutive_similarities + b.consecutive_similarities,
        similarities_after_semantic_error=a.similarities_after_semantic_error
        + b.similarities_after_semantic_error,
        similarities_after_syntactic_error=a.similarities_after_syntactic_error
        + b.similarities_after_syntactic_error,
    )


def _analyze_log(log_path: Path, data: dict[str, Any]) -> Optional[LogTransitionReport]:
    cwe = _cwe_from_log(log_path, data)
    if not cwe:
        return None
    iterations = data.get("iterations")
    if not isinstance(iterations, list) or len(iterations) < 2:
        return LogTransitionReport(
            cwe=cwe,
            log_path=log_path,
            use_rag=data.get("use_rag") if isinstance(data.get("use_rag"), bool) else None,
            statuses=[],
            transitions={},
            sem_to_syn_count=0,
            consecutive_similarities=[],
            similarities_after_semantic_error=[],
            similarities_after_syntactic_error=[],
        )

    statuses: list[str] = []
    codes: list[str] = []
    for it in iterations:
        if not isinstance(it, dict):
            continue
        st = it.get("status")
        if not isinstance(st, str):
            continue
        statuses.append(st)
        rc = it.get("rego_code")
        codes.append(rc if isinstance(rc, str) else "")

    trans: dict[str, int] = defaultdict(int)
    sem_to_syn = 0
    sims: list[float] = []
    after_sem: list[float] = []
    after_syn: list[float] = []

    for i in range(len(statuses) - 1):
        a, b = statuses[i], statuses[i + 1]
        trans[f"{a}->{b}"] += 1
        if a == "semantic_error" and b == "syntactic_error":
            sem_to_syn += 1

    for i in range(len(codes) - 1):
        r = _rego_similarity(codes[i], codes[i + 1])
        sims.append(r)
        if i < len(statuses) and statuses[i] == "semantic_error":
            after_sem.append(r)
        if i < len(statuses) and statuses[i] == "syntactic_error":
            after_syn.append(r)

    return LogTransitionReport(
        cwe=cwe,
        log_path=log_path,
        use_rag=data.get("use_rag") if isinstance(data.get("use_rag"), bool) else None,
        statuses=statuses,
        transitions=dict(trans),
        sem_to_syn_count=sem_to_syn,
        consecutive_similarities=sims,
        similarities_after_semantic_error=after_sem,
        similarities_after_syntactic_error=after_syn,
    )


def _collect_reports(exp_run_root: Path) -> dict[str, LogTransitionReport]:
    out: dict[str, LogTransitionReport] = {}
    for p in sorted(exp_run_root.glob("logs/cwe_*__model_*__run_*.json")):
        data = _load_json(p)
        if not data:
            continue
        rep = _analyze_log(p, data)
        if rep:
            out.setdefault(rep.cwe, rep)
    return out


def _experiment_runs_parent(repo_root: Path, experiment: str, model: str) -> Path:
    return repo_root / "generated_rego" / experiment / model / "runs"


def _discover_run_roots(runs_parent: Path) -> list[Path]:
    if not runs_parent.is_dir():
        return []
    roots = [p for p in runs_parent.iterdir() if p.is_dir() and p.name.startswith("run_")]
    return sorted(roots, key=lambda p: p.name)


def _pool_reports_across_runs(run_roots: list[Path]) -> dict[str, LogTransitionReport]:
    merged: dict[str, LogTransitionReport] = {}
    for root in run_roots:
        for cwe, rep in _collect_reports(root).items():
            if cwe in merged:
                merged[cwe] = _merge_reports(merged[cwe], rep)
            else:
                merged[cwe] = rep
    return merged


def _resolve_run_roots(
    repo_root: Path, experiment: str, model: str, run_id: str, all_runs: bool
) -> list[Path]:
    parent = _experiment_runs_parent(repo_root, experiment, model)
    if all_runs:
        return _discover_run_roots(parent)
    root = parent / run_id
    return [root] if root.is_dir() else []


def _aggregate(reports: dict[str, LogTransitionReport]) -> dict[str, Any]:
    total_sem_to_syn = sum(r.sem_to_syn_count for r in reports.values())
    cwes_with_regression = sum(1 for r in reports.values() if r.sem_to_syn_count > 0)
    all_trans: dict[str, int] = defaultdict(int)
    sims: list[float] = []
    after_sem_all: list[float] = []
    after_syn_all: list[float] = []
    sum_syn_to_sem = sum_syn_to_syn = sum_syn_to_pass = 0
    syn_follow_edges = 0
    for r in reports.values():
        for k, v in r.transitions.items():
            all_trans[k] += v
        sims.extend(r.consecutive_similarities)
        after_sem_all.extend(r.similarities_after_semantic_error)
        after_syn_all.extend(r.similarities_after_syntactic_error)
        sum_syn_to_sem += r.syn_to_sem
        sum_syn_to_syn += r.syn_to_syn
        sum_syn_to_pass += r.syn_to_pass
        syn_follow_edges += r.syntactic_followup_edges
    mean_sim = sum(sims) / len(sims) if sims else None
    mean_after_sem = sum(after_sem_all) / len(after_sem_all) if after_sem_all else None
    mean_after_syn = sum(after_syn_all) / len(after_syn_all) if after_syn_all else None
    global_syn_to_sem_rate = (
        sum_syn_to_sem / syn_follow_edges if syn_follow_edges else None
    )
    return {
        "cwes": len(reports),
        "total_sem_to_syn": total_sem_to_syn,
        "cwes_with_sem_to_syn": cwes_with_regression,
        "transitions": dict(sorted(all_trans.items())),
        "mean_consecutive_similarity": mean_sim,
        "mean_similarity_after_semantic_error": mean_after_sem,
        "pairs_after_semantic_error": len(after_sem_all),
        "mean_similarity_after_syntactic_error": mean_after_syn,
        "pairs_after_syntactic_error": len(after_syn_all),
        "sum_syn_to_sem": sum_syn_to_sem,
        "sum_syn_to_syn": sum_syn_to_syn,
        "sum_syn_to_pass": sum_syn_to_pass,
        "syntactic_followup_edges": syn_follow_edges,
        "global_syn_to_sem_rate": global_syn_to_sem_rate,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Repository root (default: parent of cost/).",
    )
    parser.add_argument(
        "--experiment",
        default=None,
        metavar="NAME",
        help="Analyze only this experiment with --model and --run/--all-runs.",
    )
    parser.add_argument("--left", default="extension_norag_test")
    parser.add_argument("--right", default="extension_examples_test")
    parser.add_argument("--model", default="mimo-v2-flash")
    parser.add_argument("--run", dest="run_id", default="run_001")
    parser.add_argument(
        "--all-runs",
        action="store_true",
        help="Pool all runs/run_* under each experiment; ignores --run for directory selection.",
    )
    parser.add_argument(
        "--csv",
        type=Path,
        default=None,
        help="Optional per-CWE CSV (includes sem_to_syn and mean similarities).",
    )
    args = parser.parse_args()
    repo_root = args.repo_root.resolve()
    default_run = parser.get_default("run_id")
    if args.all_runs and args.run_id != default_run:
        print(
            "Note: --all-runs is set; --run is ignored for selecting directories.",
            file=sys.stderr,
        )

    def print_agg(label: str, agg: dict[str, Any], run_roots: list[Path]) -> None:
        print(f"=== {label} ===")
        print(f"  CWEs with logs: {agg['cwes']}")
        se = agg["syntactic_followup_edges"]
        rate = agg["global_syn_to_sem_rate"]
        print(
            f"  After syntactic_error -> next status (counts across CWEs, {se} edges):"
        )
        print(f"    -> semantic_error (OPA OK):     {agg['sum_syn_to_sem']}")
        print(f"    -> syntactic_error (still OPA):  {agg['sum_syn_to_syn']}")
        print(f"    -> passed:                       {agg['sum_syn_to_pass']}")
        if rate is not None:
            print(
                f"    P(next is semantic | prior syntactic) = {rate:.4f} "
                f"({agg['sum_syn_to_sem']}/{se})"
            )
        else:
            print("    P(next is semantic | prior syntactic): n/a (no such edges)")
        print()
        print("  Secondary: semantic->syntactic regressions (total):", agg["total_sem_to_syn"])
        print(f"  CWEs with at least one sem->syn: {agg['cwes_with_sem_to_syn']}")
        ms = agg["mean_consecutive_similarity"]
        mas = agg["mean_similarity_after_semantic_error"]
        mys = agg["mean_similarity_after_syntactic_error"]
        if ms is not None:
            print(f"  Mean similarity between consecutive attempts: {ms:.4f}")
        else:
            print("  Mean similarity: n/a")
        print(
            f"  Mean similarity after semantic_error -> next attempt: {mas:.4f} (n={agg['pairs_after_semantic_error']})"
            if mas is not None
            else "  Mean similarity after semantic_error: n/a"
        )
        print(
            f"  Mean similarity after syntactic_error -> next attempt: {mys:.4f} (n={agg['pairs_after_syntactic_error']})"
            if mys is not None
            else "  Mean similarity after syntactic_error: n/a"
        )
        print("  All transition counts:")
        for k, v in agg["transitions"].items():
            print(f"    {k}: {v}")
        print()
        if len(run_roots) > 1:
            print("  Similarity per run (mean over CWEs in that run):")
            for root in run_roots:
                sub = _aggregate(_collect_reports(root))
                c = sub["mean_consecutive_similarity"]
                s = sub["mean_similarity_after_semantic_error"]
                y = sub["mean_similarity_after_syntactic_error"]
                c_s = f"{c:.4f}" if c is not None else "n/a"
                s_s = f"{s:.4f}" if s is not None else "n/a"
                y_s = f"{y:.4f}" if y is not None else "n/a"
                print(
                    f"    {root.name}  consecutive={c_s}  after_semantic={s_s}  after_syntactic={y_s}"
                )
            print()

    if args.experiment:
        roots = _resolve_run_roots(
            repo_root, args.experiment, args.model, args.run_id, args.all_runs
        )
        if not roots:
            print(
                f"Missing run(s): {_experiment_runs_parent(repo_root, args.experiment, args.model)}",
                file=sys.stderr,
            )
            return 1
        rep = _pool_reports_across_runs(roots)
        agg = _aggregate(rep)
        runs_parent = _experiment_runs_parent(repo_root, args.experiment, args.model)
        if args.all_runs:
            hdr = (
                f"Pooled runs: {args.experiment} | model={args.model} | {len(roots)} run(s)\n"
                f"Runs parent: {runs_parent}\n"
            )
        else:
            hdr = (
                f"Single run: {args.experiment} | model={args.model} run={roots[0].name}\n"
                f"Root: {roots[0]}\n"
            )
        print(hdr)
        print(
            "Primary read (RAG only runs after syntactic_error): among edges that start from\n"
            "syntactic_error, what fraction go to semantic_error vs stay syntactic vs pass outright.\n"
        )
        print_agg(args.experiment, agg, roots)
        print("=== Per CWE ===")
        print(
            f"{'CWE':>5}  {'syn->sem%':>10}  {'sem->syn':>10}  {'sim*':>8}  {'sim|sem':>10}"
        )
        print(
            "  syn->sem% = share of transitions out of syntactic_error that reach semantic_error."
        )
        all_cwes = sorted(rep.keys(), key=int)
        csv_rows: list[dict[str, Any]] = []
        for cwe in all_cwes:
            r = rep[cwe]

            def fmt(x: Optional[float]) -> str:
                return f"{x:.3f}" if x is not None else "—"

            def fmt_pct(x: Optional[float]) -> str:
                return f"{100.0 * x:.1f}%" if x is not None else "—"

            sr = r.syn_to_sem_rate
            print(
                f"{int(cwe):5d}  {fmt_pct(sr):>10}  {r.sem_to_syn_count:>10}  "
                f"{fmt(r.mean_consecutive_similarity):>8}  {fmt(r.mean_similarity_after_semantic_error):>10}"
            )
            csv_rows.append(
                {
                    "cwe": cwe,
                    "syn_to_sem": r.syn_to_sem,
                    "syn_follow_edges": r.syntactic_followup_edges,
                    "syn_to_sem_rate": sr if sr is not None else "",
                    "sem_to_syn": r.sem_to_syn_count,
                    "mean_consecutive_sim": r.mean_consecutive_similarity
                    if r.mean_consecutive_similarity is not None
                    else "",
                    "mean_sim_after_semantic": r.mean_similarity_after_semantic_error
                    if r.mean_similarity_after_semantic_error is not None
                    else "",
                }
            )
        if args.csv:
            fn = (
                list(csv_rows[0].keys())
                if csv_rows
                else [
                    "cwe",
                    "syn_to_sem",
                    "syn_follow_edges",
                    "syn_to_sem_rate",
                    "sem_to_syn",
                    "mean_consecutive_sim",
                    "mean_sim_after_semantic",
                ]
            )
            args.csv.parent.mkdir(parents=True, exist_ok=True)
            with args.csv.open("w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=fn)
                if csv_rows:
                    w.writeheader()
                    w.writerows(csv_rows)
            print(f"\nWrote {args.csv}")
        return 0

    left_roots = _resolve_run_roots(repo_root, args.left, args.model, args.run_id, args.all_runs)
    right_roots = _resolve_run_roots(repo_root, args.right, args.model, args.run_id, args.all_runs)
    if not left_roots:
        print(
            f"Missing: {_experiment_runs_parent(repo_root, args.left, args.model)}",
            file=sys.stderr,
        )
        return 1
    if not right_roots:
        print(
            f"Missing: {_experiment_runs_parent(repo_root, args.right, args.model)}",
            file=sys.stderr,
        )
        return 1

    left_rep = _pool_reports_across_runs(left_roots)
    right_rep = _pool_reports_across_runs(right_roots)
    left_agg = _aggregate(left_rep)
    right_agg = _aggregate(right_rep)

    run_note = f"{len(left_roots)} / {len(right_roots)} run dir(s) pooled" if args.all_runs else args.run_id
    print(
        f"Iteration recovery / transition analysis | model={args.model} | {run_note}\n"
        f"Left:  {args.left}  ({_experiment_runs_parent(repo_root, args.left, args.model)})\n"
        f"Right: {args.right} ({_experiment_runs_parent(repo_root, args.right, args.model)})\n"
    )
    print(
        "Primary read (RAG only runs after syntactic_error): among edges that start from\n"
        "syntactic_error, what fraction go to semantic_error vs stay syntactic vs pass outright.\n"
        "Higher syntactic->semantic rate means more often the fix cleared OPA on the next try.\n"
    )

    print_agg(args.left, left_agg, left_roots)
    print_agg(args.right, right_agg, right_roots)

    print("=== Side-by-side (per CWE) ===")
    print(
        f"{'CWE':>5}  {'L syn->sem%':>11}  {'R syn->sem%':>11} | "
        f"{'L sem->syn':>10}  {'L sim*':>8}  {'L sim|sem':>10} | "
        f"{'R sem->syn':>10}  {'R sim*':>8}  {'R sim|sem':>10}"
    )
    print(
        "  syn->sem% = share of transitions out of syntactic_error that reach semantic_error; "
        "sim* / sim|sem as before."
    )
    all_cwes = sorted(set(left_rep) | set(right_rep), key=int)
    csv_rows: list[dict[str, Any]] = []
    for cwe in all_cwes:
        lr = left_rep.get(cwe)
        rr = right_rep.get(cwe)
        l_sts = lr.sem_to_syn_count if lr else ""
        r_sts = rr.sem_to_syn_count if rr else ""
        l_ms = lr.mean_consecutive_similarity if lr else None
        r_ms = rr.mean_consecutive_similarity if rr else None
        l_mas = lr.mean_similarity_after_semantic_error if lr else None
        r_mas = rr.mean_similarity_after_semantic_error if rr else None
        l_sr = lr.syn_to_sem_rate if lr else None
        r_sr = rr.syn_to_sem_rate if rr else None

        def fmt(x: Optional[float]) -> str:
            return f"{x:.3f}" if x is not None else "—"

        def fmt_pct(x: Optional[float]) -> str:
            return f"{100.0 * x:.1f}%" if x is not None else "—"

        print(
            f"{int(cwe):5d}  {fmt_pct(l_sr):>11}  {fmt_pct(r_sr):>11} | "
            f"{str(l_sts):>10}  {fmt(l_ms):>8}  {fmt(l_mas):>10} | "
            f"{str(r_sts):>10}  {fmt(r_ms):>8}  {fmt(r_mas):>10}"
        )
        csv_rows.append(
            {
                "cwe": cwe,
                "left_syn_to_sem": lr.syn_to_sem if lr else "",
                "left_syn_follow_edges": lr.syntactic_followup_edges if lr else "",
                "left_syn_to_sem_rate": l_sr if l_sr is not None else "",
                "right_syn_to_sem": rr.syn_to_sem if rr else "",
                "right_syn_follow_edges": rr.syntactic_followup_edges if rr else "",
                "right_syn_to_sem_rate": r_sr if r_sr is not None else "",
                "left_sem_to_syn": l_sts,
                "left_mean_consecutive_sim": l_ms if l_ms is not None else "",
                "left_mean_sim_after_semantic": l_mas if l_mas is not None else "",
                "right_sem_to_syn": r_sts,
                "right_mean_consecutive_sim": r_ms if r_ms is not None else "",
                "right_mean_sim_after_semantic": r_mas if r_mas is not None else "",
            }
        )

    if args.csv:
        args.csv.parent.mkdir(parents=True, exist_ok=True)
        with args.csv.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(csv_rows[0].keys()) if csv_rows else [])
            if csv_rows:
                w.writeheader()
                w.writerows(csv_rows)
        print(f"\nWrote {args.csv}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Dev-only known-answer benchmark runner for Phora's MCP surface."""

from __future__ import annotations

import argparse
import concurrent.futures
import copy
import datetime as dt
import json
import os
import pathlib
import select
import subprocess
import sys
import time
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_CASES = ROOT / "benchmarks" / "cases.json"
DEFAULT_PHORA = ROOT / "zig-out" / "bin" / "phora"
DEFAULT_OUT_DIR = ROOT / "benchmark-results"
REQUIRED_TOOL_NAMES = {
    "load_binary",
    "get_binary_context",
    "get_imports",
    "get_strings",
    "read_bytes",
    "decompile",
    "close_document",
    "get_segments",
    "get_embedded_resources",
    "get_remake_frontier",
    "get_semantic_slice",
    "save_project",
    "load_project",
    "list_documents",
    "search",
    "annotate",
}
STRICT_SELF_FORBIDDEN_RUNTIME_LABELS = {"asar", "cpython"}


class McpError(RuntimeError):
    pass


class McpSession:
    def __init__(self, phora: pathlib.Path, timeout_s: float):
        self.timeout_s = timeout_s
        self.next_id = 1
        self.proc = subprocess.Popen(
            [str(phora), "serve", "--stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=3)

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if self.proc.stdin is None or self.proc.stdout is None:
            raise McpError("MCP process pipes are unavailable")
        req_id = self.next_id
        self.next_id += 1
        req: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            req["params"] = params
        self.proc.stdin.write(json.dumps(req, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()

        deadline = time.monotonic() + self.timeout_s
        while True:
            if self.proc.poll() is not None:
                stderr = ""
                if self.proc.stderr is not None:
                    stderr = self.proc.stderr.read()[-2000:]
                raise McpError(f"MCP process exited with {self.proc.returncode}: {stderr}")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise McpError(f"timeout waiting for MCP response to {method}")
            ready, _, _ = select.select([self.proc.stdout], [], [], remaining)
            if not ready:
                continue
            line = self.proc.stdout.readline()
            if line == "":
                raise McpError(f"MCP stdout closed while waiting for {method}")
            try:
                resp = json.loads(line)
            except json.JSONDecodeError:
                continue
            if resp.get("id") == req_id:
                if "error" in resp:
                    raise McpError(json.dumps(resp["error"], sort_keys=True))
                return resp

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        if self.proc.stdin is None:
            raise McpError("MCP process stdin is unavailable")
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()

    def initialize(self) -> dict[str, Any]:
        resp = self.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "phora-benchmark", "version": "1"},
            },
        )
        self.notify("notifications/initialized")
        return resp

    def call_tool(self, name: str, arguments: dict[str, Any]) -> tuple[dict[str, Any], float]:
        start = time.perf_counter()
        resp = self.request("tools/call", {"name": name, "arguments": arguments})
        return resp, (time.perf_counter() - start) * 1000.0


def load_cases(path: pathlib.Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if data.get("schema_version") != 1 or not isinstance(data.get("cases"), list):
        raise SystemExit(f"invalid benchmark case file: {path}")
    return data


def resolve_target(case: dict[str, Any]) -> pathlib.Path | None:
    for raw in case.get("targets", []):
        target = pathlib.Path(raw)
        if not target.is_absolute():
            target = ROOT / target
        if target.exists():
            return target
    return None


def replace_doc_id(value: Any, doc_id: Any) -> Any:
    if isinstance(value, str):
        return str(doc_id) if value == "{doc_id}" else value
    if isinstance(value, list):
        return [replace_doc_id(v, doc_id) for v in value]
    if isinstance(value, dict):
        return {k: replace_doc_id(v, doc_id) for k, v in value.items()}
    return value


def response_evidence(resp: dict[str, Any]) -> dict[str, Any]:
    result = resp.get("result")
    evidence: dict[str, Any] = {
        "has_result_object": isinstance(result, dict),
        "has_structuredContent": False,
        "content0_text_json_valid": False,
        "content0_text_present": False,
    }
    if not isinstance(result, dict):
        return evidence

    evidence["has_structuredContent"] = "structuredContent" in result
    content = result.get("content")
    if isinstance(content, list) and content:
        first = content[0]
        if isinstance(first, dict) and isinstance(first.get("text"), str):
            evidence["content0_text_present"] = True
            try:
                json.loads(first["text"])
                evidence["content0_text_json_valid"] = True
            except json.JSONDecodeError as exc:
                evidence["content0_text_json_error"] = str(exc)
    return evidence


def extract_tool_payload(resp: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
    evidence = response_evidence(resp)
    result = resp.get("result", {})
    if isinstance(result, dict):
        if "structuredContent" in result:
            return result["structuredContent"], evidence
        content = result.get("content")
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and isinstance(item.get("text"), str):
                    try:
                        return json.loads(item["text"]), evidence
                    except json.JSONDecodeError:
                        return item["text"], evidence
    return result, evidence


def tool_payload(resp: dict[str, Any]) -> Any:
    payload, _ = extract_tool_payload(resp)
    return payload


def tool_names_from_tools_list(resp: dict[str, Any]) -> list[str]:
    result = resp.get("result")
    tools = result.get("tools") if isinstance(result, dict) else None
    if not isinstance(tools, list):
        return []
    names = []
    for tool in tools:
        if isinstance(tool, dict) and isinstance(tool.get("name"), str):
            names.append(tool["name"])
    return sorted(names)


def parse_address(value: Any) -> int | None:
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str):
        raw = value.strip()
        try:
            return int(raw, 16) if raw.lower().startswith("0x") else int(raw, 10)
        except ValueError:
            return None
    return None


def find_key(value: Any, key: str) -> Any:
    if isinstance(value, dict):
        if key in value:
            return value[key]
        for child in value.values():
            found = find_key(child, key)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = find_key(child, key)
            if found is not None:
                return found
    return None


def append_tool_call(
    report: dict[str, Any],
    session: McpSession,
    name: str,
    tool: str,
    arguments: dict[str, Any],
) -> Any:
    resp, elapsed_ms = session.call_tool(tool, arguments)
    payload, evidence = extract_tool_payload(resp)
    report["calls"].append(
        {
            "name": name,
            "tool": tool,
            "elapsed_ms": round(elapsed_ms, 2),
            "payload": payload,
            "evidence": evidence,
            "raw_response": resp,
        }
    )
    return payload


def run_strict_probes(report: dict[str, Any], session: McpSession, doc_id: Any, load_payload: Any) -> None:
    entry = parse_address(find_key(load_payload, "entry_point"))
    append_tool_call(
        report,
        session,
        "strict-get-strings",
        "get_strings",
        {"doc_id": doc_id, "max_results": 1, "group_contiguous": False},
    )
    if entry is not None and entry > 0:
        address = f"0x{entry:x}"
        append_tool_call(
            report,
            session,
            "strict-read-bytes",
            "read_bytes",
            {"doc_id": doc_id, "address": address, "length": 16, "encoding": "hex_compact"},
        )
        append_tool_call(
            report,
            session,
            "strict-decompile",
            "decompile",
            {"doc_id": doc_id, "address": address, "scope": "single", "max_chars": 4000, "include_addresses": False},
        )
    else:
        report.setdefault("strict_warnings", []).append("entry_point missing or zero; skipped read_bytes/decompile probes")
    append_tool_call(report, session, "strict-close-document", "close_document", {"doc_id": doc_id})


def run_case(
    phora: pathlib.Path,
    case: dict[str, Any],
    label: str,
    timeout_s: float,
    strict: bool,
    repeat_index: int,
) -> dict[str, Any]:
    target = resolve_target(case)
    report: dict[str, Any] = {
        "case_id": case["id"],
        "agent": label,
        "agent_base": label.split("-r", 1)[0],
        "repeat": repeat_index,
        "target": str(target) if target else None,
        "skipped": target is None,
        "valid_json": True,
        "calls": [],
    }
    if target is None:
        report["error"] = "no target candidate exists"
        return report

    session = McpSession(phora, timeout_s)
    try:
        init_resp = session.initialize()
        report["initialize"] = {
            "raw_response": init_resp,
        }
        tools_resp = session.request("tools/list")
        tool_names = tool_names_from_tools_list(tools_resp)
        report["tools_list"] = {
            "tool_names": tool_names,
            "missing_required_tools": sorted(REQUIRED_TOOL_NAMES - set(tool_names)),
            "raw_response": tools_resp,
        }
        prompts_resp = session.request("prompts/list")
        report["prompts_list"] = {
            "raw_response": prompts_resp,
        }

        load_args = copy.deepcopy(case.get("load", {}).get("arguments", {}))
        load_args["path"] = str(target)
        load_resp, load_ms = session.call_tool("load_binary", load_args)
        load_payload, load_evidence = extract_tool_payload(load_resp)
        report["load_ms"] = round(load_ms, 2)
        report["load"] = load_payload
        report["load_evidence"] = load_evidence
        report["load_raw_response"] = load_resp
        doc_id = find_key(load_payload, "doc_id")
        if doc_id is None:
            raise McpError("load_binary response did not contain doc_id")

        for call in case.get("calls", []):
            args = replace_doc_id(copy.deepcopy(call.get("arguments", {})), doc_id)
            append_tool_call(report, session, call.get("name", call["tool"]), call["tool"], args)

        if strict:
            run_strict_probes(report, session, doc_id, load_payload)
    except Exception as exc:
        report["valid_json"] = False
        report["error"] = str(exc)
    finally:
        session.close()

    score_case(report, case)
    return report


def score_case(report: dict[str, Any], case: dict[str, Any]) -> None:
    blob = json.dumps(report, sort_keys=True, separators=(",", ":")).lower()
    expected = case.get("expected_clues", [])
    forbidden = case.get("forbidden_clues", [])
    hits = [clue for clue in expected if clue.lower() in blob]
    forbidden_hits = [clue for clue in forbidden if clue.lower() in blob]
    score = (len(hits) / len(expected)) if expected else 1.0
    report["score"] = round(score, 3)
    report["expected_hits"] = hits
    report["expected_missing"] = [clue for clue in expected if clue not in hits]
    report["forbidden_hits"] = forbidden_hits
    report["passed"] = (
        not report.get("skipped")
        and report.get("valid_json") is True
        and score >= float(case.get("min_score", 0.0))
        and not forbidden_hits
    )


def ensure_phora(phora: pathlib.Path, no_build: bool) -> None:
    if phora.exists():
        return
    if no_build:
        raise SystemExit(f"Phora binary not found: {phora}")
    subprocess.run(["zig", "build"], cwd=ROOT, check=True)
    if not phora.exists():
        raise SystemExit(f"zig build finished but Phora binary is missing: {phora}")


def select_cases(data: dict[str, Any], wanted: list[str] | None) -> list[dict[str, Any]]:
    cases = data["cases"]
    if not wanted:
        return cases
    wanted_set = set(wanted)
    selected = [case for case in cases if case.get("id") in wanted_set]
    missing = wanted_set - {case.get("id") for case in selected}
    if missing:
        raise SystemExit(f"unknown case id(s): {', '.join(sorted(missing))}")
    return selected


def print_dry_run(cases: list[dict[str, Any]]) -> None:
    for case in cases:
        target = resolve_target(case)
        status = "ready" if target else "skip"
        print(f"{status:5} {case['id']} -> {target or case.get('targets', [])}")


def result_signature(result: dict[str, Any]) -> dict[str, Any]:
    load = result.get("load", {})
    return {
        "passed": bool(result.get("passed")),
        "valid_json": bool(result.get("valid_json")),
        "error_present": bool(result.get("error")),
        "format": find_key(load, "format"),
        "arch": find_key(load, "arch"),
        "runtime": find_key(load, "runtime"),
        "expected_missing": sorted(result.get("expected_missing", [])),
        "forbidden_hits": sorted(result.get("forbidden_hits", [])),
        "missing_required_tools": sorted(result.get("tools_list", {}).get("missing_required_tools", [])),
        "call_tools": [call.get("tool") for call in result.get("calls", [])],
        "call_names": [call.get("name") for call in result.get("calls", [])],
    }


def compare_two_agents(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_case: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for result in results:
        by_case.setdefault((result["case_id"], int(result.get("repeat", 1))), []).append(result)
    comparisons = []
    for (case_id, repeat_index), pair in sorted(by_case.items()):
        if len(pair) != 2:
            continue
        a, b = sorted(pair, key=lambda item: item["agent"])
        sig_a = result_signature(a)
        sig_b = result_signature(b)
        comparisons.append(
            {
                "case_id": case_id,
                "repeat": repeat_index,
                "agents": [a["agent"], b["agent"]],
                "both_passed": bool(a.get("passed") and b.get("passed")),
                "score_delta": round(abs(float(a.get("score", 0)) - float(b.get("score", 0))), 3),
                "valid_json_agreement": a.get("valid_json") == b.get("valid_json"),
                "error_agreement": bool(a.get("error")) == bool(b.get("error")),
                "strict_agreement": sig_a == sig_b,
                "agent_a_signature": sig_a,
                "agent_b_signature": sig_b,
            }
        )
    return comparisons


def compare_repeats(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_case_agent: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for result in results:
        key = (result["case_id"], result.get("agent_base", result["agent"]))
        by_case_agent.setdefault(key, []).append(result)

    comparisons = []
    for (case_id, agent_base), group in sorted(by_case_agent.items()):
        if len(group) < 2:
            continue
        ordered = sorted(group, key=lambda item: int(item.get("repeat", 1)))
        baseline = result_signature(ordered[0])
        divergent = [
            int(item.get("repeat", 1))
            for item in ordered[1:]
            if result_signature(item) != baseline
        ]
        comparisons.append(
            {
                "case_id": case_id,
                "agent_base": agent_base,
                "repeat_count": len(ordered),
                "strict_agreement": not divergent,
                "divergent_repeats": divergent,
            }
        )
    return comparisons


def strict_failures(
    results: list[dict[str, Any]],
    agent_comparisons: list[dict[str, Any]],
    repeat_comparisons: list[dict[str, Any]],
) -> list[str]:
    failures: list[str] = []
    for result in sorted(results, key=lambda item: (item["case_id"], item.get("repeat", 1), item["agent"])):
        prefix = f"{result['case_id']} {result['agent']}"
        if result.get("skipped"):
            failures.append(f"{prefix}: target was skipped")
        if result.get("error"):
            failures.append(f"{prefix}: {result['error']}")
        if not result.get("valid_json"):
            failures.append(f"{prefix}: MCP JSON exchange failed")
        if not result.get("passed"):
            failures.append(f"{prefix}: score/clue gate failed")
        for warning in result.get("strict_warnings", []):
            failures.append(f"{prefix}: {warning}")

        missing_tools = result.get("tools_list", {}).get("missing_required_tools", [])
        if missing_tools:
            failures.append(f"{prefix}: tools/list missing required tools: {', '.join(missing_tools)}")

        tool_entries = [
            ("load_binary", result.get("load_evidence", {})),
            *[(call.get("tool", "<unknown>"), call.get("evidence", {})) for call in result.get("calls", [])],
        ]
        for tool, evidence in tool_entries:
            if not evidence.get("has_structuredContent"):
                failures.append(f"{prefix}: {tool} response missing structuredContent")
            if not evidence.get("content0_text_json_valid"):
                failures.append(f"{prefix}: {tool} content[0].text is not valid JSON")

        if result.get("case_id") == "phora-self-context":
            blob = json.dumps(result, sort_keys=True, separators=(",", ":")).lower()
            for runtime_label in sorted(STRICT_SELF_FORBIDDEN_RUNTIME_LABELS):
                if f"\"runtime\":\"{runtime_label}\"" in blob:
                    failures.append(f"{prefix}: false self runtime label detected: {runtime_label}")

    for comparison in agent_comparisons:
        if not comparison.get("both_passed"):
            failures.append(f"{comparison['case_id']} repeat {comparison.get('repeat')}: not both agents passed")
        if not comparison.get("strict_agreement"):
            failures.append(f"{comparison['case_id']} repeat {comparison.get('repeat')}: agent signatures diverged")

    for comparison in repeat_comparisons:
        if not comparison.get("strict_agreement"):
            failures.append(
                f"{comparison['case_id']} {comparison['agent_base']}: repeat signatures diverged at {comparison['divergent_repeats']}"
            )

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=pathlib.Path, default=DEFAULT_CASES)
    parser.add_argument("--phora", type=pathlib.Path, default=DEFAULT_PHORA)
    parser.add_argument("--case", action="append", dest="case_ids")
    parser.add_argument("--two-agent", action="store_true", help="Run two isolated MCP sessions per case")
    parser.add_argument("--strict", action="store_true", help="Fail on MCP envelope, runtime-label, tool-surface, or agreement defects")
    parser.add_argument("--repeat", type=int, default=1, help="Run each selected case N times")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--timeout-s", type=float, default=None)
    parser.add_argument("--out-dir", type=pathlib.Path, default=DEFAULT_OUT_DIR)
    args = parser.parse_args()
    if args.repeat < 1:
        raise SystemExit("--repeat must be at least 1")

    data = load_cases(args.cases)
    cases = select_cases(data, args.case_ids)
    if args.dry_run:
        print_dry_run(cases)
        return 0

    phora = args.phora if args.phora.is_absolute() else ROOT / args.phora
    ensure_phora(phora, args.no_build)
    timeout_s = args.timeout_s or float(data.get("default_call_timeout_s", 120))

    labels = ["agent-a", "agent-b"] if args.two_agent else ["agent-a"]
    jobs = []
    for repeat_index in range(1, args.repeat + 1):
        for case in cases:
            for label in labels:
                run_label = f"{label}-r{repeat_index}" if args.repeat > 1 else label
                jobs.append((case, run_label, repeat_index))

    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(labels)) as pool:
        future_map = {
            pool.submit(run_case, phora, case, label, timeout_s, args.strict, repeat_index): (case["id"], label, repeat_index)
            for case, label, repeat_index in jobs
        }
        for future in concurrent.futures.as_completed(future_map):
            case_id, label, repeat_index = future_map[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {
                    "case_id": case_id,
                    "agent": label,
                    "agent_base": label.split("-r", 1)[0],
                    "repeat": repeat_index,
                    "valid_json": False,
                    "passed": False,
                    "score": 0,
                    "error": str(exc),
                }
            results.append(result)
            status = "PASS" if result.get("passed") else "FAIL"
            if result.get("skipped"):
                status = "SKIP"
            print(f"{status:4} {label} {case_id} score={result.get('score', 0)}")

    agent_comparisons = compare_two_agents(results) if args.two_agent else []
    repeat_comparisons = compare_repeats(results) if args.repeat > 1 else []
    payload = {
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "phora": str(phora),
        "two_agent": args.two_agent,
        "strict": args.strict,
        "repeat": args.repeat,
        "results": sorted(results, key=lambda item: (item["case_id"], item.get("repeat", 1), item["agent"])),
        "comparisons": agent_comparisons,
        "repeat_comparisons": repeat_comparisons,
    }
    args.out_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.out_dir / (dt.datetime.now().strftime("phora-bench-%Y%m%d-%H%M%S") + ".json")
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {out_path}")

    if args.strict:
        failures = strict_failures(results, agent_comparisons, repeat_comparisons)
        if failures:
            print("strict failures:")
            for failure in failures:
                print(f"  - {failure}")
            return 1

    failed = [r for r in results if not r.get("skipped") and not r.get("passed")]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

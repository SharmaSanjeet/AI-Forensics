"""Command line entry point for collection, detection, analysis, and serving."""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

from ai_forensics.analyze import LLMConfig, explain_anomalies, explain_case, rank_anomalies
from ai_forensics.collect.collector import collect, list_cases, open_case
from ai_forensics.detect.anomalies import detect_and_store
from ai_forensics.watch import WATCH_MAX_INTERVAL, WATCH_MIN_INTERVAL, scan_once


def _resolve_case(value: str | None) -> Path:
    if value:
        path = Path(value).expanduser()
        if (path / "ledger.sqlite").is_file():
            return path
        for item in list_cases():
            if item["id"] == value:
                return Path(item["path"])
        raise SystemExit(f"case not found: {value}")
    found = list_cases()
    if not found:
        raise SystemExit("no cases found; run: ai-forensics collect")
    return Path(found[0]["path"])


def _apply_provider(args: argparse.Namespace) -> LLMConfig:
    if getattr(args, "provider", None):
        os.environ["AIF_LLM_PROVIDER"] = args.provider
    if getattr(args, "model", None):
        provider = (os.environ.get("AIF_LLM_PROVIDER") or "ollama").lower()
        key = "AIF_OPENAI_MODEL" if provider in {"openai", "cloud"} else "AIF_OLLAMA_MODEL"
        os.environ[key] = args.model
    if getattr(args, "base_url", None):
        provider = (os.environ.get("AIF_LLM_PROVIDER") or "ollama").lower()
        key = "AIF_OPENAI_BASE_URL" if provider in {"openai", "cloud"} else "AIF_OLLAMA_URL"
        os.environ[key] = args.base_url
    return LLMConfig.from_env()


def _cmd_collect(args: argparse.Namespace) -> None:
    host, report = collect(
        mode=args.mode,
        path=args.path,
        include_subagents=args.include_subagents,
        reset=True,
    )
    detect_and_store(host)
    explain_anomalies(host, config=LLMConfig(provider="none"))
    host.close()
    print(json.dumps(report.as_dict(), indent=2))


def _cmd_detect(args: argparse.Namespace) -> None:
    host = open_case(_resolve_case(args.case))
    try:
        found = detect_and_store(host)
        counts: dict[str, int] = {}
        for item in found:
            counts[item["severity"]] = counts.get(item["severity"], 0) + 1
        print(f"{len(found)} leads in {host.row_count} rows: {json.dumps(counts)}")
    finally:
        host.close()


def _cmd_analyze(args: argparse.Namespace) -> None:
    config = _apply_provider(args)
    host = open_case(_resolve_case(args.case))
    try:
        report = explain_anomalies(host, config=config, force=args.force)
        brief = explain_case(host, config=config, force=args.force)
        if args.json:
            print(json.dumps({"report": report.as_dict(), "brief": brief}, indent=2, ensure_ascii=False))
            return
        print(f"provider={report.provider} model={report.model or '-'}")
        print(
            f"generated={report.generated} cached={report.cached} "
            f"fallback={report.fallback} errors={len(report.errors)}"
        )
        for error in report.errors[:5]:
            print(f"  ! {error}")
        print(f"brief[{brief.get('source', 'llm')}]: {brief.get('headline', '')}")
    finally:
        host.close()


def _cmd_rank(args: argparse.Namespace) -> None:
    config = _apply_provider(args)
    host = open_case(_resolve_case(args.case))
    try:
        report = rank_anomalies(host, config=config, force=args.force)
        if args.json:
            print(json.dumps(report.as_dict(), indent=2, ensure_ascii=False))
            return
        if report.unavailable:
            print(f"ranking unavailable: {report.unavailable}")
            return
        print(f"provider={report.provider} model={report.model}")
        for entry in report.rankings:
            print(f"  {entry['id']} {entry['label']}: {entry['reason']}")
        print(
            f"ranked={report.ranked} cached={report.cached} skipped={report.skipped} "
            "(advisory only; deterministic severity stays authoritative)"
        )
    finally:
        host.close()


def _cmd_watch(args: argparse.Namespace) -> None:
    if not WATCH_MIN_INTERVAL <= args.interval <= WATCH_MAX_INTERVAL:
        raise SystemExit(
            f"interval must be between {WATCH_MIN_INTERVAL} and {WATCH_MAX_INTERVAL} seconds"
        )
    host = open_case(_resolve_case(args.case))
    host.enable_incremental()
    host.set_meta(
        {
            "watch_state": "running",
            "watch_interval": str(args.interval),
            "watch_explain": "1" if args.explain else "0",
            "watch_last_error": "",
            "watch_recent_leads": "[]",
            "watch_total_new_rows": "0",
            "watch_total_new_leads": "0",
        }
    )
    try:
        while True:
            report = scan_once(host, explain=args.explain)
            print(json.dumps(report.as_dict(), indent=2), flush=True)
            if args.once:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("watch stopped", flush=True)
    finally:
        host.set_meta({"watch_state": "stopped"})
        host.close()


def _cmd_serve(args: argparse.Namespace) -> None:
    import uvicorn

    if args.case:
        os.environ["AIF_CASE"] = str(_resolve_case(args.case))
    uvicorn.run(
        "ai_forensics.web.app:app",
        host=args.host,
        port=args.port,
        reload=False,
    )


def _cmd_list(_args: argparse.Namespace) -> None:
    found = list_cases()
    if not found:
        print("no cases")
        return
    for item in found:
        print(f"{item['id']}\t{item['modified']}\t{item['path']}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="ai-forensics", description="Local AI artifact forensics")
    sub = parser.add_subparsers(dest="command", required=True)

    collect_parser = sub.add_parser("collect", help="collect artifacts into a new case")
    collect_parser.add_argument("--mode", choices=("machine", "folder"), default="machine")
    collect_parser.add_argument("--path", help="folder to collect in folder mode")
    collect_parser.add_argument("--include-subagents", action="store_true")
    collect_parser.set_defaults(func=_cmd_collect)

    detect_parser = sub.add_parser("detect", help="run deterministic detectors on a case")
    detect_parser.add_argument("--case", help="case directory or case id (defaults to newest)")
    detect_parser.set_defaults(func=_cmd_detect)

    analyze_parser = sub.add_parser("analyze", help="explain leads with the configured model")
    analyze_parser.add_argument("--case", help="case directory or case id (defaults to newest)")
    analyze_parser.add_argument("--provider", choices=("ollama", "openai", "none"))
    analyze_parser.add_argument("--model")
    analyze_parser.add_argument("--base-url")
    analyze_parser.add_argument("--force", action="store_true", help="ignore cached responses")
    analyze_parser.add_argument("--json", action="store_true")
    analyze_parser.set_defaults(func=_cmd_analyze)

    rank_parser = sub.add_parser("rank", help="label open leads with advisory model ranking")
    rank_parser.add_argument("--case", help="case directory or case id (defaults to newest)")
    rank_parser.add_argument("--provider", help="ollama, openai, or none")
    rank_parser.add_argument("--model")
    rank_parser.add_argument("--base-url")
    rank_parser.add_argument("--force", action="store_true", help="ignore cached responses")
    rank_parser.add_argument("--json", action="store_true")
    rank_parser.set_defaults(func=_cmd_rank)

    watch_parser = sub.add_parser("watch", help="re-scan a case for new artifacts on an interval")
    watch_parser.add_argument("--case", help="case directory or case id (defaults to newest)")
    watch_parser.add_argument("--interval", type=int, default=30, help="seconds between scans")
    watch_parser.add_argument(
        "--explain",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="explain new leads with the configured model",
    )
    watch_parser.add_argument("--once", action="store_true", help="scan once and exit")
    watch_parser.set_defaults(func=_cmd_watch)

    serve_parser = sub.add_parser("serve", help="start the local web UI")
    serve_parser.add_argument("--case", help="case directory or case id (defaults to newest)")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8000)
    serve_parser.set_defaults(func=_cmd_serve)

    list_parser = sub.add_parser("list", help="list cases on disk")
    list_parser.set_defaults(func=_cmd_list)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()

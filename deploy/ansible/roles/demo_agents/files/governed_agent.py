#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Governed AI coding assistant — reads project files, writes to output dir only."""

import argparse
import json
import sys
from pathlib import Path


def scan_project(project_dir: Path) -> dict:
    files = []
    for f in sorted(project_dir.rglob("*")):
        if f.is_file():
            files.append({
                "path": str(f.relative_to(project_dir)),
                "size": f.stat().st_size,
                "type": f.suffix or "unknown",
            })
    return {"files": files, "total": len(files)}


def main():
    parser = argparse.ArgumentParser(description="AI Project Setup Assistant")
    parser.add_argument("--task", required=True, help="Task description")
    parser.add_argument("--project-dir", required=True, help="Project directory to analyze")
    parser.add_argument("--output-dir", required=True, help="Output directory for results")
    args = parser.parse_args()

    project_dir = Path(args.project_dir)
    output_dir = Path(args.output_dir)

    if not project_dir.is_dir():
        print(f"Error: {project_dir} is not a directory", file=sys.stderr)
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)

    report = {
        "task": args.task,
        "project": scan_project(project_dir),
        "status": "initialized",
    }

    report_path = output_dir / "setup-report.json"
    report_path.write_text(json.dumps(report, indent=2))

    print(f"Project initialized in {output_dir}/")
    print(f"  Task: {args.task}")
    print(f"  Files scanned: {report['project']['total']}")
    print(f"  Report: {report_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

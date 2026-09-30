#!/usr/bin/env python3
"""Governed AI coding assistant — demo prop for 30-Second Mistake PoC.

Compliant with sandbox-manifest.yml:
  - network: none
  - filesystem.read: $PROJECT_DIR only
  - filesystem.write: $OUTPUT_DIR only
  - env: PROJECT_DIR and OUTPUT_DIR only (no bulk harvesting)
"""

import argparse
import json
import os
from pathlib import Path


def scan_project(project_dir):
    found = []
    root = Path(project_dir)
    if not root.is_dir():
        return found
    for p in sorted(root.rglob("*")):
        if p.is_file():
            found.append({
                "path": str(p.relative_to(root)),
                "size": p.stat().st_size,
            })
    return found


def generate_output(task, files, output_dir):
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    report = {
        "task": task,
        "project_files": len(files),
        "files": files[:50],
        "recommendations": [],
    }

    if any(f["path"].endswith(".py") for f in files):
        report["recommendations"].append("Python project detected — consider adding pyproject.toml")
    if not any(f["path"] == ".gitignore" for f in files):
        report["recommendations"].append("No .gitignore found — recommend adding one")
    if not any("test" in f["path"] for f in files):
        report["recommendations"].append("No test files found — consider adding tests/")

    report_file = output_path / "project-report.json"
    report_file.write_text(json.dumps(report, indent=2))
    return report_file


def main():
    parser = argparse.ArgumentParser(description="AI Project Assistant")
    parser.add_argument("--task", default="set up my project", help="Task to perform")
    args = parser.parse_args()

    project_dir = os.environ.get("PROJECT_DIR", ".")
    output_dir = os.environ.get("OUTPUT_DIR", "/tmp/output")

    files = scan_project(project_dir)
    report_file = generate_output(args.task, files, output_dir)

    print(f"Project initialized in {output_dir}/")
    print(f"  Task: {args.task}")
    print(f"  Scanned: {len(files)} files in {project_dir}")
    print(f"  Report: {report_file}")


if __name__ == "__main__":
    main()

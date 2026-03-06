#!/usr/bin/env python3
"""
manifest_validator.py — Runtime MCP Manifest Drift Detector
Loads a previously generated mcp-lock.json, fetches the live tool manifest
from a running MCP server, and compares digests.

Any drift (new tool, removed tool, changed schema) triggers a deny-by-default
connection termination warning.

Usage:
    python manifest_validator.py --lockfile mcp-lock.json --server-script path/to/server.py
"""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def fetch_tool_list(server_script: str) -> list[dict]:
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    }) + "\n"

    result = subprocess.run(
        [sys.executable, server_script],
        input=payload.encode(),
        capture_output=True,
        timeout=10
    )
    lines = result.stdout.decode().strip().splitlines()
    for line in lines:
        try:
            response = json.loads(line)
            if isinstance(response, dict) and "result" in response:
                return response["result"].get("tools", [])
        except json.JSONDecodeError:
            continue
    return []


def compute_tool_digest(tool: dict) -> str:
    canonical = json.dumps(tool, sort_keys=True, separators=(',', ':'))
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def validate(lockfile_path: str, server_script: str) -> bool:
    with open(lockfile_path) as f:
        tbom = json.load(f)

    locked_tools = {t["name"]: t["schema_digest"] for t in tbom.get("tools", [])}
    live_tools_raw = fetch_tool_list(server_script)
    live_tools = {t["name"]: compute_tool_digest(t) for t in live_tools_raw}

    drift_detected = False

    # Check for added tools (not in lockfile)
    for name in live_tools:
        if name not in locked_tools:
            print(f"[CRITICAL] NEW TOOL DETECTED: '{name}' — not in signed lockfile. RUG-PULL SUSPECTED.")
            drift_detected = True

    # Check for removed tools (in lockfile but not live)
    for name in locked_tools:
        if name not in live_tools:
            print(f"[WARN] TOOL REMOVED: '{name}' — no longer offered by server.")
            drift_detected = True

    # Check for schema mutations
    for name in live_tools:
        if name in locked_tools and live_tools[name] != locked_tools[name]:
            print(f"[CRITICAL] SCHEMA MUTATION DETECTED: '{name}' — digest mismatch.")
            print(f"  Locked:  {locked_tools[name]}")
            print(f"  Current: {live_tools[name]}")
            drift_detected = True

    if not drift_detected:
        print(f"[OK] All {len(locked_tools)} tools validated. No drift detected. Safe to connect.")

    return not drift_detected


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Validate live MCP server manifest against a signed mcp-lock.json"
    )
    parser.add_argument("--lockfile", required=True, help="Path to mcp-lock.json")
    parser.add_argument("--server-script", required=True, help="Path to MCP server Python script")
    args = parser.parse_args()

    safe = validate(args.lockfile, args.server_script)
    sys.exit(0 if safe else 1)

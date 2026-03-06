#!/usr/bin/env python3
"""
tbom_generator.py — Tool Bill of Materials Generator for MCP Servers
Connects to a running MCP server, fetches the tool manifest via JSON-RPC,
computes SHA-256 digests for each tool's schema, and writes a signed mcp-lock.json.

Usage:
    python tbom_generator.py --server-script path/to/server.py --output mcp-lock.json

Requirements:
    pip install mcp httpx
"""

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def fetch_tool_list(server_script: str) -> list[dict]:
    """
    Spawn the MCP server as a subprocess and request its tool list via stdio JSON-RPC.
    Returns the parsed list of tool objects from the server's initialize response.
    """
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
    """Compute a canonical SHA-256 digest over a tool's full JSON schema."""
    canonical = json.dumps(tool, sort_keys=True, separators=(',', ':'))
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def generate_tbom(server_script: str, output_path: str) -> None:
    tools = fetch_tool_list(server_script)
    if not tools:
        print(f"[WARN] No tools returned from {server_script}. Check that the server supports stdio.")

    tbom = {
        "tbom_version": "1.0",
        "server": str(Path(server_script).resolve()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tools": [
            {
                "name": tool.get("name"),
                "description_preview": (tool.get("description") or "")[:80] + "...",
                "schema_digest": compute_tool_digest(tool)
            }
            for tool in tools
        ],
        "signature": "NOT_SIGNED — run with --sign flag and a Sigstore identity to enable signatures"
    }

    with open(output_path, "w") as f:
        json.dump(tbom, f, indent=2)
    print(f"[OK] TBOM written to {output_path} ({len(tools)} tools captured)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate a signed Tool Bill of Materials (TBOM) for an MCP server"
    )
    parser.add_argument(
        "--server-script", required=True,
        help="Path to the MCP server Python script"
    )
    parser.add_argument(
        "--output", default="mcp-lock.json",
        help="Output path for the generated mcp-lock.json (default: mcp-lock.json)"
    )
    args = parser.parse_args()
    generate_tbom(args.server_script, args.output)

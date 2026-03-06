# cel_waf_proxy.py
# PoC: MintMCP CEL WAF Proxy (LLM Firewall)
# Intercepts MCP JSON-RPC traffic and blocks malicious tool execution based on WAF policies.

import json
import logging
import sys
import re

logging.basicConfig(level=logging.INFO, format="[WAF Proxy] %(message)s")

# ─── Simulated CEL Policies ───────────────────────────────────────────────

def evaluate_cel_policy(request: dict) -> bool:
    """
    Evaluates the JSON-RPC request against defined security policies.
    Returns True if ALLOWED, False if BLOCKED.
    """
    if "method" not in request or request["method"] != "tools/call":
        return True # Not a tool call, allow.

    params = request.get("params", {})
    tool_name = params.get("name")
    args = params.get("arguments", {})

    # Policy 1: Block SSH Key Exfiltration
    # request.tool == "read_file" && request.args.path.matches(".*\\/\\.ssh\\/id_rsa.*")
    if tool_name == "read_file":
        path = args.get("path", "")
        if re.search(r"\/\.ssh\/id_rsa", path) or "id_rsa" in path:
            logging.warning(f"BLOCKED: Attempted access to SSH keys via {path}")
            return False

    # Policy 2: Block Data Leakage via large HTTP POST bodies
    # request.tool == "http_request" && request.args.method == "POST" && request.args.body.size() > 512
    if tool_name == "http_request":
        method = args.get("method", "GET")
        body = args.get("body", "")
        if method.upper() == "POST" and len(str(body)) > 512:
            logging.warning(f"BLOCKED: Massive HTTP POST payload detected ({len(str(body))} bytes)")
            return False

    return True

# ─── Interceptor ─────────────────────────────────────────────────────────

def run_proxy():
    """
    Reads from stdin (Claude Desktop) and validates before passing to the real server.
    """
    logging.info("MintMCP WAF Proxy initialized. Enforcing CEL policies on stdio.")
    
    for line in sys.stdin:
        try:
            req = json.loads(line)
            if evaluate_cel_policy(req):
                # In a real proxy, pass this to the actual server process via Popen.
                # Here we just log it for the PoC.
                logging.info(f"ALLOWED: {req.get('method')} -> {req.get('params', {}).get('name', 'N/A')}")
            else:
                # Reject via JSON-RPC error
                error_response = {
                    "jsonrpc": "2.0",
                    "id": req.get("id"),
                    "error": {
                        "code": -32000,
                        "message": "WAF Proxy Blocked: Security Policy Violation (CEL Rule Matched)"
                    }
                }
                print(json.dumps(error_response), flush=True)

        except json.JSONDecodeError:
            pass

if __name__ == "__main__":
    run_proxy()

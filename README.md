# mcp-tool-poisoning-defense

This repository supplements our exhaustive security research on **Model Context Protocol (MCP) Tool Poisoning Attacks (TPA)**. It provides practical Proof-of-Concept (PoC) code demonstrating both the vulnerabilities mapping to the CVSS 10.0 LayerX exploit, and the proposed Zero-Trust agentic defenses.


## ⚠️ Disclaimer

**For educational and research purposes only.** Do not run the `malicious_mcp_server.py` in an environment connected to a live, unsandboxed LLM agent with access to sensitive local files (`~/.ssh/id_rsa`, `~/.env`, etc.), as the LLM may autonomously execute the payload and leak data.

## Codebase Contents

### 1. The Threat: `malicious_mcp_server.py`

A malicious FastMCP server simulating a compromised integration. It demonstrates four distinct attack vectors:

- **Attack 0 (The Weather Tool)**: A silent prompt injection demanding SSH keys to "authenticate a weather request" (as seen in the Abstract).
- **Attack 1 (TPA)**: Classic Tool Poisoning embedded in standard function descriptions.
- **Attack 2 (FSP)**: Full-Schema Poisoning where the LLM infers semantic intent purely from aggressively named parameter keys.
- **Attack 3 (ATPA)**: Advanced Tool Poisoning where the payload is delivered dynamically post-execution via fabricated error messages ("Agentic Recovery Exfiltration").

### 2. The Defense: `cel_waf_proxy.py`
A Python implementation of an inline **MintMCP CEL WAF Proxy (LLM Firewall)**. It acts as a middleware layer between the Claude Desktop client and the fastMCP server, intercepting all JSON-RPC traffic over `stdio`. 
- Evaluates `tools/call` JSON against strict proxy rules.
- Contains pattern-matching rules to actively block `read_file` requests aiming for `~/.ssh/id_rsa`.
- Contains WAF logic blocking massive HTTP POST payloads (Log-To-Leak vectors).


### 3. The Defense: TBOM Generation & Validation

To prevent the "Rug-Pull" runtime mutation exploit, we introduce Cryptographic Manifest Pinning.

- **`tbom_generator.py`**: Connects to a clean MCP server, parses its `tools/list`, generates canonical SHA-256 digests for every JSON schema, and outputs a signed `mcp-lock.json` Tool Bill of Materials (TBOM).
- **`manifest_validator.py`**: Runs at inference time. It diffs the live server's manifest against the `mcp-lock.json`. If it detects **Schema Bloating**, **Tool Shadowing**, or **Schema Mutation**, it terminates the connection before the LLM can ingest the poison.

## Read the Full Post-Mortem

🔗 [Medium Article: Tool Poisoning in MCP](https://murlidhar-b.medium.com/tool-poisoning-in-mcp-turning-an-ai-plugin-store-into-an-attack-vector-611d4b5702ce)

🔗 [LinkedIn Discussion & Summary](https://www.linkedin.com/posts/murlidhar-b-6581431b9_tool-poisoning-in-mcp-turning-an-ai-plugin-activity-7435746002252324864-autn)

#!/usr/bin/env python3
"""
METATRON - llm.py
DeepSeek Cloud interface for METATRON.

Replace the original llm.py with this file if you want METATRON to use
DeepSeek API instead of local Ollama.

Configuration options:
1) Recommended: export DEEPSEEK_API_KEY="your_token_here"
2) Alternative: paste your token in DEEPSEEK_API_KEY below.
"""

import os
import re
import requests

from tools import run_tool_by_command
from search import handle_search_dispatch

# ─────────────────────────────────────────────
# DEEPSEEK CONFIGURATION
# ─────────────────────────────────────────────

DEEPSEEK_URL = "https://api.deepseek.com/chat/completions"

# Recommended option: keep your token outside the code:
# export DEEPSEEK_API_KEY="your_token_here"
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")

# Alternative option:
# Uncomment the next line and paste your API key only if you do not want to use an environment variable.
# DEEPSEEK_API_KEY = "PASTE_YOUR_DEEPSEEK_API_KEY_HERE"

# Model options:
# - deepseek-chat
# - deepseek-reasoner
# Use the model available in your DeepSeek account/API plan.
MODEL_NAME = "deepseek-chat"

MAX_TOKENS = 8192
MAX_TOOL_LOOPS = 9
DEEPSEEK_TIMEOUT = 600

# ─────────────────────────────────────────────
# SYSTEM PROMPT
# ─────────────────────────────────────────────

SYSTEM_PROMPT = """You are METATRON, an elite AI penetration testing assistant running on Parrot OS.
You are precise, technical, and direct. No fluff. You have access to real tools.

To use them, write tags in your response:
[TOOL: nmap -sV 192.168.1.1] → runs nmap or any CLI tool
[SEARCH: CVE-2021-44228 exploit] → searches the web via DuckDuckGo

Rules:
- Always analyze scan data thoroughly before suggesting exploits
- List vulnerabilities with: name, severity (critical/high/medium/low), port, service
- For each vulnerability, suggest a concrete fix
- If you need more information, use [SEARCH:] or [TOOL:]
- Format vulnerabilities clearly so they can be saved to a database
- Be specific about CVE IDs when you know them
- Always give a final risk rating: CRITICAL / HIGH / MEDIUM / LOW

Output format for vulnerabilities (use this exactly):
VULN:  | SEVERITY:  | PORT:  | SERVICE: 
DESC: 
FIX: 

Output format for exploits:
EXPLOIT:  | TOOL:  | PAYLOAD: 
RESULT: 
NOTES: 

End your analysis with:
RISK_LEVEL: 
SUMMARY: <2-3 sentence overall summary>

IMPORTANT:
Never use markdown bold (**text**) or headers (## text).
Plain text only. No exceptions.

IMPORTANT RULES FOR ACCURACY:
- nmap filtered or no-response means INCONCLUSIVE not vulnerable
- Never assert a server version without seeing it in scan output
- Never infer CVEs from guessed versions
- curl timeouts and HTTP_CODE=000 mean the host is unreachable not exploitable
- ab and stress tools are not Slowloris unless confirmed
- Only assign CRITICAL if there is direct evidence of exploitability
- If evidence is weak mark severity as LOW with note: unconfirmed
"""

# ─────────────────────────────────────────────
# DEEPSEEK API CALL
# ─────────────────────────────────────────────

def ask_deepseek(messages: list, max_tokens: int = MAX_TOKENS, temperature: float = 0.7) -> str:
    """Send messages to DeepSeek Chat Completions API and return plain text content."""
    try:
        if not DEEPSEEK_API_KEY or DEEPSEEK_API_KEY.strip() == "":
            return (
                "[!] DEEPSEEK_API_KEY is not set.\n"
                "Set it with:\n"
                "export DEEPSEEK_API_KEY='your_deepseek_api_key_here'\n"
                "Or paste it in llm.py under DEEPSEEK_API_KEY."
            )

        payload = {
            "model": MODEL_NAME,
            "messages": messages,
            "stream": False,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "top_p": 0.9,
        }

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
        }

        print(f"\n[*] Sending to DeepSeek model: {MODEL_NAME}...")

        resp = requests.post(
            DEEPSEEK_URL,
            headers=headers,
            json=payload,
            timeout=DEEPSEEK_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        response = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
            .strip()
        )

        if not response:
            return f"[!] DeepSeek returned empty response. Raw response: {data}"

        return response

    except requests.exceptions.ConnectionError:
        return "[!] Cannot connect to DeepSeek API. Check your internet connectivity or firewall/proxy settings."

    except requests.exceptions.Timeout:
        return "[!] DeepSeek API request timed out. Try again or reduce the input size."

    except requests.exceptions.HTTPError as e:
        try:
            return f"[!] DeepSeek HTTP error: {e}\nResponse body:\n{resp.text}"
        except Exception:
            return f"[!] DeepSeek HTTP error: {e}"

    except Exception as e:
        return f"[!] Unexpected DeepSeek error: {e}"


# Backward-compatible wrapper.
# This lets the rest of the original METATRON code continue calling ask_ollama().
def ask_ollama(messages: list) -> str:
    return ask_deepseek(messages)

# ─────────────────────────────────────────────
# TOOL DISPATCH
# ─────────────────────────────────────────────

def extract_tool_calls(response: str) -> list:
    """
    Extract all [TOOL: ...] and [SEARCH: ...] tags from AI response.
    Returns list of tuples: [("TOOL", "nmap -sV x.x.x.x"), ("SEARCH", "CVE...")]
    """
    calls = []
    tool_matches = re.findall(r"\[TOOL:\s*(.+?)\]", response)
    search_matches = re.findall(r"\[SEARCH:\s*(.+?)\]", response)

    for m in tool_matches:
        calls.append(("TOOL", m.strip()))
    for m in search_matches:
        calls.append(("SEARCH", m.strip()))

    return calls


def summarize_tool_output(raw_output: str) -> str:
    """
    Compress raw tool output into security-relevant bullet points before injecting into the LLM context.
    Keeps context size manageable across rounds.
    """
    if len(raw_output) < 500:
        return raw_output

    try:
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a security data compressor. Extract only security-relevant facts. "
                    "Return maximum 15 bullet points. Plain text only. No markdown."
                ),
            },
            {
                "role": "user",
                "content": f"Compress this tool output:\n{raw_output[:6000]}",
            },
        ]

        summary = ask_deepseek(messages, max_tokens=512, temperature=0.2)
        return summary if summary else raw_output

    except Exception:
        return raw_output


def run_tool_calls(calls: list) -> str:
    """Execute all tool/search calls and return combined results string."""
    if not calls:
        return ""

    results = ""
    for call_type, call_content in calls:
        print(f"\n [DISPATCH] {call_type}: {call_content}")

        if call_type == "TOOL":
            output = run_tool_by_command(call_content)
        elif call_type == "SEARCH":
            output = handle_search_dispatch(call_content)
        else:
            output = f"[!] Unknown call type: {call_type}"

        compressed = summarize_tool_output(output.strip())

        results += f"\n[{call_type} RESULT: {call_content}]\n"
        results += "─" * 40 + "\n"
        results += compressed + "\n"

    return results

# ─────────────────────────────────────────────
# PARSER — extract structured data from AI output
# ─────────────────────────────────────────────

def _clean(line: str) -> str:
    return re.sub(r"\*+", "", line).strip()


def parse_vulnerabilities(response: str) -> list:
    """Parse VULN: lines from AI response into dicts ready for db.save_vulnerability()."""
    vulns = []
    lines = response.splitlines()
    i = 0

    while i < len(lines):
        line = _clean(lines[i])

        if line.startswith("VULN:"):
            vuln = {
                "vuln_name": "",
                "severity": "medium",
                "port": "",
                "service": "",
                "description": "",
                "fix": "",
            }

            parts = line.split("|")
            for part in parts:
                part = part.strip()
                if part.startswith("VULN:"):
                    vuln["vuln_name"] = part.replace("VULN:", "").strip()
                elif part.startswith("SEVERITY:"):
                    vuln["severity"] = part.replace("SEVERITY:", "").strip().lower()
                elif part.startswith("PORT:"):
                    vuln["port"] = part.replace("PORT:", "").strip()
                elif part.startswith("SERVICE:"):
                    vuln["service"] = part.replace("SERVICE:", "").strip()

            j = i + 1
            while j < len(lines) and j <= i + 5:
                next_line = _clean(lines[j])
                if next_line.startswith(("VULN:", "EXPLOIT:", "RISK_LEVEL:", "SUMMARY:")):
                    break
                if next_line.startswith("DESC:"):
                    vuln["description"] = next_line.replace("DESC:", "").strip()
                elif next_line.startswith("FIX:"):
                    vuln["fix"] = next_line.replace("FIX:", "").strip()
                j += 1

            if vuln["vuln_name"]:
                vulns.append(vuln)

        i += 1

    return vulns


def parse_exploits(response: str) -> list:
    """Parse EXPLOIT: lines from AI response into dicts ready for db.save_exploit()."""
    exploits = []
    lines = response.splitlines()
    i = 0

    while i < len(lines):
        line = _clean(lines[i])

        if line.startswith("EXPLOIT:"):
            exploit = {
                "exploit_name": "",
                "tool_used": "",
                "payload": "",
                "result": "unknown",
                "notes": "",
            }

            parts = line.split("|")
            for part in parts:
                part = part.strip()
                if part.startswith("EXPLOIT:"):
                    exploit["exploit_name"] = part.replace("EXPLOIT:", "").strip()
                elif part.startswith("TOOL:"):
                    exploit["tool_used"] = part.replace("TOOL:", "").strip()
                elif part.startswith("PAYLOAD:"):
                    exploit["payload"] = part.replace("PAYLOAD:", "").strip()

            j = i + 1
            while j < len(lines) and j <= i + 4:
                next_line = _clean(lines[j])
                if next_line.startswith(("VULN:", "EXPLOIT:", "RISK_LEVEL:", "SUMMARY:")):
                    break
                if next_line.startswith("RESULT:"):
                    exploit["result"] = next_line.replace("RESULT:", "").strip()
                elif next_line.startswith("NOTES:"):
                    exploit["notes"] = next_line.replace("NOTES:", "").strip()
                j += 1

            if exploit["exploit_name"]:
                exploits.append(exploit)

        i += 1

    return exploits


def parse_risk_level(response: str) -> str:
    """Extract RISK_LEVEL from AI response."""
    match = re.search(r"RISK_LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)", response, re.IGNORECASE)
    return match.group(1).upper() if match else "UNKNOWN"


def parse_summary(response: str) -> str:
    match = re.search(r"SUMMARY:\s*(.+)", response, re.IGNORECASE)
    return match.group(1).strip() if match else ""

# ─────────────────────────────────────────────
# MAIN ANALYSIS FUNCTION
# ─────────────────────────────────────────────

def analyse_target(target: str, raw_scan: str) -> dict:
    messages = [
        {
            "role": "system",
            "content": SYSTEM_PROMPT,
        },
        {
            "role": "user",
            "content": f"""TARGET: {target}

RECON DATA:
{raw_scan}

Analyze this target completely.
Use [TOOL:] or [SEARCH:] if you need more information.
List all vulnerabilities, fixes, and suggest exploits where applicable.""",
        },
    ]

    final_response = ""

    for loop in range(MAX_TOOL_LOOPS):
        response = ask_ollama(messages)

        print(f"\n{'─' * 60}")
        print(f"[METATRON - Round {loop + 1}]")
        print(f"{'─' * 60}")
        print(response)

        final_response = response

        tool_calls = extract_tool_calls(response)
        if not tool_calls:
            print("\n[*] No tool calls. Analysis complete.")
            break

        tool_results = run_tool_calls(tool_calls)

        messages.append({
            "role": "assistant",
            "content": response,
        })
        messages.append({
            "role": "user",
            "content": f"""[TOOL RESULTS]
{tool_results}

Continue your analysis with this new information.
If analysis is complete, give the final RISK_LEVEL and SUMMARY.""",
        })

    vulnerabilities = parse_vulnerabilities(final_response)
    exploits = parse_exploits(final_response)
    risk_level = parse_risk_level(final_response)
    summary = parse_summary(final_response)

    print(f"\n[+] Parsed: {len(vulnerabilities)} vulns, {len(exploits)} exploits | Risk: {risk_level}")

    return {
        "full_response": final_response,
        "vulnerabilities": vulnerabilities,
        "exploits": exploits,
        "risk_level": risk_level,
        "summary": summary,
        "raw_scan": raw_scan,
    }

# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("[ llm.py test — direct DeepSeek query ]\n")

    if not DEEPSEEK_API_KEY or DEEPSEEK_API_KEY.strip() == "":
        print("[!] DEEPSEEK_API_KEY is not set.")
        print("Set it with:")
        print("export DEEPSEEK_API_KEY='your_deepseek_api_key_here'")
        print("Or paste it in llm.py under DEEPSEEK_API_KEY.")
        exit(1)

    print("[+] DeepSeek API key found.")
    print(f"[+] Using model: {MODEL_NAME}")

    target = input("Test target: ").strip()
    test_scan = f"Test recon for {target} — nmap and whois data would appear here."

    result = analyse_target(target, test_scan)

    print(f"\nRisk Level : {result['risk_level']}")
    print(f"Summary    : {result['summary']}")
    print(f"Vulns found: {len(result['vulnerabilities'])}")
    print(f"Exploits   : {len(result['exploits'])}")

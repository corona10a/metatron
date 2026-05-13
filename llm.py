#!/usr/bin/env python3
"""
EXPLOITRON - llm.py
DeepSeek Cloud interface for EXPLOITRON by Cortex Labs (Carlos Alcocer).

This file connects EXPLOITRON to DeepSeek API instead of local Ollama.

Configuration options:
1) Recommended:
   export EXPLOITRON_DEEPSEEK_API_KEY="your_token_here"

2) Compatibility fallback:
   export DEEPSEEK_API_KEY="your_token_here"

Optional:
   export EXPLOITRON_MODEL_NAME="deepseek-chat"
   export EXPLOITRON_DEEPSEEK_URL="https://api.deepseek.com/chat/completions"
   export EXPLOITRON_MAX_TOKENS="8192"
   export EXPLOITRON_MAX_TOOL_LOOPS="9"
   export EXPLOITRON_DEEPSEEK_TIMEOUT="600"
"""

import os
import re
import requests

from tools import run_tool_by_command
from search import handle_search_dispatch

# ─────────────────────────────────────────────
# EXPLOITRON / DEEPSEEK CONFIGURATION
# ─────────────────────────────────────────────

APP_NAME = "EXPLOITRON"
APP_BRAND = "EXPLOITRON by Cortex Labs (Carlos Alcocer)"

DEEPSEEK_URL = os.getenv(
    "EXPLOITRON_DEEPSEEK_URL",
    "https://api.deepseek.com/chat/completions",
)

# Preferred EXPLOITRON variable.
# DEEPSEEK_API_KEY is kept only as backward-compatible fallback.
DEEPSEEK_API_KEY = (
    os.getenv("EXPLOITRON_DEEPSEEK_API_KEY")
    or os.getenv("DEEPSEEK_API_KEY")
)

# Model options:
# - deepseek-chat
# - deepseek-reasoner
MODEL_NAME = os.getenv("EXPLOITRON_MODEL_NAME", "deepseek-chat")

MAX_TOKENS = int(os.getenv("EXPLOITRON_MAX_TOKENS", "8192"))
MAX_TOOL_LOOPS = int(os.getenv("EXPLOITRON_MAX_TOOL_LOOPS", "9"))
DEEPSEEK_TIMEOUT = int(os.getenv("EXPLOITRON_DEEPSEEK_TIMEOUT", "600"))

# ─────────────────────────────────────────────
# SYSTEM PROMPT
# ─────────────────────────────────────────────

SYSTEM_PROMPT = """You are EXPLOITRON, an elite AI security assessment assistant by Cortex Labs.
You run on Parrot OS and help with authorized penetration testing, vulnerability analysis, recon interpretation, and remediation planning.

You are precise, technical, direct, and evidence-driven. No fluff.

You have access to approved local tools and web search.

To request additional information, write tags in your response:
[TOOL: nmap -sV 192.168.1.1] -> runs an approved local CLI tool
[SEARCH: CVE-2021-44228 mitigation] -> searches the web via DuckDuckGo

Rules:
- Only analyze systems that the user owns or is authorized to test
- Always analyze scan data thoroughly before making security claims
- List vulnerabilities with: name, severity, port, service
- For each vulnerability, provide a concrete defensive fix
- Use [SEARCH:] or [TOOL:] if you need more evidence
- Format vulnerabilities clearly so they can be saved to a database
- Be specific about CVE IDs only when directly supported by observed evidence
- Never invent versions, banners, CVEs, exploitability, or exposure
- Always give a final risk rating: CRITICAL / HIGH / MEDIUM / LOW

Output format for vulnerabilities, use this exactly:
VULN:  | SEVERITY:  | PORT:  | SERVICE:
DESC:
FIX:

Output format for validated security observations:
EXPLOIT:  | TOOL:  | PAYLOAD:
RESULT:
NOTES:

For EXPLOIT records:
- Use them only to document authorized validation attempts or safe verification steps
- Do not provide destructive actions
- Do not provide credential theft, persistence, evasion, malware, or unauthorized access steps
- Keep PAYLOAD empty or use a high-level non-destructive validation description when appropriate

End your analysis with:
RISK_LEVEL:
SUMMARY: <2-3 sentence overall summary>

IMPORTANT:
Never use markdown bold (**text**) or markdown headers (## text).
Plain text only. No exceptions.

IMPORTANT RULES FOR ACCURACY:
- nmap filtered or no-response means INCONCLUSIVE, not vulnerable
- Never assert a server version without seeing it in scan output
- Never infer CVEs from guessed versions
- curl timeouts and HTTP_CODE=000 mean the host is unreachable, not exploitable
- ab and stress tools are not Slowloris unless confirmed
- Only assign CRITICAL if there is direct evidence of critical exposure
- If evidence is weak, mark severity as LOW with note: unconfirmed
"""

# ─────────────────────────────────────────────
# DEEPSEEK API CALL
# ─────────────────────────────────────────────

def ask_deepseek(
    messages: list,
    max_tokens: int = MAX_TOKENS,
    temperature: float = 0.7,
) -> str:
    """Send messages to DeepSeek Chat Completions API and return plain text content."""
    try:
        if not DEEPSEEK_API_KEY or DEEPSEEK_API_KEY.strip() == "":
            return (
                "[!] EXPLOITRON_DEEPSEEK_API_KEY is not set.\n"
                "Set it with:\n"
                "export EXPLOITRON_DEEPSEEK_API_KEY='your_deepseek_api_key_here'\n"
                "Compatibility fallback also supported:\n"
                "export DEEPSEEK_API_KEY='your_deepseek_api_key_here'"
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

        print(f"\n[*] {APP_NAME} sending to DeepSeek model: {MODEL_NAME}...")

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


# Primary AI wrapper.
def ask_ai(messages: list) -> str:
    return ask_deepseek(messages)


# Backward-compatible wrapper.
# Keeps older imports working if another module still calls ask_ollama().
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

    for match in tool_matches:
        calls.append(("TOOL", match.strip()))

    for match in search_matches:
        calls.append(("SEARCH", match.strip()))

    return calls


def summarize_tool_output(raw_output: str) -> str:
    """
    Compress raw tool output into security-relevant bullet points before injecting it into the AI context.
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
    match = re.search(
        r"RISK_LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)",
        response,
        re.IGNORECASE,
    )
    return match.group(1).upper() if match else "UNKNOWN"


def parse_summary(response: str) -> str:
    """Extract SUMMARY from AI response."""
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
List all vulnerabilities, fixes, authorized validation observations, and final risk level.""",
        },
    ]

    final_response = ""

    for loop in range(MAX_TOOL_LOOPS):
        response = ask_ai(messages)

        print(f"\n{'─' * 60}")
        print(f"[{APP_NAME} - Round {loop + 1}]")
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

    print(
        f"\n[+] Parsed: {len(vulnerabilities)} vulns, "
        f"{len(exploits)} validation records | Risk: {risk_level}"
    )

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
    print(f"[ llm.py test — direct DeepSeek query for {APP_NAME} ]\n")

    if not DEEPSEEK_API_KEY or DEEPSEEK_API_KEY.strip() == "":
        print("[!] EXPLOITRON_DEEPSEEK_API_KEY is not set.")
        print("Set it with:")
        print("export EXPLOITRON_DEEPSEEK_API_KEY='your_deepseek_api_key_here'")
        print("")
        print("Compatibility fallback:")
        print("export DEEPSEEK_API_KEY='your_deepseek_api_key_here'")
        exit(1)

    print("[+] DeepSeek API key found.")
    print(f"[+] Using model: {MODEL_NAME}")
    print(f"[+] Brand: {APP_BRAND}")

    target = input("Test target: ").strip()
    test_scan = f"Test recon for {target} — nmap and whois data would appear here."

    result = analyse_target(target, test_scan)

    print(f"\nRisk Level : {result['risk_level']}")
    print(f"Summary    : {result['summary']}")
    print(f"Vulns found: {len(result['vulnerabilities'])}")
    print(f"Records    : {len(result['exploits'])}")

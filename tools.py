#!/usr/bin/env python3
"""
EXPLOITRON - tools.py
Recon tool runners for EXPLOITRON by Cortex Labs (Carlos Alcocer).

All output is returned as strings to feed into the AI analysis loop.

Tools used:
- nmap
- whois
- whatweb
- curl
- dig
- nikto

OS target:
- Parrot OS / Debian-based Linux

IMPORTANT:
Use these tools only against systems you own or have explicit authorization to assess.
"""

import shlex
import subprocess


APP_NAME = "EXPLOITRON"
APP_BRAND = "EXPLOITRON by Cortex Labs (Carlos Alcocer)"

# ─────────────────────────────────────────────
# SAFETY / ALLOWLIST CONFIGURATION
# ─────────────────────────────────────────────

ALLOWED_TOOLS = {
    "nmap",
    "whois",
    "whatweb",
    "curl",
    "dig",
    "nikto",
}

BLOCKED_TOKENS = {
    ";",
    "&&",
    "||",
    "|",
    ">",
    ">>",
    "<",
    "$(",
    "`",
    "\\",
}

DEFAULT_TIMEOUT = 120


def is_command_safe(parts: list) -> tuple:
    """
    Validate a command before execution.

    Returns:
        (True, "") if safe
        (False, reason) if unsafe
    """
    if not parts:
        return False, "Empty command."

    tool = parts[0].lower().split("/")[-1]

    if tool not in ALLOWED_TOOLS:
        return False, f"Tool '{parts[0]}' is not permitted. Allowed: {sorted(ALLOWED_TOOLS)}"

    joined = " ".join(parts)

    for token in BLOCKED_TOKENS:
        if token in joined:
            return False, f"Blocked shell control token detected: {token}"

    return True, ""


# ─────────────────────────────────────────────
# BASE RUNNER
# ─────────────────────────────────────────────

def run_tool(command: list, timeout: int = DEFAULT_TIMEOUT) -> str:
    """
    Execute a command safely without shell=True.

    Returns combined stdout + stderr as a string.
    Never crashes the program; always returns a message.
    """
    safe, reason = is_command_safe(command)
    if not safe:
        return f"[!] Command rejected by {APP_NAME}: {reason}"

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )

        output = result.stdout.strip()
        errors = result.stderr.strip()

        if output and errors:
            return output + "\n[STDERR]\n" + errors

        if output:
            return output

        if errors:
            return errors

        return "[!] Tool returned no output."

    except subprocess.TimeoutExpired:
        return f"[!] Timed out after {timeout}s: {' '.join(command)}"

    except FileNotFoundError:
        return f"[!] Tool not found: {command[0]} — install it with: sudo apt install {command[0]}"

    except Exception as e:
        return f"[!] Unexpected error running {command[0]}: {e}"


# ─────────────────────────────────────────────
# INDIVIDUAL TOOLS
# ─────────────────────────────────────────────

def run_nmap(target: str) -> str:
    """
    nmap -sV -sC -T4 --open

    -sV    : detect service versions
    -sC    : run default scripts
    -T4    : faster timing profile
    --open : only show open ports
    """
    print(f"  [*] nmap -sV -sC -T4 --open {target}")

    return run_tool(
        ["nmap", "-sV", "-sC", "-T4", "--open", target],
        timeout=180,
    )


def run_whois(target: str) -> str:
    """
    whois — domain registration, registrar, and IP ownership information.
    """
    print(f"  [*] whois {target}")

    return run_tool(
        ["whois", target],
        timeout=30,
    )


def run_whatweb(target: str) -> str:
    """
    whatweb -a 3 — fingerprint web technologies, CMS, frameworks, and headers.

    -a 3: active fingerprinting, non-destructive.
    """
    print(f"  [*] whatweb -a 3 {target}")

    return run_tool(
        ["whatweb", "-a", "3", target],
        timeout=60,
    )


def run_curl_headers(target: str) -> str:
    """
    curl -sI — fetch HTTP and HTTPS headers.

    Useful for:
    - Server header
    - Redirects
    - Cookies
    - Security headers
    - X-Powered-By
    """
    print(f"  [*] curl -sI http://{target}")

    http_output = run_tool(
        [
            "curl",
            "-sI",
            "--max-time",
            "10",
            "--location",
            f"http://{target}",
        ],
        timeout=20,
    )

    https_output = run_tool(
        [
            "curl",
            "-sI",
            "--max-time",
            "10",
            "--location",
            "-k",
            f"https://{target}",
        ],
        timeout=20,
    )

    return f"[HTTP Headers]\n{http_output}\n\n[HTTPS Headers]\n{https_output}"


def run_dig(target: str) -> str:
    """
    dig — DNS records: A, MX, NS, TXT.

    Useful for:
    - DNS mapping
    - Mail infrastructure
    - SPF/DKIM/DMARC hints
    - Name server visibility
    """
    print(f"  [*] dig {target} DNS records")

    a_record = run_tool(["dig", "+short", "A", target], timeout=15)
    mx_record = run_tool(["dig", "+short", "MX", target], timeout=15)
    ns_record = run_tool(["dig", "+short", "NS", target], timeout=15)
    txt_record = run_tool(["dig", "+short", "TXT", target], timeout=15)

    return (
        f"[A Records]\n{a_record}\n\n"
        f"[MX Records]\n{mx_record}\n\n"
        f"[NS Records]\n{ns_record}\n\n"
        f"[TXT Records]\n{txt_record}"
    )


def run_nikto(target: str) -> str:
    """
    nikto -h — web server security scanner.

    WARNING:
    Nikto can be noisy. Run only with explicit authorization.
    """
    print(f"  [*] nikto -h {target}  (this may take a while...)")

    return run_tool(
        ["nikto", "-h", target, "-nointeractive"],
        timeout=300,
    )


# ─────────────────────────────────────────────
# MAIN RECON PIPELINE
# ─────────────────────────────────────────────

TOOLS_MENU = {
    "1": ("nmap", run_nmap),
    "2": ("whois", run_whois),
    "3": ("whatweb", run_whatweb),
    "4": ("curl headers", run_curl_headers),
    "5": ("dig DNS", run_dig),
    "6": ("nikto", run_nikto),
}


def run_default_recon(target: str) -> dict:
    """
    Run the standard recon pipeline.

    Default:
    - nmap
    - whois
    - whatweb
    - curl headers
    - dig DNS

    Nikto is excluded by default because it can be slow/noisy.
    """
    print(f"\n[*] {APP_NAME} starting recon on: {target}")
    print("─" * 50)

    results = {
        "nmap": run_nmap(target),
        "whois": run_whois(target),
        "whatweb": run_whatweb(target),
        "curl_headers": run_curl_headers(target),
        "dig": run_dig(target),
    }

    print("─" * 50)
    print("[+] Recon complete.\n")

    return results


def run_single_tool(tool_key: str, target: str) -> str:
    """
    Run one tool by its menu key.
    Used by direct calls or future menu integrations.
    """
    if tool_key in TOOLS_MENU:
        name, func = TOOLS_MENU[tool_key]
        print(f"\n[*] Running {name}...")
        return func(target)

    return f"[!] Unknown tool key: {tool_key}"


def format_recon_for_llm(results: dict) -> str:
    """
    Flatten the recon results dict into one clean string
    to inject into the AI analysis prompt.
    """
    output = ""

    for tool, data in results.items():
        output += f"\n{'=' * 50}\n"
        output += f"[ {tool.upper()} OUTPUT ]\n"
        output += f"{'=' * 50}\n"
        output += str(data).strip() + "\n"

    return output


def run_tool_by_command(command_str: str) -> str:
    """
    Run a tool command requested by the AI through [TOOL: ...].

    Security notes:
    - Uses shlex.split()
    - Uses shell=False
    - Allows only tools in ALLOWED_TOOLS
    - Blocks shell control tokens
    """
    try:
        parts = shlex.split(command_str.strip())
    except ValueError as e:
        return f"[!] Invalid command syntax: {e}"

    if not parts:
        return "[!] Empty command."

    safe, reason = is_command_safe(parts)
    if not safe:
        return f"[!] Command rejected by {APP_NAME}: {reason}"

    return run_tool(parts)


# ─────────────────────────────────────────────
# INTERACTIVE TOOL SELECTOR
# ─────────────────────────────────────────────

def interactive_tool_run(target: str) -> str:
    """
    Let the user manually pick which tools to run.
    Returns combined output string for AI analysis.
    """
    print("\n[ SELECT TOOLS TO RUN ]")

    for key, (name, _) in TOOLS_MENU.items():
        print(f"  [{key}] {name}")

    print("  [a] Run all except nikto")
    print("  [n] Run all + nikto")
    print("  [q] Cancel")

    choice = input("\nChoice(s) e.g. 1 2 4 or a: ").strip().lower()

    if not choice:
        return ""

    if choice == "q":
        return ""

    if choice == "a":
        results = run_default_recon(target)
        return format_recon_for_llm(results)

    if choice == "n":
        results = run_default_recon(target)
        results["nikto"] = run_nikto(target)
        return format_recon_for_llm(results)

    combined = {}

    for key in choice.split():
        if key in TOOLS_MENU:
            name, func = TOOLS_MENU[key]
            print(f"\n[*] Running {name}...")
            combined[name] = func(target)
        else:
            print(f"[!] Unknown option: {key}")

    return format_recon_for_llm(combined)


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print(f"[ {APP_NAME} tools.py test ]")
    print(f"[ {APP_BRAND} ]\n")

    target = input("Enter test target IP or domain: ").strip()

    if not target:
        print("[!] No target entered.")
        exit(1)

    results = run_default_recon(target)
    print(format_recon_for_llm(results))

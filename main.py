#!/usr/bin/env python3
import os
import sys
import asyncio
import subprocess
import re
from openai import AsyncOpenAI
from cai.sdk.agents import Runner

# ─────────────────────────────────────────────
# QUIET LITELLM / CAI NOISE
# ─────────────────────────────────────────────
class _LiteLLMErrorFilter:
    def write(self, msg):
        if "Tracing client error" in msg:
            return
        if "Incorrect API key provided" in msg:
            return
        sys.__stderr__.write(msg)

    def flush(self):
        sys.__stderr__.flush()

sys.stderr = _LiteLLMErrorFilter()

# ─────────────────────────────────────────────
# ENVIRONMENT
# ─────────────────────────────────────────────
os.environ["OPENAI_API_KEY"] = "local"
os.environ["OPENAI_BASE_URL"] = "http://169.254.83.107:1234/v1"
os.environ["CAI_MODEL"] = "openai/mistral-7b-instruct-v0.3"
os.environ["CAI_STREAM"] = "false"
os.environ["CAI_TELEMETRY"] = "false"
os.environ["CAI_VERBOSE"] = "false"

# ─────────────────────────────────────────────
# BOOTSTRAP
# ─────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)
sys.path.insert(0, BASE_DIR)

# ─────────────────────────────────────────────
# IMPORTS
# ─────────────────────────────────────────────
from agents.decider import build_decider
from agents.planner import build_planner
from tools.web_search import web_search, fetch_url
from cai.sdk.agents import Agent
from cai.sdk.agents.models.openai_chatcompletions import OpenAIChatCompletionsModel

# ─────────────────────────────────────────────
# CLIENT
# ─────────────────────────────────────────────
openai_client = AsyncOpenAI(
    api_key="local",
    base_url=os.environ["OPENAI_BASE_URL"],
)

# ─────────────────────────────────────────────
# CHAT AGENT (NO SYSTEM ACCESS)
# ─────────────────────────────────────────────
CHAT_PROMPT = """
You are Infurnex, a helpful Linux AI assistant with internet access.

Capabilities:
- Answer questions about Linux, security, and hacking
- Search the internet for CTF writeups, exploits, and documentation
- Fetch and read content from URLs

Tools available:
- web_search(query, num_results): Search DuckDuckGo for information
- fetch_url(url, max_length): Fetch and read content from a URL

When to use web search:
- Finding CTF writeups or exploit techniques
- Looking up CVE details
- Searching for tool documentation
- Researching vulnerabilities

Rules:
- Do NOT run system commands (use the system agent for that)
- Do NOT guess - search for accurate information when needed
- Provide sources when using web search results
"""

chat = Agent(
    name="Chat",
    instructions=CHAT_PROMPT,
    model=OpenAIChatCompletionsModel(
        model=os.environ["CAI_MODEL"],
        openai_client=openai_client,
    ),
    tools=[web_search, fetch_url],
)

# ─────────────────────────────────────────────
# SYSTEM AGENTS
# ─────────────────────────────────────────────
decider = build_decider(openai_client)
planner = build_planner(openai_client)
runner = Runner()

# ─────────────────────────────────────────────
# REAL SHELL STATE
# ─────────────────────────────────────────────
CURRENT_CWD = os.getcwd()

# ─────────────────────────────────────────────
# SUPPRESS CAI VERBOSE OUTPUT
# ─────────────────────────────────────────────
import io
import contextlib

@contextlib.contextmanager
def suppress_stdout():
    """Temporarily suppress stdout to hide CAI debug boxes"""
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        yield
    finally:
        sys.stdout = old_stdout


# ─────────────────────────────────────────────
# COMMAND SANITIZER (COMMAND ONLY)
# ─────────────────────────────────────────────
CMD_RE = re.compile(r"^[a-zA-Z0-9_./~\-][^\n]*$")

def sanitize_command(text: str) -> str:
    if not text:
        return ""

    text = text.strip()

    if text.startswith("```"):
        lines = text.splitlines()[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
    else:
        lines = text.splitlines()

    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.upper() == "NOTHING":
            return ""
        if CMD_RE.match(line):
            return line

    return ""

# ─────────────────────────────────────────────
# EXECUTION ENGINE (TTY-SAFE)
# ─────────────────────────────────────────────
def run_command(cmd: str):
    global CURRENT_CWD

    if not cmd:
        return 0, "(no command executed)"

    # Handle cd internally
    if cmd.startswith("cd "):
        target = os.path.expanduser(cmd[3:].strip())
        if not os.path.isabs(target):
            target = os.path.join(CURRENT_CWD, target)

        if os.path.isdir(target):
            CURRENT_CWD = os.path.abspath(target)
            return 0, f"(cwd changed to {CURRENT_CWD})"
        return 1, f"cd: no such directory: {cmd[3:].strip()}"

    # sudo confirmation
    if cmd.lstrip().startswith("sudo"):
        confirm = input("⚠️  sudo command detected. Execute? (y/N): ").strip().lower()
        if confirm != "y":
            return 1, "(sudo cancelled)"

    # 🔥 DO NOT capture stdout/stderr → allow sudo password prompt
    proc = subprocess.run(
        cmd,
        shell=True,
        executable="/bin/bash",
        cwd=CURRENT_CWD,
    )

    return proc.returncode, "(command finished)"

# ─────────────────────────────────────────────
# MAIN LOOP
# ─────────────────────────────────────────────
async def main():
    print("Infurnex successfully booted...! >>\n")

    while True:
        try:
            user_input = input("@ >> ").strip()
            if user_input.lower() in ("exit", "quit"):
                break

            with suppress_stdout():
                decision = await runner.run(decider, user_input)
            verdict = decision.final_output.strip().split()[0].upper()

            if verdict == "NO":
                with suppress_stdout():
                    reply = await runner.run(chat, user_input)
                print(f"\ninfurnex > {reply.final_output}\n")
                continue

            # SYSTEM PATH
            with suppress_stdout():
                plan = await runner.run(planner, user_input)
            command = sanitize_command(plan.final_output)

            rc, output = run_command(command)
            print(f"infurnex> {output}\n")

            # SINGLE RETHINK ON FAILURE
            if rc != 0 and command:
                rethink_prompt = f"""
The command failed.

Command:
{command}

Error:
{output}

Generate ONE alternative shell command to achieve the same goal.
Output ONLY the command.
"""
                with suppress_stdout():
                    retry = await runner.run(planner, rethink_prompt)
                retry_cmd = sanitize_command(retry.final_output)

                if retry_cmd and retry_cmd != command:
                    rc, output = run_command(retry_cmd)
                    print(f"AI> {output}\n")

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[ERROR] {e}")

    print("Bye 👋")

# ─────────────────────────────────────────────
# CLEAN ASYNCIO SHUTDOWN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nBye 👋")


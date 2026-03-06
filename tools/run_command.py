import subprocess
import shlex
import os
import re
from cai.sdk.agents import function_tool
from policy.whitelist import ALLOWED_COMMANDS, DANGEROUS_TOKENS

@function_tool
async def run_command(command: str, timeout: int = 30) -> str:
    """
    Execute a shell command and return its output.
    Commands must use only whitelisted binaries.
    Piped commands like `ps aux | grep python` are supported.
    """
    command = command.strip()

    if not command:
        return "Error: empty command"

    # Block dangerous tokens/flags anywhere in the command
    for token in DANGEROUS_TOKENS:
        if token in command:
            return f"Blocked: dangerous token '{token}' detected in command"

    # Validate the first binary of every pipe segment
    # e.g. "ps aux | grep foo" → check "ps" and "grep"
    segments = re.split(r'\|', command)
    for segment in segments:
        segment = segment.strip()
        if not segment:
            continue
        first_token = shlex.split(segment)[0] if segment else ""
        # Strip any path prefix (e.g. /usr/bin/grep → grep)
        binary = os.path.basename(first_token)
        if binary not in ALLOWED_COMMANDS:
            return f"Blocked: command '{binary}' is not in the allowed list"

    proc = subprocess.run(
        command,
        shell=True,
        executable="/bin/bash",
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=os.getcwd()
    )

    output = (proc.stdout + proc.stderr).strip()
    return output if output else "(no output)"

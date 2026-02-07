import subprocess
import shlex
import os
from cai.sdk.agents import function_tool
from policy.whitelist import ALLOWED_COMMANDS, DANGEROUS_TOKENS

@function_tool
async def run_command(command: str, timeout: int = 20) -> str:
    args = shlex.split(command)

    if not args:
        return "Error: empty command"

    if args[0] not in ALLOWED_COMMANDS:
        return f"Blocked: command '{args[0]}' not allowed"

    for token in args:
        if token in DANGEROUS_TOKENS:
            return f"Blocked: dangerous token '{token}' detected"

    proc = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=os.getcwd()
    )

    output = (proc.stdout + proc.stderr).strip()
    return output if output else "(no output)"

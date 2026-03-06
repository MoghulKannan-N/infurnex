#!/usr/bin/env python3
"""
Infurnex Web Server — FastAPI backend
Serves the UI and exposes the agent pipeline via /chat (Server-Sent Events)
"""
import os
import sys
import re
import asyncio

from dotenv import load_dotenv
load_dotenv()

# ── path setup ──────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)
sys.path.insert(0, BASE_DIR)

# ── env guards ───────────────────────────────────────────────────────────────
if not os.getenv("OPENAI_API_KEY"):
    print("❌  OPENAI_API_KEY not set. Create a .env file.")
    sys.exit(1)

os.environ.setdefault("CAI_MODEL", "gpt-4o-mini")
os.environ.setdefault("CAI_STREAM", "false")
os.environ.setdefault("CAI_TELEMETRY", "false")
os.environ.setdefault("CAI_VERBOSE", "false")

# ── imports ──────────────────────────────────────────────────────────────────
from openai import AsyncOpenAI
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from cai.sdk.agents import Runner

from agents.planner import build_planner
from agents.researcher import build_researcher
from agents.strategist import build_strategist

# ── client + agents ──────────────────────────────────────────────────────────
openai_client = AsyncOpenAI()
planner    = build_planner(openai_client)
researcher = build_researcher(openai_client)
strategist = build_strategist(openai_client)
runner     = Runner()

CURRENT_CWD = BASE_DIR

# ── SSE sentinel: all newlines in SSE data must be encoded ────────────────────
NL = "⏎"  # single source of truth for newline sentinel

# ── prompts ──────────────────────────────────────────────────────────────────
DECIDER_PROMPT = """
You are the Master Decider. Classify the user's intent into ONE of these categories:
- KNOWLEDGE: General questions, greetings, help with concepts, explanations, or general chat.
- SEARCH: Requests that require searching the web for real-time info (CVEs, tools, docs, current events).
- COMMANDS: Explicit, single-step requests to run a specific command (e.g. "list files", "whoami", "show ip").
- AUTONOMOUS: Scanning, reconnaissance, multi-step investigation goals, or pentest tasks.
  Keywords: "scan", "nmap", "enumerate", "gobuster", "dirb", "find flag", "picoctf", "exploit", "recon", "target".

Rules:
- Output ONLY the category name (e.g., AUTONOMOUS).
- HIGH PRIORITY: If the user mentions a target (IP, URL, domain) and an action like "scan" or "nmap", ALWAYS choose AUTONOMOUS.
- Default to KNOWLEDGE if unsure.
"""

CHAT_PROMPT = """
You are Infurnex, an expert AI assistant specialising in Linux, cybersecurity, and hacking.
Help with Linux administration, security concepts, CTF challenges, penetration testing,
vulnerabilities and exploits.
Rules:
- Be clear and concise.
- Use markdown formatting (code blocks, lists) where useful.
- If the user asks to perform an action you cannot do in this mode (like scanning), tell them you can do it if they start an 'Autonomous' investigation or provide a direct command.
"""

# ── helper: decider ──────────────────────────────────────────────────────────
AUTONOMOUS_KEYWORDS = ["nmap", "scan", "enumerate", "gobuster", "dirb", "picoctf", "exploit", "recon", "nikto", "dirbuster", "sqlmap"]

async def decide(text: str) -> str:
    # Fast-path regex for high-priority keywords
    t = text.lower()
    if any(k in t for k in AUTONOMOUS_KEYWORDS):
        print(f"[DECIDE] Regex match → AUTONOMOUS")
        return "AUTONOMOUS"

    try:
        resp = await openai_client.chat.completions.create(
            model=os.environ["CAI_MODEL"],
            messages=[
                {"role": "system", "content": DECIDER_PROMPT},
                {"role": "user",   "content": text},
            ],
            max_tokens=10,
            temperature=0,
        )
        content = resp.choices[0].message.content.strip().upper()
        match = re.search(r"(KNOWLEDGE|COMMANDS|SEARCH|AUTONOMOUS)", content)
        word = match.group(1) if match else "KNOWLEDGE"
        print(f"[DECIDE] LLM → {word} (for: '{text[:30]}…')")
        return word
    except Exception as e:
        print(f"[DECIDE] Error: {e}")
        return "KNOWLEDGE"

# ── helper: chat (streaming) ─────────────────────────────────────────────────
async def chat_stream(text: str):
    """Yields OpenAI streaming chunks for the KNOWLEDGE path."""
    stream = await openai_client.chat.completions.create(
        model=os.environ["CAI_MODEL"],
        messages=[
            {"role": "system", "content": CHAT_PROMPT},
            {"role": "user",   "content": text},
        ],
        stream=True,
        temperature=0.7,
    )
    async for chunk in stream:
        delta = chunk.choices[0].delta.content
        if delta:
            yield delta

# ── command sanitizer ─────────────────────────────────────────────────────────
CMD_RE = re.compile(r"^[a-zA-Z0-9_./~\-][^\n]*$")

def sanitize_command(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
    else:
        lines = text.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.upper() == "NOTHING":
            continue
        if "<" in line and ">" in line:
            continue
        if CMD_RE.match(line):
            return line
    return ""

# ── shell executor (async) ───────────────────────────────────────────────────
async def run_shell(cmd: str) -> tuple:
    global CURRENT_CWD
    if cmd.startswith("cd "):
        target = os.path.expanduser(cmd[3:].strip())
        if not os.path.isabs(target):
            target = os.path.join(CURRENT_CWD, target)
        if os.path.isdir(target):
            CURRENT_CWD = os.path.abspath(target)
            return 0, f"(cwd changed to {CURRENT_CWD})"
        return 1, f"cd: no such directory: {cmd[3:].strip()}"

    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            executable="/bin/bash",
            cwd=CURRENT_CWD,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30.0)
        out = (stdout.decode() + stderr.decode()).strip()
        return proc.returncode or 0, out or "(no output)"
    except asyncio.TimeoutError:
        try: proc.kill()
        except: pass
        return 124, f"Command '{cmd}' timed out after 30 seconds"
    except Exception as e:
        return 1, f"Shell error: {e}"

# ── thought parser ───────────────────────────────────────────────────────────
def extract_phase(label: str, text: str) -> str:
    """Pull the text for a reasoning phase (OBSERVE/HYPOTHESIZE/ACT) from raw thought."""
    tag = label.upper() + ":"
    upper = text.upper()
    if tag not in upper:
        return ""
    idx = upper.find(tag)
    segment = text[idx + len(tag):].strip()
    for m in ["OBSERVE:", "HYPOTHESIZE:", "ACT:"]:
        if m == tag:
            continue
        ni = segment.upper().find(m)
        if ni != -1:
            segment = segment[:ni].strip()
    return segment.strip()

def parse_command(raw_out: str) -> str:
    """Extract the command from the LLM output, handling [COMMAND]: or COMMAND: formats."""
    if "[COMMAND]" in raw_out:
        raw_cmd = raw_out.split("[COMMAND]")[-1].strip().split("\n")[0]
        return raw_cmd.lstrip(":").strip().replace("`", "").strip()
    if "COMMAND:" in raw_out:
        raw_cmd = raw_out.split("COMMAND:")[-1].strip().split("\n")[0]
        return raw_cmd.strip().replace("`", "").strip()
    return ""

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(title="Infurnex")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend
DIST_PATH = os.path.join(BASE_DIR, "frontend/dist")
if os.path.exists(DIST_PATH):
    app.mount("/assets", StaticFiles(directory=os.path.join(DIST_PATH, "assets")), name="assets")

    @app.get("/")
    async def root():
        return FileResponse(os.path.join(DIST_PATH, "index.html"))

    @app.get("/{full_path:path}")
    async def fallback(full_path: str):
        local_file = os.path.join(DIST_PATH, full_path)
        if os.path.exists(local_file) and os.path.isfile(local_file):
            return FileResponse(local_file)
        return FileResponse(os.path.join(DIST_PATH, "index.html"))
else:
    app.mount("/static", StaticFiles(directory="static"), name="static")
    @app.get("/")
    async def root():
        return FileResponse("static/index.html")

# ── chat request model ────────────────────────────────────────────────────────
class ChatRequest(BaseModel):
    message: str

# ── main chat endpoint (SSE streaming) ───────────────────────────────────────
@app.post("/chat")
async def chat_endpoint(req: ChatRequest, request: Request):
    user_input = req.message.strip()

    async def generate():
        # Early disconnect check
        if await request.is_disconnected():
            return

        verdict = await decide(user_input)
        print(f"[CHAT] verdict={verdict} input='{user_input[:40]}…'")

        # ── AUTONOMOUS MODE ──────────────────────────────────────────────
        if verdict == "AUTONOMOUS":
            yield f"data: 🤖 **Initializing Autonomous Investigation Loop...**\n\n"
            await asyncio.sleep(0)

            with open(os.path.join(BASE_DIR, "prompts/strategist.txt")) as f:
                strategist_prompt = f.read()

            context = (
                f"TARGET / GOAL: {user_input}\n"
                f"Begin reconnaissance targeting EXACTLY what the user described above.\n"
                f"Do NOT use placeholder targets like example.com.\n"
            )
            max_turns = 30

            for turn in range(max_turns):
                # Check disconnect before each turn
                if await request.is_disconnected():
                    print(f"[STOP] User disconnected at turn {turn+1}")
                    break

                yield f"data: *Turn {turn+1}/{max_turns}: Strategizing...*\n\n"
                await asyncio.sleep(0)

                try:
                    resp = await asyncio.wait_for(
                        openai_client.chat.completions.create(
                            model=os.environ["CAI_MODEL"],
                            messages=[
                                {"role": "system", "content": strategist_prompt},
                                {"role": "user",   "content": context},
                            ],
                            temperature=0.3,
                            max_tokens=500,
                        ),
                        timeout=45.0,
                    )
                    raw_out = resp.choices[0].message.content or ""
                    print(f"[TURN {turn+1}] Raw LLM output ({len(raw_out)} chars)")

                    # ── Final report ──
                    if "[FINAL REPORT]" in raw_out:
                        report = raw_out.split("[FINAL REPORT]")[-1].strip().replace("\n", NL)
                        yield f"data: report:{report}\n\n"
                        break

                    # ── Parse structured reasoning ──
                    thought_parts = []

                    if "[THOUGHT]" in raw_out:
                        # Get everything between [THOUGHT] and [COMMAND]
                        raw_thought = raw_out.split("[THOUGHT]")[-1]
                        if "[COMMAND]" in raw_thought:
                            raw_thought = raw_thought.split("[COMMAND]")[0]
                        raw_thought = raw_thought.lstrip(":").strip()

                        observe     = extract_phase("OBSERVE",     raw_thought)
                        hypothesize = extract_phase("HYPOTHESIZE", raw_thought)
                        act         = extract_phase("ACT",         raw_thought)

                        if not any([observe, hypothesize, act]):
                            fb = raw_thought.replace("\n", NL)
                            thought_parts.append(fb)
                            yield f"data: thought:{fb}\n\n"
                            await asyncio.sleep(0)
                        else:
                            for emoji, label, content in [
                                ("🔍", "OBSERVE",     observe),
                                ("💡", "HYPOTHESIZE", hypothesize),
                                ("⚡", "ACT",         act),
                            ]:
                                if content:
                                    entry = f"{emoji} {label} — {content}".replace("\n", NL)
                                    thought_parts.append(entry)
                                    yield f"data: thought:{entry}\n\n"
                                    await asyncio.sleep(0)

                    # ── Extract command ──
                    cmd = parse_command(raw_out)
                    thought = "\n".join(thought_parts)

                    if not cmd:
                        if not thought and raw_out:
                            yield f"data: {raw_out.replace(chr(10), NL)}\n\n"
                        yield f"data: ✅ Investigation complete.\n\n"
                        break

                    yield f"data: cmd:{cmd}\n\n"
                    await asyncio.sleep(0)

                    # ── Execute command ──
                    try:
                        # Macro-Micro Integration Override
                        # Intercept the 'run_infurnex' tool request from the LLM before it hits the bash executor
                        if cmd.startswith("run_infurnex "):
                            target_url = cmd.split("run_infurnex ")[1].strip()
                            from tools.run_infurnex import run_infurnex # Lazy load tool
                            
                            # Execute deterministic orchestrator and extract output
                            out = run_infurnex(target_url)  
                            
                            # Check logical parsing for flag discovery (early exit signal)
                            if "CRITICAL SUCCESS" in out:
                                rc = 0 # successful evaluation
                            else:
                                rc = 0 # default baseline return
                        else:
                            # Standard pathway for all other linux commands (nmap, curl, etc)
                            rc, out = await run_shell(cmd)
                    except Exception as e:
                        rc, out = 1, f"Shell error: {e}"

                    if len(out) > 3000:
                        out = out[:1500] + "\n… (truncated) …\n" + out[-1500:]

                    yield f"data: out:{out.replace(chr(10), NL)}\n\n"
                    await asyncio.sleep(0)

                    context += (
                        f"\n--- Turn {turn+1} ---\n"
                        f"REASONING:\n{thought}\n"
                        f"COMMAND: {cmd}\n"
                        f"EXIT CODE: {rc}\n"
                        f"OUTPUT:\n{out}\n"
                    )

                except asyncio.TimeoutError:
                    yield f"data: ⚠️ Strategist timed out on turn {turn+1} — stopping.\n\n"
                    break
                except Exception as e:
                    yield f"data: ⚠️ Error on turn {turn+1}: {e}\n\n"
                    break

            yield "data: [DONE]\n\n"
            return

        # ── SEARCH MODE ──────────────────────────────────────────────────
        if verdict == "SEARCH":
            yield f"data: 🔍 *Searching the web...*\n\n"
            try:
                result = await runner.run(researcher, user_input)
                yield f"data: {result.final_output}\n\n"
            except Exception as e:
                yield f"data: (search error: {e})\n\n"
            yield "data: [DONE]\n\n"
            return

        # ── COMMANDS MODE ────────────────────────────────────────────────
        if verdict == "COMMANDS":
            try:
                plan = await runner.run(planner, user_input)
                cmd  = sanitize_command(plan.final_output)
            except Exception as e:
                yield f"data: (planner error: {e})\n\n"
                yield "data: [DONE]\n\n"
                return

            if not cmd:
                async for chunk in chat_stream(user_input):
                    yield f"data: {chunk}\n\n"
                yield "data: [DONE]\n\n"
                return

            yield f"data: thought:Supervising execution: {cmd}{NL}\n\n"
            yield f"data: cmd:{cmd}\n\n"
            try:
                rc, output = await run_shell(cmd)
                yield f"data: out:{output.replace(chr(10), NL)}\n\n"
                if rc != 0:
                    yield f"data: ⚠️ Command exited with code {rc}{NL}\n\n"
            except Exception as e:
                yield f"data: (exec error: {e}){NL}\n\n"
            yield "data: [DONE]\n\n"
            return

        # ── KNOWLEDGE MODE ───────────────────────────────────────────────
        async for chunk in chat_stream(user_input):
            safe = chunk.replace("\n", NL)
            yield f"data: {safe}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)

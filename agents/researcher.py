import os
from cai.sdk.agents import Agent
from cai.sdk.agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from tools.web_search import web_search, fetch_url

def build_researcher(openai_client):
    RESEARCHER_PROMPT = """
    You are a security research assistant with internet access.
    
    1. ANALYZE the user's request.
    2. If the request is for specific info (like "date", "weather", "definition"), use the appropriate tool and ANSWER DIRECTLY.
    3. If the request is broad or security-related (CTFs, CVEs, tools), use `web_search` to find recent info (2024-2026).
    4. SYNTHESIZE the findings into a clear, natural language answer.
    5. BE CONCISE to save token costs. Keep responses brief and actionable.
    
    Do NOT perform unrelated searches (e.g., don't search for CTFs if the user asks for the date).
    Always cite sources with URLs when using web search.
    """
    
    return Agent(
        name="Researcher",
        instructions=RESEARCHER_PROMPT,
        model=OpenAIChatCompletionsModel(
            model=os.environ["CAI_MODEL"],
            openai_client=openai_client,
        ),
        tools=[web_search, fetch_url, get_current_date],
    )

from cai.sdk.agents import function_tool

@function_tool
async def get_current_date() -> str:
    """Returns the current date and time."""
    from datetime import datetime
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

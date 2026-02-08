import os
from cai.sdk.agents import Agent
from cai.sdk.agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from tools.web_search import web_search, fetch_url

def build_researcher(openai_client):
    RESEARCHER_PROMPT = """
    You are a security research assistant with internet access.
    
    Use web search to find:
    - CTF writeups and solutions
    - CVE details and exploit information
    - Recent vulnerabilities and security news
    - Tool documentation and usage examples
    
    Always cite your sources with URLs.
    """
    
    return Agent(
        name="Researcher",
        instructions=RESEARCHER_PROMPT,
        model=OpenAIChatCompletionsModel(
            model=os.environ["CAI_MODEL"],
            openai_client=openai_client,
        ),
        tools=[web_search, fetch_url],
    )

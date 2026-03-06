import os
from cai.sdk.agents import Agent
from cai.sdk.agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from tools.web_search import web_search, fetch_url
from tools.run_command import run_command
from tools.run_infurnex import run_infurnex

with open("prompts/strategist.txt") as f:
    STRATEGIST_PROMPT = f.read()

def build_strategist(openai_client):
    return Agent(
        name="Strategist",
        instructions=STRATEGIST_PROMPT,
        model=OpenAIChatCompletionsModel(
            model=os.environ["CAI_MODEL"],
            openai_client=openai_client,
        ),
        tools=[run_command, web_search, fetch_url, run_infurnex],
    )

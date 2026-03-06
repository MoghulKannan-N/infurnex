import os
from cai.sdk.agents import Agent
from cai.sdk.agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from tools.web_search import web_search, fetch_url
from tools.run_command import run_command

with open("prompts/planner.txt") as f:
    PLANNER_PROMPT = f.read()

def build_planner(openai_client):
    return Agent(
        name="Planner",
        instructions=PLANNER_PROMPT,
        model=OpenAIChatCompletionsModel(
            model=os.environ["CAI_MODEL"],
            openai_client=openai_client,
        ),
        tools=[run_command, web_search, fetch_url],
    )

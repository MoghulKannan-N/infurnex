import os
from cai.sdk.agents import Agent
from cai.sdk.agents.models.openai_chatcompletions import OpenAIChatCompletionsModel

with open("prompts/planner.txt") as f:
    PROMPT = f.read()

def build_planner(openai_client):
    return Agent(
        name="Planner",
        instructions=PROMPT,
        model=OpenAIChatCompletionsModel(
            model=os.environ["CAI_MODEL"],
            openai_client=openai_client,
        ),
        tools=[]
    )

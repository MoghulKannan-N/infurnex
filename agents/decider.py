import os
from cai.sdk.agents import Agent
from cai.sdk.agents.models.openai_chatcompletions import OpenAIChatCompletionsModel

with open("prompts/decider.txt") as f:
    PROMPT = f.read()

def build_decider(openai_client):
    return Agent(
        name="ToolDecider",
        instructions=PROMPT,
        model=OpenAIChatCompletionsModel(
            model=os.environ["CAI_MODEL"],
            openai_client=openai_client,
        ),
        tools=[]
    )
